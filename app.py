from fastapi import FastAPI, HTTPException, Header, Query, Request, Response, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional
from pathlib import Path
from datetime import datetime, timezone, timedelta
import sqlite3
import secrets
import os
import json
import urllib.request
import urllib.error
import hashlib
import hmac
import re

try:
    import psycopg
    from psycopg.rows import dict_row
except ImportError:
    psycopg = None
    dict_row = None

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.getenv("DB_PATH", str(BASE_DIR / "meetings.db")))
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
USE_POSTGRES = bool(DATABASE_URL)
REQUIRE_PERSISTENT_DB = os.getenv("REQUIRE_PERSISTENT_DB", "false").strip().lower() in {"1", "true", "yes", "on"}

if REQUIRE_PERSISTENT_DB and not USE_POSTGRES:
    raise RuntimeError(
        "Persistent database is required but DATABASE_URL is missing. "
        "Refusing to start with ephemeral SQLite to protect existing meeting data."
    )

WEBHOOK_SECRET = os.getenv("PLAUD_WEBHOOK_SECRET", "change-me")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_TRANSLATION_MODEL = os.getenv("OPENAI_TRANSLATION_MODEL", "gpt-5.6-luna")
FRONTEND_ORIGINS = [x.strip() for x in os.getenv("FRONTEND_ORIGINS", "http://localhost:8000").split(",") if x.strip()]
APP_ADMIN_EMAIL = os.getenv("APP_ADMIN_EMAIL", "").strip().lower()
APP_ADMIN_PASSWORD = os.getenv("APP_ADMIN_PASSWORD", "")
APP_ADMIN_NAME = os.getenv("APP_ADMIN_NAME", "관리자")
SESSION_DAYS = int(os.getenv("SESSION_DAYS", "7"))
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").strip().lower() in {"1", "true", "yes", "on"}
COOKIE_SAMESITE = os.getenv("COOKIE_SAMESITE", "lax").strip().lower()
if COOKIE_SAMESITE not in {"lax", "strict", "none"}:
    COOKIE_SAMESITE = "lax"
SESSION_COOKIE = "mm_session"

app = FastAPI(title="Meeting Minutes MVP")
app.add_middleware(
    CORSMiddleware,
    allow_origins=FRONTEND_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def disable_frontend_cache(request: Request, call_next):
    response = await call_next(request)
    path = request.url.path.lower()
    if path == "/" or path.endswith((".html", ".js", ".css")):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response

FOLDER_COLOR_PALETTE = {
    "#536878",  # slate
    "#64748B",  # blue gray
    "#667761",  # sage
    "#7A6F66",  # taupe
    "#806A78",  # mauve
    "#73765A",  # olive
    "#756D91",  # muted purple
    "#8A6B57",  # terracotta
    "#5F777A",  # muted teal
    "#867A59",  # muted ochre
}

LANGUAGES = {
    "ko": "Korean",
    "en": "English",
    "ja": "Japanese",
}


class PgCursorProxy:
    def __init__(self, cursor, lastrowid=None):
        self._cursor = cursor
        self.lastrowid = lastrowid

    @property
    def rowcount(self):
        return self._cursor.rowcount

    def fetchone(self):
        return self._cursor.fetchone()

    def fetchall(self):
        return self._cursor.fetchall()


class PgConnectionProxy:
    def __init__(self, conn):
        self._conn = conn

    def _convert_sql(self, sql: str) -> str:
        # The app uses SQLite-style qmark parameters. PostgreSQL/psycopg uses %s.
        return sql.replace("?", "%s")

    def execute(self, sql, params=()):
        converted = self._convert_sql(sql)
        stripped = converted.lstrip().upper()
        returning_id = False

        # These inserts are the only places where current app code reads .lastrowid.
        for table in ("MEETINGS", "USERS", "FOLDERS"):
            if stripped.startswith(f"INSERT INTO {table}") and "RETURNING " not in stripped:
                converted = converted.rstrip().rstrip(";") + " RETURNING id"
                returning_id = True
                break

        cur = self._conn.cursor()
        cur.execute(converted, tuple(params) if params is not None else ())
        lastrowid = None
        if returning_id:
            returned = cur.fetchone()
            if returned:
                lastrowid = returned["id"]
        return PgCursorProxy(cur, lastrowid=lastrowid)

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        self._conn.close()


def db():
    if USE_POSTGRES:
        if psycopg is None:
            raise RuntimeError("DATABASE_URL is set but psycopg is not installed")
        conn = psycopg.connect(DATABASE_URL, row_factory=dict_row)
        return PgConnectionProxy(conn)

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


DB_INTEGRITY_ERRORS = (sqlite3.IntegrityError,)
if psycopg is not None:
    DB_INTEGRITY_ERRORS = DB_INTEGRITY_ERRORS + (psycopg.IntegrityError,)


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def hash_password(password: str, salt: bytes | None = None) -> tuple[str, str]:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 310000)
    return salt.hex(), digest.hex()


def verify_password(password: str, salt_hex: str, expected_hex: str) -> bool:
    try:
        salt = bytes.fromhex(salt_hex)
    except ValueError:
        return False
    _, actual_hex = hash_password(password, salt)
    return hmac.compare_digest(actual_hex, expected_hex)


def hash_session_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def init_db():
    conn = db()

    if USE_POSTGRES:
        statements = [
            """
            CREATE TABLE IF NOT EXISTS users (
                id BIGSERIAL PRIMARY KEY,
                email TEXT NOT NULL UNIQUE,
                display_name TEXT,
                password_salt TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                is_active INTEGER NOT NULL DEFAULT 1,
                is_admin INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                user_id BIGINT NOT NULL,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS folders (
                id BIGSERIAL PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                parent_id BIGINT,
                color TEXT NOT NULL DEFAULT '#4F6B8A',
                created_at TEXT NOT NULL,
                FOREIGN KEY(parent_id) REFERENCES folders(id) ON DELETE SET NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS meetings (
                id BIGSERIAL PRIMARY KEY,
                title TEXT NOT NULL,
                recorded_at TEXT,
                transcript TEXT NOT NULL,
                summary TEXT,
                participants TEXT,
                source TEXT NOT NULL DEFAULT 'manual',
                created_at TEXT NOT NULL,
                updated_at TEXT,
                folder_id BIGINT,
                author TEXT,
                location TEXT,
                meeting_method TEXT,
                purpose TEXT,
                follow_up TEXT,
                source_external_id TEXT,
                source_synced_at TEXT,
                FOREIGN KEY(folder_id) REFERENCES folders(id) ON DELETE SET NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS drafts (
                user_id BIGINT PRIMARY KEY,
                title TEXT,
                recorded_at TEXT,
                author TEXT,
                folder_id BIGINT,
                location TEXT,
                meeting_method TEXT,
                participants TEXT,
                purpose TEXT,
                transcript TEXT,
                summary TEXT,
                follow_up TEXT,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY(folder_id) REFERENCES folders(id) ON DELETE SET NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS follow_up_items (
                id BIGSERIAL PRIMARY KEY,
                meeting_id BIGINT NOT NULL,
                task TEXT NOT NULL,
                owner TEXT,
                start_date TEXT,
                end_date TEXT,
                status TEXT NOT NULL DEFAULT 'open',
                completion_note TEXT,
                completed_date TEXT,
                memo TEXT,
                color TEXT NOT NULL DEFAULT '#64748B',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(meeting_id) REFERENCES meetings(id) ON DELETE CASCADE
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS shares (
                token TEXT PRIMARY KEY,
                meeting_id BIGINT NOT NULL,
                expires_at TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(meeting_id) REFERENCES meetings(id)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS translations (
                id BIGSERIAL PRIMARY KEY,
                meeting_id BIGINT NOT NULL,
                language TEXT NOT NULL,
                translated_title TEXT NOT NULL,
                translated_summary TEXT,
                translated_transcript TEXT NOT NULL,
                model TEXT,
                created_at TEXT NOT NULL,
                UNIQUE(meeting_id, language),
                FOREIGN KEY(meeting_id) REFERENCES meetings(id)
            )
            """,
            "ALTER TABLE meetings ADD COLUMN IF NOT EXISTS updated_at TEXT",
            "ALTER TABLE meetings ADD COLUMN IF NOT EXISTS folder_id BIGINT",
            "ALTER TABLE meetings ADD COLUMN IF NOT EXISTS author TEXT",
            "ALTER TABLE meetings ADD COLUMN IF NOT EXISTS location TEXT",
            "ALTER TABLE meetings ADD COLUMN IF NOT EXISTS meeting_method TEXT",
            "ALTER TABLE meetings ADD COLUMN IF NOT EXISTS purpose TEXT",
            "ALTER TABLE meetings ADD COLUMN IF NOT EXISTS follow_up TEXT",
            "ALTER TABLE meetings ADD COLUMN IF NOT EXISTS source_external_id TEXT",
            "ALTER TABLE meetings ADD COLUMN IF NOT EXISTS source_synced_at TEXT",
            "CREATE UNIQUE INDEX IF NOT EXISTS ux_meetings_source_external_id ON meetings(source, source_external_id) WHERE source_external_id IS NOT NULL",
            "ALTER TABLE drafts ADD COLUMN IF NOT EXISTS location TEXT",
            "ALTER TABLE drafts ADD COLUMN IF NOT EXISTS meeting_method TEXT",
            "ALTER TABLE drafts ADD COLUMN IF NOT EXISTS participants TEXT",
            "ALTER TABLE drafts ADD COLUMN IF NOT EXISTS purpose TEXT",
            "ALTER TABLE drafts ADD COLUMN IF NOT EXISTS follow_up TEXT",
            "ALTER TABLE drafts ADD COLUMN IF NOT EXISTS follow_up_items_json TEXT",
            "ALTER TABLE follow_up_items ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'open'",
            "ALTER TABLE follow_up_items ADD COLUMN IF NOT EXISTS completion_note TEXT",
            "ALTER TABLE follow_up_items ADD COLUMN IF NOT EXISTS completed_date TEXT",
            "ALTER TABLE follow_up_items ADD COLUMN IF NOT EXISTS memo TEXT",
            "ALTER TABLE follow_up_items ADD COLUMN IF NOT EXISTS color TEXT NOT NULL DEFAULT '#64748B'",
            "ALTER TABLE folders ADD COLUMN IF NOT EXISTS parent_id BIGINT",
            "ALTER TABLE folders ADD COLUMN IF NOT EXISTS color TEXT NOT NULL DEFAULT '#4F6B8A'",
        ]
        for statement in statements:
            conn.execute(statement)
        conn.commit()
    else:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                display_name TEXT,
                password_salt TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                is_active INTEGER NOT NULL DEFAULT 1,
                is_admin INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS folders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                parent_id INTEGER,
                color TEXT NOT NULL DEFAULT '#4F6B8A',
                created_at TEXT NOT NULL,
                FOREIGN KEY(parent_id) REFERENCES folders(id) ON DELETE SET NULL
            );

            CREATE TABLE IF NOT EXISTS meetings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                recorded_at TEXT,
                transcript TEXT NOT NULL,
                summary TEXT,
                participants TEXT,
                source TEXT NOT NULL DEFAULT 'manual',
                created_at TEXT NOT NULL,
                updated_at TEXT,
                folder_id INTEGER,
                author TEXT,
                location TEXT,
                meeting_method TEXT,
                purpose TEXT,
                follow_up TEXT,
                source_external_id TEXT,
                source_synced_at TEXT,
                FOREIGN KEY(folder_id) REFERENCES folders(id) ON DELETE SET NULL
            );

            CREATE TABLE IF NOT EXISTS drafts (
                user_id INTEGER PRIMARY KEY,
                title TEXT,
                recorded_at TEXT,
                author TEXT,
                folder_id INTEGER,
                location TEXT,
                meeting_method TEXT,
                participants TEXT,
                purpose TEXT,
                transcript TEXT,
                summary TEXT,
                follow_up TEXT,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY(folder_id) REFERENCES folders(id) ON DELETE SET NULL
            );

            CREATE TABLE IF NOT EXISTS follow_up_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                meeting_id INTEGER NOT NULL,
                task TEXT NOT NULL,
                owner TEXT,
                start_date TEXT,
                end_date TEXT,
                status TEXT NOT NULL DEFAULT 'open',
                completion_note TEXT,
                completed_date TEXT,
                memo TEXT,
                color TEXT NOT NULL DEFAULT '#64748B',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(meeting_id) REFERENCES meetings(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS shares (
                token TEXT PRIMARY KEY,
                meeting_id INTEGER NOT NULL,
                expires_at TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(meeting_id) REFERENCES meetings(id)
            );

            CREATE TABLE IF NOT EXISTS translations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                meeting_id INTEGER NOT NULL,
                language TEXT NOT NULL,
                translated_title TEXT NOT NULL,
                translated_summary TEXT,
                translated_transcript TEXT NOT NULL,
                model TEXT,
                created_at TEXT NOT NULL,
                UNIQUE(meeting_id, language),
                FOREIGN KEY(meeting_id) REFERENCES meetings(id)
            );
            """
        )
        columns = {r[1] for r in conn.execute("PRAGMA table_info(meetings)").fetchall()}
        if "updated_at" not in columns:
            conn.execute("ALTER TABLE meetings ADD COLUMN updated_at TEXT")
        if "folder_id" not in columns:
            conn.execute("ALTER TABLE meetings ADD COLUMN folder_id INTEGER")
        if "author" not in columns:
            conn.execute("ALTER TABLE meetings ADD COLUMN author TEXT")
        if "location" not in columns:
            conn.execute("ALTER TABLE meetings ADD COLUMN location TEXT")
        if "meeting_method" not in columns:
            conn.execute("ALTER TABLE meetings ADD COLUMN meeting_method TEXT")
        if "purpose" not in columns:
            conn.execute("ALTER TABLE meetings ADD COLUMN purpose TEXT")
        if "follow_up" not in columns:
            conn.execute("ALTER TABLE meetings ADD COLUMN follow_up TEXT")
        if "source_external_id" not in columns:
            conn.execute("ALTER TABLE meetings ADD COLUMN source_external_id TEXT")
        if "source_synced_at" not in columns:
            conn.execute("ALTER TABLE meetings ADD COLUMN source_synced_at TEXT")
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS ux_meetings_source_external_id "
            "ON meetings(source, source_external_id) WHERE source_external_id IS NOT NULL"
        )

        draft_columns = {r[1] for r in conn.execute("PRAGMA table_info(drafts)").fetchall()}
        if "location" not in draft_columns:
            conn.execute("ALTER TABLE drafts ADD COLUMN location TEXT")
        if "meeting_method" not in draft_columns:
            conn.execute("ALTER TABLE drafts ADD COLUMN meeting_method TEXT")
        if "participants" not in draft_columns:
            conn.execute("ALTER TABLE drafts ADD COLUMN participants TEXT")
        if "purpose" not in draft_columns:
            conn.execute("ALTER TABLE drafts ADD COLUMN purpose TEXT")
        if "follow_up" not in draft_columns:
            conn.execute("ALTER TABLE drafts ADD COLUMN follow_up TEXT")
        if "follow_up_items_json" not in draft_columns:
            conn.execute("ALTER TABLE drafts ADD COLUMN follow_up_items_json TEXT")

        fu_columns = {r[1] for r in conn.execute("PRAGMA table_info(follow_up_items)").fetchall()}
        if "status" not in fu_columns:
            conn.execute("ALTER TABLE follow_up_items ADD COLUMN status TEXT NOT NULL DEFAULT 'open'")
        if "completion_note" not in fu_columns:
            conn.execute("ALTER TABLE follow_up_items ADD COLUMN completion_note TEXT")
        if "completed_date" not in fu_columns:
            conn.execute("ALTER TABLE follow_up_items ADD COLUMN completed_date TEXT")
        if "memo" not in fu_columns:
            conn.execute("ALTER TABLE follow_up_items ADD COLUMN memo TEXT")
        if "color" not in fu_columns:
            conn.execute("ALTER TABLE follow_up_items ADD COLUMN color TEXT NOT NULL DEFAULT '#64748B'")

        folder_columns = {r[1] for r in conn.execute("PRAGMA table_info(folders)").fetchall()}
        if "parent_id" not in folder_columns:
            conn.execute("ALTER TABLE folders ADD COLUMN parent_id INTEGER")
        if "color" not in folder_columns:
            conn.execute("ALTER TABLE folders ADD COLUMN color TEXT NOT NULL DEFAULT '#4F6B8A'")
        conn.commit()

    user_count = conn.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"]
    if user_count == 0 and APP_ADMIN_EMAIL and APP_ADMIN_PASSWORD:
        salt_hex, password_hex = hash_password(APP_ADMIN_PASSWORD)
        conn.execute(
            """
            INSERT INTO users(email, display_name, password_salt, password_hash, is_active, is_admin, created_at)
            VALUES (?, ?, ?, ?, 1, 1, ?)
            """,
            (APP_ADMIN_EMAIL, APP_ADMIN_NAME, salt_hex, password_hex, now_iso()),
        )
        conn.commit()

    conn.close()


init_db()


class LoginIn(BaseModel):
    email: str
    password: str


class ChangePasswordIn(BaseModel):
    current_password: str
    new_password: str


class AdminUserCreateIn(BaseModel):
    email: str
    display_name: Optional[str] = None
    password: str


class AdminUserPatchIn(BaseModel):
    display_name: Optional[str] = None
    is_active: Optional[bool] = None
    new_password: Optional[str] = None


class FolderIn(BaseModel):
    name: str
    parent_id: Optional[int] = None
    color: str = "#536878"


class FolderRenameIn(BaseModel):
    name: str


class FolderMoveIn(BaseModel):
    parent_id: Optional[int] = None


class FolderColorIn(BaseModel):
    color: str



class MeetingFolderMoveIn(BaseModel):
    folder_id: Optional[int] = None


class FollowUpItemIn(BaseModel):
    task: str
    owner: Optional[str] = None
    start_date: Optional[str] = None
    end_date: Optional[str] = None
    status: str = "open"
    completion_note: Optional[str] = None
    completed_date: Optional[str] = None
    memo: Optional[str] = None
    color: str = "#64748B"


class DraftIn(BaseModel):
    title: Optional[str] = None
    recorded_at: Optional[str] = None
    author: Optional[str] = None
    folder_id: Optional[int] = None
    location: Optional[str] = None
    meeting_method: Optional[str] = None
    participants: Optional[list[str] | str] = None
    purpose: Optional[str] = None
    transcript: Optional[str] = None
    summary: Optional[str] = None
    follow_up: Optional[str] = None
    follow_up_items: Optional[list[FollowUpItemIn]] = None


class MeetingIn(BaseModel):
    title: str = Field(default="제목 없는 회의")
    recorded_at: Optional[str] = None
    transcript: str
    summary: Optional[str] = None
    participants: Optional[list[str] | str] = None
    source: str = "manual"
    folder_id: Optional[int] = None
    author: Optional[str] = None
    location: Optional[str] = None
    meeting_method: Optional[str] = None
    purpose: Optional[str] = None
    follow_up: Optional[str] = None
    follow_up_items: Optional[list[FollowUpItemIn]] = None


class MeetingUpdate(BaseModel):
    title: str
    recorded_at: Optional[str] = None
    transcript: str
    summary: Optional[str] = None
    participants: Optional[list[str] | str] = None
    folder_id: Optional[int] = None
    author: Optional[str] = None
    location: Optional[str] = None
    meeting_method: Optional[str] = None
    purpose: Optional[str] = None
    follow_up: Optional[str] = None
    follow_up_items: Optional[list[FollowUpItemIn]] = None


class PlaudWebhookIn(BaseModel):
    # Zapier maps the PLAUD trigger fields into these stable API keys.
    title: Optional[str] = None
    transcript: Optional[str] = None
    summary: Optional[str] = None
    create_time: Optional[str] = None
    external_id: Optional[str] = None
    recording_id: Optional[str] = None


class ShareIn(BaseModel):
    expires_hours: Optional[int] = Field(default=168, ge=1, le=24 * 365)


class TranslationIn(BaseModel):
    target_language: str = Field(pattern="^(en|ja)$")
    force_refresh: bool = False


def validate_follow_up_date(value: str | None, field_name: str):
    if not value:
        return None
    try:
        datetime.strptime(value, "%Y-%m-%d")
    except ValueError:
        raise HTTPException(status_code=400, detail=f"{field_name}은 YYYY-MM-DD 형식이어야 합니다.")
    return value


def normalize_follow_up_items(items):
    normalized = []
    for item in items or []:
        task = (item.task or "").strip()
        owner = (item.owner or "").strip() or None
        start_date = validate_follow_up_date(item.start_date, "F/U 시작일")
        end_date = validate_follow_up_date(item.end_date, "F/U 종료일")
        status = (item.status or "open").strip().lower()
        if status not in {"open", "completed"}:
            raise HTTPException(status_code=400, detail="F/U 상태는 open 또는 completed만 가능합니다.")
        completion_note = (item.completion_note or "").strip() or None
        completed_date = validate_follow_up_date(item.completed_date, "F/U 완료일")
        memo = (item.memo or "").strip() or None
        color = (item.color or "#64748B").strip().upper()
        if color not in FOLDER_COLOR_PALETTE:
            raise HTTPException(status_code=400, detail="허용된 10개 F/U 색상 중 하나를 선택해 주세요.")

        if not task and not owner and not start_date and not end_date and not completion_note and not memo:
            continue
        if not task:
            raise HTTPException(status_code=400, detail="F/U 업무내용을 입력해 주세요.")
        if start_date and end_date and end_date < start_date:
            raise HTTPException(status_code=400, detail="F/U 종료일은 시작일보다 빠를 수 없습니다.")

        if status == "completed" and not completed_date:
            completed_date = end_date or start_date
        if status == "open":
            completed_date = None
            completion_note = None

        normalized.append({
            "task": task,
            "owner": owner,
            "start_date": start_date,
            "end_date": end_date,
            "status": status,
            "completion_note": completion_note,
            "completed_date": completed_date,
            "memo": memo,
            "color": color,
        })
    return normalized


def follow_up_items_to_text(items):
    lines = []
    for item in items or []:
        period = ""
        if item.get("start_date") and item.get("end_date"):
            period = f"{item['start_date']} ~ {item['end_date']}"
        elif item.get("start_date"):
            period = item["start_date"]
        elif item.get("end_date"):
            period = f"~ {item['end_date']}"
        state = "완료" if item.get("status") == "completed" else "진행"
        meta = " / ".join(x for x in [item.get("owner"), period, state] if x)
        line = f"- {item['task']}" + (f" ({meta})" if meta else "")
        if item.get("completion_note"):
            line += f"\n  완료사항: {item['completion_note']}"
        lines.append(line)
    return "\n".join(lines) or None


def replace_follow_up_items(conn, meeting_id: int, items):
    normalized = normalize_follow_up_items(items)
    conn.execute("DELETE FROM follow_up_items WHERE meeting_id=?", (meeting_id,))
    now = now_iso()
    for item in normalized:
        conn.execute(
            """
            INSERT INTO follow_up_items(
                meeting_id, task, owner, start_date, end_date,
                status, completion_note, completed_date, memo, color,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                meeting_id,
                item["task"],
                item["owner"],
                item["start_date"],
                item["end_date"],
                item["status"],
                item["completion_note"],
                item["completed_date"],
                item["memo"],
                item["color"],
                now,
                now,
            ),
        )
    return normalized


def get_follow_up_items(meeting_id: int):
    conn = db()
    rows = conn.execute(
        """
        SELECT id, meeting_id, task, owner, start_date, end_date,
               status, completion_note, completed_date, memo, color, created_at, updated_at
        FROM follow_up_items
        WHERE meeting_id=?
        ORDER BY
          CASE WHEN start_date IS NULL THEN 1 ELSE 0 END,
          start_date,
          CASE WHEN end_date IS NULL THEN 1 ELSE 0 END,
          end_date,
          id
        """,
        (meeting_id,),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def normalize_participants(value):
    if value is None:
        return None
    if isinstance(value, list):
        return json.dumps(value, ensure_ascii=False)
    return str(value)


def parse_participants(value):
    if not value:
        return value
    try:
        return json.loads(value)
    except Exception:
        return value


def row_to_meeting(row):
    if not row:
        return None
    d = dict(row)
    d["participants"] = parse_participants(d.get("participants"))
    return d


def row_to_translation(row):
    if not row:
        return None
    d = dict(row)
    return {
        "meeting_id": d["meeting_id"],
        "language": d["language"],
        "title": d["translated_title"],
        "summary": d.get("translated_summary"),
        "transcript": d["translated_transcript"],
        "model": d.get("model"),
        "created_at": d["created_at"],
    }


def public_user(row):
    return {
        "id": row["id"],
        "email": row["email"],
        "display_name": row["display_name"],
        "is_admin": bool(row["is_admin"]),
        "is_active": bool(row["is_active"]),
    }


def validate_new_password(password: str):
    # User-approved free-form password policy.
    # Preserve the password exactly as entered; only an empty string is rejected.
    if password is None or len(password) == 0:
        raise HTTPException(status_code=400, detail="비밀번호를 입력해 주세요.")
    return True


def get_current_user_optional(request: Request):
    raw_token = request.cookies.get(SESSION_COOKIE)
    if not raw_token:
        return None
    token_hash = hash_session_token(raw_token)
    conn = db()
    row = conn.execute(
        """
        SELECT u.*, s.expires_at AS session_expires_at
        FROM sessions s
        JOIN users u ON u.id = s.user_id
        WHERE s.token_hash=? AND u.is_active=1
        """,
        (token_hash,),
    ).fetchone()
    if not row:
        conn.close()
        return None
    if datetime.fromisoformat(row["session_expires_at"]) < datetime.now(timezone.utc):
        conn.execute("DELETE FROM sessions WHERE token_hash=?", (token_hash,))
        conn.commit()
        conn.close()
        return None
    result = public_user(row)
    conn.close()
    return result


def require_user(request: Request):
    user = get_current_user_optional(request)
    if not user:
        raise HTTPException(status_code=401, detail="로그인이 필요합니다.")
    return user


def require_admin(user=Depends(require_user)):
    if not user.get("is_admin"):
        raise HTTPException(status_code=403, detail="관리자 권한이 필요합니다.")
    return user


def normalize_folder_color(value: str | None) -> str:
    color = (value or "#536878").strip().upper()
    if color not in FOLDER_COLOR_PALETTE:
        raise HTTPException(status_code=400, detail="허용된 10개 폴더 색상 중 하나를 선택해 주세요.")
    return color



def validate_folder_parent(conn, folder_id: int | None, parent_id: int | None):
    if parent_id is None:
        return
    if folder_id is not None and int(parent_id) == int(folder_id):
        raise HTTPException(status_code=400, detail="폴더 자신을 상위 폴더로 지정할 수 없습니다.")

    parent = conn.execute("SELECT id, parent_id FROM folders WHERE id=?", (parent_id,)).fetchone()
    if not parent:
        raise HTTPException(status_code=404, detail="상위 폴더를 찾을 수 없습니다.")

    # Cycle guard when an existing folder's parent is changed.
    if folder_id is not None:
        seen = set()
        current = parent
        while current:
            current_id = int(current["id"])
            if current_id == int(folder_id):
                raise HTTPException(status_code=400, detail="하위 폴더를 상위 폴더로 지정할 수 없습니다.")
            if current_id in seen:
                break
            seen.add(current_id)
            next_id = current["parent_id"]
            if next_id is None:
                break
            current = conn.execute(
                "SELECT id, parent_id FROM folders WHERE id=?",
                (next_id,),
            ).fetchone()


def create_meeting(payload: MeetingIn):
    now = now_iso()
    conn = db()
    try:
        normalized_fu = normalize_follow_up_items(payload.follow_up_items)
        follow_up_text = (payload.follow_up or "").strip() or follow_up_items_to_text(normalized_fu)

        cur = conn.execute(
            """
            INSERT INTO meetings(
                title, recorded_at, transcript, summary, participants,
                source, created_at, updated_at, folder_id, author,
                location, meeting_method, purpose, follow_up
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                payload.title.strip() or "제목 없는 회의",
                payload.recorded_at,
                payload.transcript,
                payload.summary,
                normalize_participants(payload.participants),
                payload.source,
                now,
                now,
                payload.folder_id,
                (payload.author or "").strip() or None,
                (payload.location or "").strip() or None,
                (payload.meeting_method or "").strip() or None,
                (payload.purpose or "").strip() or None,
                follow_up_text,
            ),
        )
        meeting_id = cur.lastrowid
        replace_follow_up_items(conn, meeting_id, payload.follow_up_items)
        conn.commit()

        row = conn.execute(
            """
            SELECT m.*, f.name AS folder_name, f.color AS folder_color
            FROM meetings m
            LEFT JOIN folders f ON f.id = m.folder_id
            WHERE m.id=?
            """,
            (meeting_id,),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=500, detail="회의록 INSERT 후 DB 재조회에 실패했습니다.")

        result = row_to_meeting(row)
        result["follow_up_items"] = get_follow_up_items(meeting_id)
        result["saved"] = True
        result["storage_backend"] = "postgresql" if USE_POSTGRES else "sqlite_ephemeral"
        return result
    except Exception:
        try:
            conn.rollback()
        except Exception:
            pass
        raise
    finally:
        conn.close()


def get_original_meeting(meeting_id: int):
    conn = db()
    row = conn.execute(
        """
        SELECT m.*, f.name AS folder_name, f.color AS folder_color
        FROM meetings m
        LEFT JOIN folders f ON f.id = m.folder_id
        WHERE m.id=?
        """,
        (meeting_id,),
    ).fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Meeting not found")
    result = row_to_meeting(row)
    result["follow_up_items"] = get_follow_up_items(meeting_id)
    return result


def get_translation(meeting_id: int, language: str):
    conn = db()
    row = conn.execute(
        "SELECT * FROM translations WHERE meeting_id=? AND language=?",
        (meeting_id, language),
    ).fetchone()
    conn.close()
    return row_to_translation(row)


def available_translation_languages(meeting_id: int):
    conn = db()
    rows = conn.execute(
        "SELECT language FROM translations WHERE meeting_id=? ORDER BY language",
        (meeting_id,),
    ).fetchall()
    conn.close()
    return [r["language"] for r in rows]


def extract_output_text(api_response: dict) -> str:
    if isinstance(api_response.get("output_text"), str):
        return api_response["output_text"]
    texts = []
    for item in api_response.get("output", []):
        if item.get("type") != "message":
            continue
        for content in item.get("content", []):
            if content.get("type") in {"output_text", "text"} and content.get("text"):
                texts.append(content["text"])
    return "\n".join(texts).strip()


def parse_json_text(text: str) -> dict:
    cleaned = text.strip()
    if cleaned.startswith("```"):
        lines = cleaned.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        cleaned = "\n".join(lines).strip()
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        start = cleaned.find("{")
        end = cleaned.rfind("}")
        if start >= 0 and end > start:
            return json.loads(cleaned[start : end + 1])
        raise


def call_translation_model(meeting: dict, target_language: str):
    if not OPENAI_API_KEY:
        raise HTTPException(
            status_code=503,
            detail="OPENAI_API_KEY가 설정되지 않았습니다. 서버 환경변수에 API 키를 설정해 주세요.",
        )

    target_name = LANGUAGES[target_language]
    source_payload = {
        "title": meeting.get("title") or "",
        "summary": meeting.get("summary") or "",
        "transcript": meeting.get("transcript") or "",
    }

    instructions = f"""
You are a professional meeting-minutes translator for manufacturing, engineering, R&D, and business meetings.
Translate the supplied Korean meeting content into {target_name}.

Rules:
- Preserve all technical terms, numbers, units, chemical formulas, equipment names, proper nouns, dates, and action items accurately.
- Preserve speaker labels, timestamps, bullets, section structure, and line breaks as much as possible.
- Do not summarize, omit, embellish, or add explanations.
- If a proper noun or acronym should remain unchanged, keep it unchanged.
- For Japanese, use natural professional business/technical Japanese.
- For English, use concise professional technical English.
- Return ONLY a valid JSON object with exactly these keys: title, summary, transcript.
- Every value must be a JSON string. If summary is empty, return an empty string.
""".strip()

    body = {
        "model": OPENAI_TRANSLATION_MODEL,
        "input": [
            {"role": "system", "content": instructions},
            {
                "role": "user",
                "content": "Translate this meeting JSON:\n" + json.dumps(source_payload, ensure_ascii=False),
            },
        ],
    }

    req = urllib.request.Request(
        "https://api.openai.com/v1/responses",
        data=json.dumps(body, ensure_ascii=False).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {OPENAI_API_KEY}",
            "Content-Type": "application/json",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=180) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise HTTPException(status_code=502, detail=f"Translation API error: {detail[:1000]}")
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Translation request failed: {exc}")

    text = extract_output_text(payload)
    if not text:
        raise HTTPException(status_code=502, detail="Translation API returned no text output")

    try:
        translated = parse_json_text(text)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Translation output parsing failed: {exc}")

    for key in ("title", "summary", "transcript"):
        if key not in translated or not isinstance(translated[key], str):
            raise HTTPException(status_code=502, detail=f"Translation output missing valid '{key}' field")
    return translated


@app.get("/api/health")
def health():
    conn = db()
    user_count = conn.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"]
    conn.close()
    return {
        "ok": True,
        "auth_configured": user_count > 0,
        "translation_configured": bool(OPENAI_API_KEY),
        "plaud_webhook_configured": bool(WEBHOOK_SECRET and WEBHOOK_SECRET != "change-me"),
        "translation_model": OPENAI_TRANSLATION_MODEL,
        "cookie_secure": COOKIE_SECURE,
        "cookie_samesite": COOKIE_SAMESITE,
        "storage_backend": "postgresql" if USE_POSTGRES else "sqlite_ephemeral",
        "persistent_storage": bool(USE_POSTGRES),
    }


@app.post("/api/auth/login")
def login(payload: LoginIn, response: Response):
    email = payload.email.strip().lower()
    conn = db()
    row = conn.execute("SELECT * FROM users WHERE email=? AND is_active=1", (email,)).fetchone()
    if not row or not verify_password(payload.password, row["password_salt"], row["password_hash"]):
        conn.close()
        raise HTTPException(status_code=401, detail="이메일 또는 비밀번호가 올바르지 않습니다.")
    raw_token = secrets.token_urlsafe(32)
    token_hash = hash_session_token(raw_token)
    expires = datetime.now(timezone.utc) + timedelta(days=SESSION_DAYS)
    conn.execute(
        "INSERT INTO sessions(token_hash, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)",
        (token_hash, row["id"], expires.isoformat(), now_iso()),
    )
    conn.commit()
    user = public_user(row)
    conn.close()
    response.set_cookie(
        key=SESSION_COOKIE, value=raw_token, httponly=True, secure=COOKIE_SECURE,
        samesite=COOKIE_SAMESITE, max_age=SESSION_DAYS * 24 * 3600, path="/"
    )
    return {"user": user}


@app.post("/api/auth/logout")
def logout(request: Request, response: Response):
    raw_token = request.cookies.get(SESSION_COOKIE)
    if raw_token:
        conn = db()
        conn.execute("DELETE FROM sessions WHERE token_hash=?", (hash_session_token(raw_token),))
        conn.commit()
        conn.close()
    response.delete_cookie(SESSION_COOKIE, path="/")
    return {"ok": True}


@app.get("/api/auth/me")
def me(user=Depends(require_user)):
    return {"user": user}


@app.post("/api/auth/change-password")
def change_password(payload: ChangePasswordIn, user=Depends(require_user)):
    validate_new_password(payload.new_password)
    conn = db()
    row = conn.execute("SELECT * FROM users WHERE id=? AND is_active=1", (user["id"],)).fetchone()
    if not row or not verify_password(payload.current_password, row["password_salt"], row["password_hash"]):
        conn.close()
        raise HTTPException(status_code=400, detail="현재 비밀번호가 올바르지 않습니다.")
    salt_hex, password_hex = hash_password(payload.new_password)
    conn.execute(
        "UPDATE users SET password_salt=?, password_hash=? WHERE id=?",
        (salt_hex, password_hex, user["id"]),
    )
    # Invalidate all other sessions after a password change.
    conn.execute("DELETE FROM sessions WHERE user_id=?", (user["id"],))
    conn.commit()
    conn.close()
    return {"ok": True, "relogin_required": True}


@app.get("/api/admin/users")
def admin_list_users(admin=Depends(require_admin)):
    conn = db()
    rows = conn.execute(
        "SELECT id, email, display_name, is_active, is_admin, created_at FROM users ORDER BY created_at, id"
    ).fetchall()
    conn.close()
    return [
        {
            "id": r["id"],
            "email": r["email"],
            "display_name": r["display_name"],
            "is_active": bool(r["is_active"]),
            "is_admin": bool(r["is_admin"]),
            "created_at": r["created_at"],
        }
        for r in rows
    ]


@app.post("/api/admin/users")
def admin_create_user(payload: AdminUserCreateIn, admin=Depends(require_admin)):
    email = payload.email.strip().lower()
    if not email or "@" not in email:
        raise HTTPException(status_code=400, detail="올바른 이메일 주소를 입력해 주세요.")
    validate_new_password(payload.password)
    salt_hex, password_hex = hash_password(payload.password)
    conn = db()
    try:
        cur = conn.execute(
            """
            INSERT INTO users(email, display_name, password_salt, password_hash, is_active, is_admin, created_at)
            VALUES (?, ?, ?, ?, 1, 0, ?)
            """,
            (email, (payload.display_name or "").strip() or None, salt_hex, password_hex, now_iso()),
        )
        conn.commit()
    except DB_INTEGRITY_ERRORS:
        conn.close()
        raise HTTPException(status_code=409, detail="이미 등록된 이메일입니다.")
    row = conn.execute("SELECT * FROM users WHERE id=?", (cur.lastrowid,)).fetchone()
    result = public_user(row)
    conn.close()
    return result


@app.patch("/api/admin/users/{user_id}")
def admin_update_user(user_id: int, payload: AdminUserPatchIn, admin=Depends(require_admin)):
    conn = db()
    row = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="사용자를 찾을 수 없습니다.")

    if user_id == admin["id"] and payload.is_active is False:
        conn.close()
        raise HTTPException(status_code=400, detail="현재 로그인한 관리자 계정은 비활성화할 수 없습니다.")

    updates = []
    values = []
    if payload.display_name is not None:
        updates.append("display_name=?")
        values.append(payload.display_name.strip() or None)
    if payload.is_active is not None:
        updates.append("is_active=?")
        values.append(1 if payload.is_active else 0)
    if payload.new_password:
        validate_new_password(payload.new_password)
        salt_hex, password_hex = hash_password(payload.new_password)
        updates.extend(["password_salt=?", "password_hash=?"])
        values.extend([salt_hex, password_hex])

    if updates:
        values.append(user_id)
        conn.execute(f"UPDATE users SET {', '.join(updates)} WHERE id=?", values)
        if payload.is_active is False or payload.new_password:
            conn.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
        conn.commit()

    updated = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    result = public_user(updated)
    conn.close()
    return result


@app.get("/api/admin/diagnostics/db")
def database_diagnostics(admin=Depends(require_admin)):
    conn = db()
    try:
        meeting_count = conn.execute("SELECT COUNT(*) AS n FROM meetings").fetchone()["n"]
        folder_count = conn.execute("SELECT COUNT(*) AS n FROM folders").fetchone()["n"]
        user_count = conn.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"]
        return {
            "ok": True,
            "storage_backend": "postgresql" if USE_POSTGRES else "sqlite_ephemeral",
            "meeting_count": meeting_count,
            "folder_count": folder_count,
            "user_count": user_count,
        }
    finally:
        conn.close()


def _plaud_source_external_id(payload: PlaudWebhookIn) -> str:
    explicit_id = (payload.external_id or payload.recording_id or "").strip()
    if explicit_id:
        return "id:" + explicit_id

    create_time = (payload.create_time or "").strip()
    if not create_time:
        raise HTTPException(
            status_code=400,
            detail="PLAUD create_time or an explicit external_id/recording_id is required for duplicate protection.",
        )

    title = (payload.title or "").strip()
    material = f"plaud-zapier|{create_time}|{title}".encode("utf-8")
    return "fallback:" + hashlib.sha256(material).hexdigest()


def _plaud_webhook_secret_ok(received: Optional[str]) -> bool:
    if not WEBHOOK_SECRET or WEBHOOK_SECRET == "change-me":
        return False
    return hmac.compare_digest(received or "", WEBHOOK_SECRET)


@app.post("/api/plaud/webhook")
def plaud_webhook(payload: PlaudWebhookIn, x_webhook_secret: Optional[str] = Header(default=None)):
    # This endpoint is intentionally disabled until a real secret is configured in Render.
    if not WEBHOOK_SECRET or WEBHOOK_SECRET == "change-me":
        raise HTTPException(status_code=503, detail="PLAUD webhook is not configured")
    if not _plaud_webhook_secret_ok(x_webhook_secret):
        raise HTTPException(status_code=401, detail="Invalid webhook secret")

    transcript = (payload.transcript or "").strip()
    summary = (payload.summary or "").strip()
    if not transcript and not summary:
        raise HTTPException(status_code=400, detail="PLAUD transcript or summary is required")

    title = (payload.title or "").strip() or "PLAUD 회의"
    recorded_at = (payload.create_time or "").strip() or None
    source = "plaud-zapier"
    source_external_id = _plaud_source_external_id(payload)
    now = now_iso()

    conn = db()
    try:
        existing = conn.execute(
            """
            SELECT id, title, transcript, summary, recorded_at, source,
                   created_at, updated_at, source_synced_at
            FROM meetings
            WHERE source=? AND source_external_id=?
            """,
            (source, source_external_id),
        ).fetchone()

        if existing:
            # An automatic refresh is safe only while the meeting has not been manually edited.
            source_synced_at = existing["source_synced_at"]
            automatically_owned = bool(source_synced_at and existing["updated_at"] == source_synced_at)

            if automatically_owned:
                conn.execute(
                    """
                    UPDATE meetings
                    SET title=?, recorded_at=?, transcript=?, summary=?,
                        updated_at=?, source_synced_at=?
                    WHERE id=?
                    """,
                    (title, recorded_at, transcript, summary or None, now, now, existing["id"]),
                )
                conn.commit()
                return {
                    "ok": True,
                    "status": "updated",
                    "meeting_id": existing["id"],
                    "source_external_id": source_external_id,
                    "duplicate": True,
                    "manual_edits_preserved": False,
                }

            return {
                "ok": True,
                "status": "duplicate_preserved",
                "meeting_id": existing["id"],
                "source_external_id": source_external_id,
                "duplicate": True,
                "manual_edits_preserved": True,
            }

        cur = conn.execute(
            """
            INSERT INTO meetings(
                title, recorded_at, transcript, summary, participants,
                source, created_at, updated_at, folder_id, author,
                location, meeting_method, purpose, follow_up,
                source_external_id, source_synced_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                title, recorded_at, transcript, summary or None, None,
                source, now, now, None, None,
                None, None, None, None,
                source_external_id, now,
            ),
        )
        meeting_id = cur.lastrowid
        conn.commit()
        return {
            "ok": True,
            "status": "created",
            "meeting_id": meeting_id,
            "source_external_id": source_external_id,
            "duplicate": False,
            "storage_backend": "postgresql" if USE_POSTGRES else "sqlite_ephemeral",
        }
    except DB_INTEGRITY_ERRORS:
        # A simultaneous retry can race the unique index. Treat the winner as the canonical import.
        try:
            conn.rollback()
        except Exception:
            pass
        existing = conn.execute(
            "SELECT id FROM meetings WHERE source=? AND source_external_id=?",
            (source, source_external_id),
        ).fetchone()
        if existing:
            return {
                "ok": True,
                "status": "duplicate_race_preserved",
                "meeting_id": existing["id"],
                "source_external_id": source_external_id,
                "duplicate": True,
                "manual_edits_preserved": True,
            }
        raise
    except Exception:
        try:
            conn.rollback()
        except Exception:
            pass
        raise
    finally:
        conn.close()


@app.get("/api/drafts/current")
def get_current_draft(user=Depends(require_user)):
    conn = db()
    row = conn.execute(
        """
        SELECT d.*, f.name AS folder_name
        FROM drafts d
        LEFT JOIN folders f ON f.id = d.folder_id
        WHERE d.user_id=?
        """,
        (user["id"],),
    ).fetchone()
    conn.close()
    if not row:
        return {"draft": None}
    result = dict(row)
    try:
        result["follow_up_items"] = json.loads(result.get("follow_up_items_json") or "[]")
    except Exception:
        result["follow_up_items"] = []
    return {"draft": result}


@app.put("/api/drafts/current")
def save_current_draft(payload: DraftIn, user=Depends(require_user)):
    conn = db()
    if payload.folder_id is not None:
        folder = conn.execute("SELECT id FROM folders WHERE id=?", (payload.folder_id,)).fetchone()
        if not folder:
            conn.close()
            raise HTTPException(status_code=404, detail="자동저장할 폴더를 찾을 수 없습니다.")

    normalized_fu = normalize_follow_up_items(payload.follow_up_items)
    fu_json = json.dumps(normalized_fu, ensure_ascii=False)

    conn.execute(
        """
        INSERT INTO drafts(
            user_id, title, recorded_at, author, folder_id,
            location, meeting_method, participants, purpose,
            transcript, summary, follow_up, follow_up_items_json, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(user_id) DO UPDATE SET
            title=excluded.title,
            recorded_at=excluded.recorded_at,
            author=excluded.author,
            folder_id=excluded.folder_id,
            location=excluded.location,
            meeting_method=excluded.meeting_method,
            participants=excluded.participants,
            purpose=excluded.purpose,
            transcript=excluded.transcript,
            summary=excluded.summary,
            follow_up=excluded.follow_up,
            follow_up_items_json=excluded.follow_up_items_json,
            updated_at=excluded.updated_at
        """,
        (
            user["id"],
            (payload.title or "").strip() or None,
            payload.recorded_at,
            (payload.author or "").strip() or None,
            payload.folder_id,
            (payload.location or "").strip() or None,
            (payload.meeting_method or "").strip() or None,
            normalize_participants(payload.participants),
            (payload.purpose or "").strip() or None,
            payload.transcript or "",
            payload.summary,
            payload.follow_up or follow_up_items_to_text(normalized_fu),
            fu_json,
            now_iso(),
        ),
    )
    conn.commit()
    row = conn.execute("SELECT * FROM drafts WHERE user_id=?", (user["id"],)).fetchone()
    conn.close()
    result = dict(row)
    result["follow_up_items"] = normalized_fu
    return {"ok": True, "draft": result}


@app.delete("/api/drafts/current")
def delete_current_draft(user=Depends(require_user)):
    conn = db()
    conn.execute("DELETE FROM drafts WHERE user_id=?", (user["id"],))
    conn.commit()
    conn.close()
    return {"ok": True}


@app.get("/api/folders")
def list_folders(user=Depends(require_user)):
    conn = db()
    rows = conn.execute(
        """
        SELECT
            f.id, f.name, f.parent_id, f.color, f.created_at,
            COUNT(m.id) AS meeting_count
        FROM folders f
        LEFT JOIN meetings m ON m.folder_id = f.id
        GROUP BY f.id, f.name, f.parent_id, f.color, f.created_at
        ORDER BY LOWER(f.name), f.id
        """
    ).fetchall()
    total_count = conn.execute("SELECT COUNT(*) AS n FROM meetings").fetchone()["n"]
    uncategorized_count = conn.execute(
        "SELECT COUNT(*) AS n FROM meetings WHERE folder_id IS NULL"
    ).fetchone()["n"]
    conn.close()
    return {
        "folders": [
            {
                "id": r["id"],
                "name": r["name"],
                "parent_id": r["parent_id"],
                "color": r["color"] or "#4F6B8A",
                "created_at": r["created_at"],
                "meeting_count": r["meeting_count"],
            }
            for r in rows
        ],
        "total_count": total_count,
        "uncategorized_count": uncategorized_count,
    }


@app.post("/api/folders")
def create_folder(payload: FolderIn, user=Depends(require_user)):
    name = payload.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="폴더 이름을 입력해 주세요.")
    if len(name) > 80:
        raise HTTPException(status_code=400, detail="폴더 이름은 80자 이하로 입력해 주세요.")

    color = normalize_folder_color(payload.color)
    conn = db()
    validate_folder_parent(conn, None, payload.parent_id)

    try:
        cur = conn.execute(
            "INSERT INTO folders(name, parent_id, color, created_at) VALUES (?, ?, ?, ?)",
            (name, payload.parent_id, color, now_iso()),
        )
        conn.commit()
    except DB_INTEGRITY_ERRORS:
        conn.rollback()
        conn.close()
        raise HTTPException(status_code=409, detail="같은 이름의 폴더가 이미 있습니다.")

    row = conn.execute("SELECT * FROM folders WHERE id=?", (cur.lastrowid,)).fetchone()
    result = dict(row)
    conn.close()
    return result


@app.patch("/api/folders/{folder_id}/rename")
def rename_folder(folder_id: int, payload: FolderRenameIn, user=Depends(require_user)):
    name = payload.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="폴더 이름을 입력해 주세요.")
    if len(name) > 80:
        raise HTTPException(status_code=400, detail="폴더 이름은 80자 이하로 입력해 주세요.")

    conn = db()
    existing = conn.execute("SELECT id FROM folders WHERE id=?", (folder_id,)).fetchone()
    if not existing:
        conn.close()
        raise HTTPException(status_code=404, detail="폴더를 찾을 수 없습니다.")
    try:
        conn.execute("UPDATE folders SET name=? WHERE id=?", (name, folder_id))
        conn.commit()
    except DB_INTEGRITY_ERRORS:
        conn.rollback()
        conn.close()
        raise HTTPException(status_code=409, detail="같은 이름의 폴더가 이미 있습니다.")

    row = conn.execute("SELECT * FROM folders WHERE id=?", (folder_id,)).fetchone()
    result = dict(row)
    conn.close()
    return result


@app.patch("/api/folders/{folder_id}/move")
def move_folder(folder_id: int, payload: FolderMoveIn, user=Depends(require_user)):
    conn = db()
    existing = conn.execute("SELECT id, parent_id FROM folders WHERE id=?", (folder_id,)).fetchone()
    if not existing:
        conn.close()
        raise HTTPException(status_code=404, detail="폴더를 찾을 수 없습니다.")

    validate_folder_parent(conn, folder_id, payload.parent_id)
    conn.execute("UPDATE folders SET parent_id=? WHERE id=?", (payload.parent_id, folder_id))
    conn.commit()
    row = conn.execute("SELECT * FROM folders WHERE id=?", (folder_id,)).fetchone()
    result = dict(row)
    conn.close()
    return result


@app.patch("/api/folders/{folder_id}/color")
def change_folder_color(folder_id: int, payload: FolderColorIn, user=Depends(require_user)):
    color = normalize_folder_color(payload.color)
    conn = db()
    existing = conn.execute("SELECT id FROM folders WHERE id=?", (folder_id,)).fetchone()
    if not existing:
        conn.close()
        raise HTTPException(status_code=404, detail="폴더를 찾을 수 없습니다.")

    conn.execute("UPDATE folders SET color=? WHERE id=?", (color, folder_id))
    conn.commit()
    row = conn.execute("SELECT * FROM folders WHERE id=?", (folder_id,)).fetchone()
    result = dict(row)
    conn.close()
    return result


@app.patch("/api/folders/{folder_id}")
def update_folder(folder_id: int, payload: FolderIn, user=Depends(require_user)):
    name = payload.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="폴더 이름을 입력해 주세요.")
    if len(name) > 80:
        raise HTTPException(status_code=400, detail="폴더 이름은 80자 이하로 입력해 주세요.")

    color = normalize_folder_color(payload.color)
    conn = db()
    existing = conn.execute(
        "SELECT id FROM folders WHERE id=?",
        (folder_id,),
    ).fetchone()
    if not existing:
        conn.close()
        raise HTTPException(status_code=404, detail="폴더를 찾을 수 없습니다.")

    validate_folder_parent(conn, folder_id, payload.parent_id)

    try:
        conn.execute(
            "UPDATE folders SET name=?, parent_id=?, color=? WHERE id=?",
            (name, payload.parent_id, color, folder_id),
        )
        conn.commit()
    except DB_INTEGRITY_ERRORS:
        conn.rollback()
        conn.close()
        raise HTTPException(status_code=409, detail="같은 이름의 폴더가 이미 있습니다.")

    row = conn.execute("SELECT * FROM folders WHERE id=?", (folder_id,)).fetchone()
    result = dict(row)
    conn.close()
    return result


@app.delete("/api/folders/{folder_id}")
def delete_folder(folder_id: int, user=Depends(require_user)):
    conn = db()
    row = conn.execute(
        "SELECT id, name, parent_id FROM folders WHERE id=?",
        (folder_id,),
    ).fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="폴더를 찾을 수 없습니다.")

    parent_id = row["parent_id"]
    meeting_count = conn.execute(
        "SELECT COUNT(*) AS n FROM meetings WHERE folder_id=?",
        (folder_id,),
    ).fetchone()["n"]
    child_count = conn.execute(
        "SELECT COUNT(*) AS n FROM folders WHERE parent_id=?",
        (folder_id,),
    ).fetchone()["n"]

    # Preserve content: meetings and child folders move one level up.
    conn.execute("UPDATE meetings SET folder_id=? WHERE folder_id=?", (parent_id, folder_id))
    conn.execute("UPDATE folders SET parent_id=? WHERE parent_id=?", (parent_id, folder_id))
    conn.execute("DELETE FROM folders WHERE id=?", (folder_id,))
    conn.commit()
    conn.close()

    return {
        "ok": True,
        "deleted_folder_id": folder_id,
        "deleted_folder_name": row["name"],
        "moved_meetings": meeting_count,
        "reparented_child_folders": child_count,
        "destination_parent_id": parent_id,
    }


@app.get("/api/storage/status")
def storage_status(user=Depends(require_user)):
    conn = db()
    try:
        meeting_count = conn.execute("SELECT COUNT(*) AS n FROM meetings").fetchone()["n"]
        folder_count = conn.execute("SELECT COUNT(*) AS n FROM folders").fetchone()["n"]
        return {
            "ok": True,
            "backend": "postgresql" if USE_POSTGRES else "sqlite_ephemeral",
            "persistent": bool(USE_POSTGRES),
            "persistent_required": REQUIRE_PERSISTENT_DB,
            "meeting_count": meeting_count,
            "folder_count": folder_count,
        }
    finally:
        conn.close()



@app.post("/api/meetings")
def add_meeting(payload: MeetingIn, user=Depends(require_user)):
    if not (payload.author or "").strip():
        payload.author = (user.get("display_name") or user.get("email") or "").strip() or None
    return create_meeting(payload)


class FollowUpMemoIn(BaseModel):
    memo: Optional[str] = None
    color: Optional[str] = None


@app.patch("/api/follow-ups/{follow_up_id}/memo")
def update_follow_up_memo(
    follow_up_id: int,
    payload: FollowUpMemoIn,
    user=Depends(require_user),
):
    conn = db()
    row = conn.execute(
        """
        SELECT fu.id, fu.meeting_id
        FROM follow_up_items fu
        JOIN meetings m ON m.id = fu.meeting_id
        WHERE fu.id=?
        """,
        (follow_up_id,),
    ).fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="F/U 항목을 찾을 수 없습니다.")

    memo = (payload.memo or "").strip() or None
    existing = conn.execute("SELECT color FROM follow_up_items WHERE id=?", (follow_up_id,)).fetchone()
    color = (payload.color or (existing["color"] if existing else None) or "#64748B").strip().upper()
    if color not in FOLDER_COLOR_PALETTE:
        conn.close()
        raise HTTPException(status_code=400, detail="허용된 10개 F/U 색상 중 하나를 선택해 주세요.")
    conn.execute(
        "UPDATE follow_up_items SET memo=?, color=?, updated_at=? WHERE id=?",
        (memo, color, now_iso(), follow_up_id),
    )
    conn.commit()

    updated = conn.execute(
        """
        SELECT id, meeting_id, task, owner, start_date, end_date,
               status, completion_note, completed_date, memo, color, created_at, updated_at
        FROM follow_up_items
        WHERE id=?
        """,
        (follow_up_id,),
    ).fetchone()
    conn.close()
    return dict(updated)


@app.get("/api/follow-ups/search")
def search_follow_ups(q: str = "", user=Depends(require_user)):
    query = (q or "").strip()
    if not query:
        return {"q": "", "items": []}

    like = f"%{query}%"
    conn = db()
    rows = conn.execute(
        """
        SELECT
            fu.id, fu.meeting_id, fu.task, fu.owner, fu.start_date, fu.end_date,
            fu.status, fu.completion_note, fu.completed_date, fu.memo, fu.color,
            m.title AS meeting_title,
            m.folder_id,
            f.name AS folder_name,
            f.color AS folder_color
        FROM follow_up_items fu
        JOIN meetings m ON m.id = fu.meeting_id
        LEFT JOIN folders f ON f.id = m.folder_id
        WHERE
            fu.task LIKE ?
            OR COALESCE(fu.owner, '') LIKE ?
            OR COALESCE(fu.memo, '') LIKE ?
            OR COALESCE(fu.completion_note, '') LIKE ?
            OR m.title LIKE ?
        ORDER BY
            CASE WHEN fu.status='completed' THEN 1 ELSE 0 END,
            COALESCE(fu.end_date, fu.start_date, '9999-12-31'),
            fu.id DESC
        LIMIT 100
        """,
        (like, like, like, like, like),
    ).fetchall()
    conn.close()
    return {"q": query, "items": [dict(r) for r in rows]}


@app.get("/api/follow-ups/calendar")
def follow_up_calendar(month: str, user=Depends(require_user)):
    if not re.fullmatch(r"\d{4}-\d{2}", month or ""):
        raise HTTPException(status_code=400, detail="month는 YYYY-MM 형식이어야 합니다.")
    try:
        year, month_num = [int(x) for x in month.split("-")]
        first = datetime(year, month_num, 1)
        if month_num == 12:
            next_month = datetime(year + 1, 1, 1)
        else:
            next_month = datetime(year, month_num + 1, 1)
    except ValueError:
        raise HTTPException(status_code=400, detail="유효하지 않은 월입니다.")

    first_date = first.strftime("%Y-%m-%d")
    last_date = (next_month - timedelta(days=1)).strftime("%Y-%m-%d")

    conn = db()
    rows = conn.execute(
        """
        SELECT
            fu.id, fu.meeting_id, fu.task, fu.owner, fu.start_date, fu.end_date,
            fu.status, fu.completion_note, fu.completed_date, fu.memo, fu.color,
            m.title AS meeting_title,
            m.folder_id,
            f.name AS folder_name,
            f.color AS folder_color
        FROM follow_up_items fu
        JOIN meetings m ON m.id = fu.meeting_id
        LEFT JOIN folders f ON f.id = m.folder_id
        WHERE
            (fu.start_date IS NOT NULL OR fu.end_date IS NOT NULL)
            AND COALESCE(fu.end_date, fu.start_date) >= ?
            AND COALESCE(fu.start_date, fu.end_date) <= ?
        ORDER BY
            COALESCE(fu.start_date, fu.end_date),
            COALESCE(fu.end_date, fu.start_date),
            fu.id
        """,
        (first_date, last_date),
    ).fetchall()
    conn.close()

    return {
        "month": month,
        "items": [dict(r) for r in rows],
    }


@app.get("/api/meetings")
def list_meetings(q: str = "", folder: str = "all", user=Depends(require_user)):
    conn = db()
    clauses = []
    params = []

    if q.strip():
        like = f"%{q.strip()}%"
        clauses.append(
            """
            (
                m.title LIKE ?
                OR m.transcript LIKE ?
                OR COALESCE(m.summary, '') LIKE ?
                OR EXISTS (
                    SELECT 1
                    FROM translations t
                    WHERE t.meeting_id = m.id
                      AND (
                          COALESCE(t.translated_title, '') LIKE ?
                          OR COALESCE(t.translated_transcript, '') LIKE ?
                          OR COALESCE(t.translated_summary, '') LIKE ?
                      )
                )
            )
            """
        )
        params.extend([like, like, like, like, like, like])

    if folder == "uncategorized":
        clauses.append("m.folder_id IS NULL")
    elif folder not in {"", "all"}:
        try:
            folder_id = int(folder)
        except ValueError:
            conn.close()
            raise HTTPException(status_code=400, detail="잘못된 폴더 필터입니다.")
        clauses.append("m.folder_id=?")
        params.append(folder_id)

    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""

    rows = conn.execute(
        f"""
        SELECT
            m.id,
            m.title,
            m.recorded_at,
            m.summary,
            m.participants,
            m.source,
            m.created_at,
            m.folder_id,
            m.author,
            f.name AS folder_name,
            f.color AS folder_color
        FROM meetings m
        LEFT JOIN folders f ON f.id = m.folder_id
        {where}
        ORDER BY
            CASE WHEN m.recorded_at IS NULL THEN 1 ELSE 0 END,
            m.recorded_at DESC,
            m.created_at DESC,
            m.id DESC
        """,
        params,
    ).fetchall()
    conn.close()

    result = []
    for r in rows:
        item = row_to_meeting(r)
        item["translations"] = available_translation_languages(item["id"])
        result.append(item)
    return result


@app.get("/api/meetings/{meeting_id}")
def get_meeting(meeting_id: int, lang: str = Query(default="ko", pattern="^(ko|en|ja)$"), user=Depends(require_user)):
    meeting = get_original_meeting(meeting_id)
    meeting["available_translations"] = available_translation_languages(meeting_id)
    meeting["language"] = "ko"

    if lang == "ko":
        return meeting

    translated = get_translation(meeting_id, lang)
    if not translated:
        raise HTTPException(status_code=404, detail="Requested translation has not been created yet")

    return {
        **meeting,
        "title": translated["title"],
        "summary": translated["summary"],
        "transcript": translated["transcript"],
        "language": lang,
        "translation_model": translated.get("model"),
        "translation_created_at": translated.get("created_at"),
    }


@app.patch("/api/meetings/{meeting_id}/folder")
def move_meeting_folder(meeting_id: int, payload: MeetingFolderMoveIn, user=Depends(require_user)):
    conn = db()
    try:
        meeting = conn.execute(
            "SELECT id, folder_id FROM meetings WHERE id=?",
            (meeting_id,),
        ).fetchone()
        if not meeting:
            raise HTTPException(status_code=404, detail="회의록을 찾을 수 없습니다.")

        folder_name = None
        if payload.folder_id is not None:
            folder = conn.execute(
                "SELECT id, name FROM folders WHERE id=?",
                (payload.folder_id,),
            ).fetchone()
            if not folder:
                raise HTTPException(status_code=404, detail="이동할 폴더를 찾을 수 없습니다.")
            folder_name = folder["name"]

        conn.execute(
            "UPDATE meetings SET folder_id=?, updated_at=? WHERE id=?",
            (payload.folder_id, now_iso(), meeting_id),
        )
        conn.commit()

        # Do not report success from the UPDATE statement alone.
        # Read the persisted value back from the same database.
        verified = conn.execute(
            """
            SELECT m.id, m.folder_id, m.updated_at,
                   f.name AS folder_name, f.color AS folder_color
            FROM meetings m
            LEFT JOIN folders f ON f.id = m.folder_id
            WHERE m.id=?
            """,
            (meeting_id,),
        ).fetchone()
        if not verified:
            raise HTTPException(status_code=500, detail="회의록 이동 후 DB 재조회에 실패했습니다.")

        stored_folder_id = verified["folder_id"]
        expected_folder_id = payload.folder_id
        if stored_folder_id != expected_folder_id:
            raise HTTPException(
                status_code=500,
                detail=f"회의록 위치 저장 검증 실패: expected={expected_folder_id}, stored={stored_folder_id}",
            )

        return {
            "ok": True,
            "verified": True,
            "meeting_id": meeting_id,
            "folder_id": stored_folder_id,
            "folder_name": verified["folder_name"],
            "folder_color": verified["folder_color"],
            "updated_at": verified["updated_at"],
        }
    except HTTPException:
        conn.rollback()
        raise
    except Exception as exc:
        conn.rollback()
        raise HTTPException(status_code=500, detail=f"회의록 위치 저장 실패: {exc}")
    finally:
        conn.close()


@app.put("/api/meetings/{meeting_id}")
def update_meeting(meeting_id: int, payload: MeetingUpdate, user=Depends(require_user)):
    get_original_meeting(meeting_id)
    conn = db()
    try:
        normalized_fu = normalize_follow_up_items(payload.follow_up_items) if payload.follow_up_items is not None else None
        follow_up_text = (payload.follow_up or "").strip() or (
            follow_up_items_to_text(normalized_fu) if normalized_fu is not None else None
        )

        if normalized_fu is None:
            existing = conn.execute("SELECT follow_up FROM meetings WHERE id=?", (meeting_id,)).fetchone()
            follow_up_text = follow_up_text or (existing["follow_up"] if existing else None)

        conn.execute(
            """
            UPDATE meetings
            SET title=?, recorded_at=?, transcript=?, summary=?, participants=?,
                updated_at=?, folder_id=?, author=?, location=?, meeting_method=?,
                purpose=?, follow_up=?
            WHERE id=?
            """,
            (
                payload.title.strip() or "제목 없는 회의",
                payload.recorded_at,
                payload.transcript,
                payload.summary,
                normalize_participants(payload.participants),
                now_iso(),
                payload.folder_id,
                (payload.author or "").strip() or None,
                (payload.location or "").strip() or None,
                (payload.meeting_method or "").strip() or None,
                (payload.purpose or "").strip() or None,
                follow_up_text,
                meeting_id,
            ),
        )

        if normalized_fu is not None:
            replace_follow_up_items(conn, meeting_id, payload.follow_up_items)

        conn.execute("DELETE FROM translations WHERE meeting_id=?", (meeting_id,))
        conn.commit()

        row = conn.execute(
            """
            SELECT m.*, f.name AS folder_name, f.color AS folder_color
            FROM meetings m
            LEFT JOIN folders f ON f.id = m.folder_id
            WHERE m.id=?
            """,
            (meeting_id,),
        ).fetchone()
        result = row_to_meeting(row)
        result["follow_up_items"] = get_follow_up_items(meeting_id)
        result["available_translations"] = []
        result["language"] = "ko"
        return result
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


@app.post("/api/meetings/{meeting_id}/translate")
def translate_meeting(meeting_id: int, payload: TranslationIn, user=Depends(require_user)):
    existing = get_translation(meeting_id, payload.target_language)
    if existing and not payload.force_refresh:
        return {**existing, "cached": True}

    meeting = get_original_meeting(meeting_id)
    translated = call_translation_model(meeting, payload.target_language)
    now = datetime.now(timezone.utc).isoformat()

    conn = db()
    conn.execute(
        """
        INSERT INTO translations(
            meeting_id, language, translated_title, translated_summary,
            translated_transcript, model, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(meeting_id, language) DO UPDATE SET
            translated_title=excluded.translated_title,
            translated_summary=excluded.translated_summary,
            translated_transcript=excluded.translated_transcript,
            model=excluded.model,
            created_at=excluded.created_at
        """,
        (
            meeting_id,
            payload.target_language,
            translated["title"],
            translated["summary"],
            translated["transcript"],
            OPENAI_TRANSLATION_MODEL,
            now,
        ),
    )
    conn.commit()
    conn.close()

    return {
        "meeting_id": meeting_id,
        "language": payload.target_language,
        **translated,
        "model": OPENAI_TRANSLATION_MODEL,
        "created_at": now,
        "cached": False,
    }


@app.post("/api/meetings/{meeting_id}/share")
def create_share(meeting_id: int, payload: ShareIn, user=Depends(require_user)):
    get_original_meeting(meeting_id)
    token = secrets.token_urlsafe(24)
    now = datetime.now(timezone.utc)
    expires_at = (
        (now + timedelta(hours=payload.expires_hours)).isoformat()
        if payload.expires_hours
        else None
    )
    conn = db()
    conn.execute(
        """
        INSERT INTO shares(token, meeting_id, expires_at, created_at)
        VALUES (?, ?, ?, ?)
        """,
        (token, meeting_id, expires_at, now.isoformat()),
    )
    conn.commit()
    conn.close()
    return {
        "token": token,
        "url": f"/share.html?token={token}",
        "expires_at": expires_at,
        "available_languages": ["ko"] + available_translation_languages(meeting_id),
        "login_required": True,
    }


def validate_share(token: str):
    conn = db()
    row = conn.execute(
        """
        SELECT s.meeting_id, s.expires_at
        FROM shares s
        WHERE s.token=?
        """,
        (token,),
    ).fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Share link not found")
    if row["expires_at"]:
        exp = datetime.fromisoformat(row["expires_at"])
        if exp < datetime.now(timezone.utc):
            raise HTTPException(status_code=410, detail="Share link expired")
    return dict(row)


@app.get("/api/share/{token}")
def read_share(token: str, lang: str = Query(default="ko", pattern="^(ko|en|ja)$"), user=Depends(require_user)):
    share = validate_share(token)
    meeting_id = share["meeting_id"]
    meeting = get_original_meeting(meeting_id)
    available = ["ko"] + available_translation_languages(meeting_id)
    result = {
        **meeting,
        "language": "ko",
        "available_languages": available,
        "expires_at": share["expires_at"],
    }

    if lang == "ko":
        return result

    translated = get_translation(meeting_id, lang)
    if not translated:
        raise HTTPException(status_code=404, detail="Requested translation is not available for this share link")

    return {
        **result,
        "title": translated["title"],
        "summary": translated["summary"],
        "transcript": translated["transcript"],
        "language": lang,
    }


app.mount("/", StaticFiles(directory=BASE_DIR / "static", html=True), name="static")
