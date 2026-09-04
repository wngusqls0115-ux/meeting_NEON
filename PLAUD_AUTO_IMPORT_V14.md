# PLAUD Auto Import V14

## Scope
Additive backend-only integration for `meeting_NEON`. No UI, folder, F/U, auth, translation, or Render/Neon connection behavior is changed.

## Endpoint
`POST /api/plaud/webhook`

Required Render environment variable: `PLAUD_WEBHOOK_SECRET` (must not be empty or `change-me`).

Header: `X-Webhook-Secret: <same secret>`

Zapier JSON mapping:
- `title` <- PLAUD `Title`
- `transcript` <- PLAUD `Transcript`
- `summary` <- PLAUD `Summary`
- `create_time` <- PLAUD `Create Time`
- `external_id` <- PLAUD file/recording ID if Zapier exposes one (optional)

If no explicit ID is exposed, duplicate identity falls back to SHA-256 of `PLAUD + Create Time + Title`.

## Duplicate behavior
- First delivery: creates one meeting with source `plaud-zapier`.
- Zapier retry / same recording: does not create another meeting.
- PLAUD re-transcription/re-summary: automatically refreshes the same meeting only while that meeting has not been manually edited.
- After a user manually edits the meeting, later duplicate deliveries preserve the user's content.

## Schema change
Two nullable columns are added to `meetings`:
- `source_external_id TEXT`
- `source_synced_at TEXT`

A partial unique index is added on `(source, source_external_id)` when `source_external_id` is not null. Existing rows are untouched.
