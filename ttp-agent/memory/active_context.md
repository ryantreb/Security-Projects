# Active Session Context

## Session Metadata
- **ID**: {pending initialization}
- **Started**: {pending initialization}
- **Phase**: uninitialized
- **Current Item**: null

---

## Checkpoint (for crash recovery)

```json
{
  "schema_version": "1.0",
  "session_id": null,
  "last_checkpoint": null,
  "phase": "uninitialized",
  "current_item_guid": null,
  "completed_guids": [],
  "pending_guids": [],
  "escalated_guids": []
}
```

---

## Working Memory

### Analysis Queue

| GUID | Source | Title | Status | Confidence | Report Path |
|------|--------|-------|--------|------------|-------------|
| — | — | — | — | — | — |

### Escalation Queue

| GUID | Title | Reason | Confidence |
|------|-------|--------|------------|
| — | — | — | — |

### Processing Stats

```json
{
  "items_queued": 0,
  "items_processed": 0,
  "items_successful": 0,
  "items_escalated": 0,
  "items_errored": 0,
  "ttps_mapped": 0,
  "iocs_extracted": 0
}
```

---

## Session Notes

*Session notes will be appended here during execution.*

---

## How This File Is Used

### On Session Start
1. Agent reads this file
2. If checkpoint exists with incomplete session: RESUME
3. If no checkpoint or completed session: INITIALIZE new session

### During Execution
1. Before each major step: UPDATE checkpoint
2. After completing items: UPDATE queue tables
3. On errors/warnings: APPEND to Session Notes

### On Session End
1. CLEAR checkpoint data
2. PRESERVE session notes for logging
3. RESET tables for next session

### Checkpoint Phases
- `uninitialized`: No active session
- `initializing`: Session startup
- `monitoring`: Fetching RSS feeds
- `analyzing`: Processing threat items
- `reporting`: Generating reports
- `retrospective`: Self-improvement phase
- `complete`: Session finished successfully
- `error`: Session terminated with error
