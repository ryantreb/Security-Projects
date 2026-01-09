# Skill Patch Log

This file records all automatic modifications made to SKILL.md files by the perform-retrospective skill.

---

## Format

Each patch entry follows this format:

```
## {YYYY-MM-DDTHH:MM:SSZ}

- **Session**: {session_id}
- **Skill**: {skill-name}
- **Section**: {section-name}
- **Symptom**: {what was observed}
- **Diagnosis**: {likely cause}
- **Change**:
  ```diff
  - {removed lines}
  + {added lines}
  ```
- **Rationale**: {why this change was made}
- **Rollback Trigger**: {conditions that would trigger rollback}
- **Backup**: {path to backup file}
- **Status**: active | rolled_back
```

---

## Patch History

*No patches applied yet.*
