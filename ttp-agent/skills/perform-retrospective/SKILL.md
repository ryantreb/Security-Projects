# Retrospective & Self-Improvement Skill

## Purpose
Review session performance, identify systematic errors, and patch SKILL.md files to improve future performance.

## Trigger Conditions
- End of every session (mandatory)
- Mid-session if 3+ analyses have confidence < 0.6
- Manual invocation for diagnostics

---

## SAFETY GUARDRAILS (IMMUTABLE — DO NOT MODIFY THIS SECTION)

### Pre-Edit Protocol (REQUIRED)
1. **Backup**: `cp {skill}/SKILL.md {skill}/SKILL.md.bak.{YYYYMMDD-HHMMSS}`
2. **Scope Limit**: Maximum 1 edit per skill per session
3. **Diff Size Limit**: `old_str` must be <30 lines
4. **Syntax Validation**: After edit, verify SKILL.md contains required sections
5. **Immutability Check**: Verify edit does not touch forbidden zones

### Forbidden Zones (NEVER EDIT) — IMMUTABLE
- Any line containing the word `IMMUTABLE`
- Any section titled "SAFETY GUARDRAILS"
- Prime Directives in AGENT.md
- Trust Boundaries in AGENT.md
- INPUT SANITIZATION sections in any SKILL.md
- This Forbidden Zones list itself
- Any content between `<!-- LOCKED -->` and `<!-- /LOCKED -->` tags

### Rollback Protocol
1. Store edit metadata in `state/skill_edits.json`
2. If next session produces >50% more errors than previous session: auto-rollback
3. If next session confidence average drops >20%: auto-rollback
4. Rollback command: `cp {skill}/SKILL.md.bak.{latest} {skill}/SKILL.md`
5. Log rollback event with reason

### Edit Limits
- Maximum 3 edits across all skills per 24-hour period
- Minimum 2 sessions between edits to same skill
- No edits if session had <5 items processed (insufficient data)

---

## Execution Steps

### Step 1: Collect Session Metrics
```
1. READ all log entries for current session from logs/{date}.jsonl
2. AGGREGATE metrics:
   {
     "session_id": "uuid",
     "duration_seconds": 0,
     "items_processed": 0,
     "items_successful": 0,
     "items_escalated": 0,
     "items_errored": 0,
     "avg_confidence": 0.0,
     "confidence_distribution": {
       "high": 0,      // >= 0.8
       "medium": 0,    // 0.6 - 0.79
       "low": 0,       // 0.4 - 0.59
       "very_low": 0   // < 0.4
     },
     "ttp_mappings": 0,
     "ttp_mappings_high_conf": 0,
     "ttp_mappings_medium_conf": 0,
     "ttp_mappings_low_conf": 0,
     "iocs_extracted": 0,
     "delegations": {
       "malware-triage": {"invoked": 0, "succeeded": 0, "failed": 0},
       "file-analyzer": {"invoked": 0, "succeeded": 0, "failed": 0}
     },
     "feeds": {
       "healthy": 0,
       "unhealthy": 0,
       "errors": []
     },
     "errors": [],
     "warnings": []
   }
```

### Step 2: Load Historical Data
```
1. READ state/session_history.json (last 10 sessions)
2. IF not exists: CREATE empty history
3. CALCULATE trends:
   - avg_confidence_trend: improving | stable | declining
   - error_rate_trend: improving | stable | worsening
   - throughput_trend: improving | stable | declining
```

### Step 3: Identify Patterns (Diagnosis)
```
APPLY diagnosis rules in order:

RULE 1: Low TTP Mapping Rate
  IF ttp_mappings / items_processed < 2.0:
    SYMPTOM: "Low TTP mapping rate"
    LIKELY_CAUSE: "Mapping protocol too strict OR content quality issue"
    PATCH_TARGET: "analyze-threat > TTP Mapping Protocol"
    PATCH_TYPE: "relaxation"

RULE 2: Consistently Low Corroboration
  IF avg(confidence_factors.corroboration) < 0.5 across >50% items:
    SYMPTOM: "Low corroboration scores"
    LIKELY_CAUSE: "Not fetching full articles OR single-source content"
    PATCH_TARGET: "monitor-rss > add note about source diversity"
    PATCH_TYPE: "documentation"

RULE 3: Feed Health Issues
  IF feeds.unhealthy > 0:
    SYMPTOM: "Unhealthy feeds detected"
    LIKELY_CAUSE: "Feed URL changed OR site blocking"
    PATCH_TARGET: "config/feeds.json"
    PATCH_TYPE: "config_update"
    NOTE: "Requires human review - not auto-patchable"

RULE 4: High Escalation Rate
  IF items_escalated / items_processed > 0.3:
    SYMPTOM: "High escalation rate (>30%)"
    LIKELY_CAUSE: "Confidence thresholds too aggressive OR poor source quality"
    PATCH_TARGET: "analyze-threat > Confidence Calculation"
    PATCH_TYPE: "threshold_adjustment"

RULE 5: Confidence Clustering
  IF std_dev(confidence scores) < 0.1:
    SYMPTOM: "Confidence scores clustered (low variance)"
    LIKELY_CAUSE: "Scoring weights miscalibrated"
    PATCH_TARGET: "analyze-threat > Confidence Calculation"
    PATCH_TYPE: "weight_adjustment"

RULE 6: Sub-skill Failures
  IF any delegation.failed / delegation.invoked > 0.2:
    SYMPTOM: "Sub-skill failure rate >20%"
    LIKELY_CAUSE: "Sub-skill error handling OR input validation"
    PATCH_TARGET: "{sub-skill} > Error Handling"
    PATCH_TYPE: "error_handling"

RULE 7: Parse Errors
  IF errors contains multiple "parse" errors from same feed:
    SYMPTOM: "Repeated parse errors"
    LIKELY_CAUSE: "Feed format changed"
    PATCH_TARGET: "monitor-rss > Error Handling"
    PATCH_TYPE: "parser_update"
    NOTE: "May require human review"
```

### Step 4: Evaluate Patch Candidates
```
FOR EACH identified pattern:
  1. CHECK if pattern occurred in >= 3 recent sessions (avoid one-off fixes)
  2. CHECK if target skill was edited in last 2 sessions (cooldown)
  3. CHECK if 24-hour edit limit reached
  4. CHECK if target contains forbidden zones

  IF all checks pass:
    ADD to patch_candidates list with:
    - priority (based on impact)
    - confidence (based on pattern strength)
    - risk (based on edit scope)
```

### Step 5: Generate Patch (If Approved)
```
IF patch_candidates not empty AND highest_priority.confidence > 0.7:

  1. SELECT highest priority candidate

  2. IDENTIFY exact old_str:
     - Must be unique in target file
     - Must be <30 lines
     - Must not contain forbidden patterns

  3. GENERATE new_str:
     - Minimal change to address issue
     - Preserve formatting and structure
     - Add comment noting this was auto-patched

  4. VALIDATE:
     - old_str exists exactly once in file
     - new_str is syntactically valid
     - No forbidden zones affected
```

### Step 6: Apply Patch (With Safety)
```
1. CREATE backup:
   cp skills/{skill}/SKILL.md skills/{skill}/SKILL.md.bak.{timestamp}

2. RECORD in state/skill_edits.json:
   {
     "timestamp": "ISO8601",
     "session_id": "uuid",
     "skill": "skill-name",
     "section": "section-name",
     "old_str_hash": "sha256",
     "new_str_hash": "sha256",
     "rationale": "explanation",
     "backup_path": "path/to/backup",
     "metrics_before": {...},
     "rollback_threshold": {
       "error_increase": 0.5,
       "confidence_decrease": 0.2
     }
   }

3. APPLY edit using str_replace tool:
   Path: skills/{skill}/SKILL.md
   old_str: {exact text to replace}
   new_str: {replacement text}

4. VALIDATE post-edit:
   - File parses correctly
   - Required sections present
   - No forbidden zone violations

5. IF validation fails:
   - ROLLBACK immediately
   - LOG error
   - SKIP to next candidate or exit
```

### Step 7: Document in Patch Log
```
APPEND to state/patch_log.md:

## {timestamp}

- **Session**: {session_id}
- **Skill**: {skill}
- **Section**: {section}
- **Symptom**: {symptom description}
- **Diagnosis**: {likely cause}
- **Change**:
  ```diff
  - {old_str summary}
  + {new_str summary}
  ```
- **Rationale**: {detailed explanation}
- **Rollback Trigger**: Error increase >50% OR confidence decrease >20%
- **Backup**: {backup_path}
```

### Step 8: Update Session History
```
1. APPEND current session metrics to state/session_history.json
2. TRIM to last 10 sessions
3. CALCULATE rolling averages for trend detection
```

### Step 9: Check for Auto-Rollback
```
IF previous session had a patch applied:
  1. COMPARE current metrics to pre-patch metrics
  2. IF error_rate increased >50%:
     - EXECUTE rollback
     - LOG rollback with reason
     - ADD to lessons_learned
  3. IF avg_confidence decreased >20%:
     - EXECUTE rollback
     - LOG rollback with reason
     - ADD to lessons_learned
```

### Step 10: Generate Retrospective Report
```
OUTPUT to console and logs:

=== Session Retrospective ===

Metrics:
- Items Processed: {count}
- Average Confidence: {avg} ({trend})
- Escalation Rate: {rate}%
- TTP Mapping Rate: {rate} per item

Patterns Detected:
{FOR EACH pattern:}
- {symptom}: {likely_cause}
{END FOR}

Actions Taken:
{IF patch applied:}
- Patched {skill}/{section}: {rationale_summary}
{ELSE:}
- No patches applied (insufficient evidence / cooldown / limit reached)
{END IF}

{IF rollback occurred:}
- ROLLED BACK previous patch to {skill}: {reason}
{END IF}

Recommendations:
{List of suggested improvements requiring human review}

=============================
```

---

## What NOT to Patch (Decision Rules)

### Never Auto-Patch
1. **One-off errors**: Wait for pattern across 3+ sessions
2. **Input data issues**: Fix sanitization, not analysis logic
3. **External failures**: Network issues, API outages
4. **Forbidden zones**: Any IMMUTABLE sections
5. **Complex logic**: Changes requiring multi-section edits
6. **New features**: Only fix existing logic, don't add

### Requires Human Review
1. Feed configuration changes
2. Trust boundary modifications
3. Confidence threshold changes >0.1
4. Addition/removal of TTP mappings
5. Changes to sanitization rules

---

## State File Schemas

### `state/skill_edits.json`
```json
{
  "schema_version": "1.0",
  "edits": [
    {
      "id": "uuid",
      "timestamp": "ISO8601",
      "session_id": "uuid",
      "skill": "analyze-threat",
      "section": "Confidence Calculation",
      "file_path": "skills/analyze-threat/SKILL.md",
      "old_str_hash": "sha256",
      "new_str_hash": "sha256",
      "old_str_preview": "first 100 chars...",
      "new_str_preview": "first 100 chars...",
      "rationale": "Technique-level mappings were undervalued",
      "backup_path": "skills/analyze-threat/SKILL.md.bak.20250106-143000",
      "metrics_before": {
        "avg_confidence": 0.65,
        "error_rate": 0.05
      },
      "status": "active|rolled_back",
      "rollback_info": null
    }
  ],
  "daily_edit_count": {
    "2025-01-06": 1
  }
}
```

### `state/session_history.json`
```json
{
  "schema_version": "1.0",
  "sessions": [
    {
      "session_id": "uuid",
      "timestamp": "ISO8601",
      "duration_seconds": 300,
      "items_processed": 10,
      "avg_confidence": 0.72,
      "escalation_rate": 0.1,
      "error_rate": 0.0,
      "ttp_mapping_rate": 3.4,
      "patches_applied": 0,
      "rollbacks": 0
    }
  ]
}
```

### `state/patch_log.md`
Human-readable log of all patches (see Step 7 format).

---

## Example Patch Scenarios

### Scenario 1: Adjusting Confidence Weight
```
SYMPTOM: Technique-level mappings consistently produce confidence ~0.7
DIAGNOSIS: attack_specificity weight of 0.7 for techniques is too low
PATTERN: Observed in 5 consecutive sessions, 80% of valid analyses

PATCH:
  File: skills/analyze-threat/SKILL.md
  Section: Attack Specificity Score

  old_str: |
    0.7 - Technique level:
        - T1566 (Phishing)

  new_str: |
    0.8 - Technique level (adjusted from 0.7):
        - T1566 (Phishing)
        Note: Technique-level often provides sufficient actionable intel
```

### Scenario 2: Adding TTP Mapping Hint
```
SYMPTOM: "credential harvesting" frequently not mapped
DIAGNOSIS: Missing keyword in TTP Mapping Reference
PATTERN: Missed in 8 items across 4 sessions

PATCH:
  File: skills/analyze-threat/SKILL.md
  Section: Common Mappings (Quick Reference)

  old_str: |
    | "credential dumping" | T1003 OS Credential Dumping | medium |

  new_str: |
    | "credential dumping" | T1003 OS Credential Dumping | medium |
    | "credential harvesting" | T1003 OS Credential Dumping | medium |
```

---

## Metrics Thresholds Reference

| Metric | Healthy | Warning | Critical |
|--------|---------|---------|----------|
| avg_confidence | >0.7 | 0.5-0.7 | <0.5 |
| escalation_rate | <0.1 | 0.1-0.3 | >0.3 |
| error_rate | <0.05 | 0.05-0.15 | >0.15 |
| ttp_mapping_rate | >2.0 | 1.0-2.0 | <1.0 |
| feed_health | 100% | 80-99% | <80% |
