# TTP-to-Query Autonomous Agent

An autonomous threat intelligence agent that monitors RSS feeds, extracts TTPs (Tactics, Techniques, and Procedures), maps them to MITRE ATT&CK, and generates actionable intelligence reports.

## Overview

This agent is designed to run autonomously via Claude Code CLI, processing threat intelligence feeds and producing structured analysis with minimal human intervention.

### Key Features

- **Autonomous RSS Monitoring**: Fetches and deduplicates threat intel from configured feeds
- **TTP Extraction & Mapping**: Automatically maps threats to MITRE ATT&CK framework
- **IOC Extraction**: Identifies and validates indicators of compromise
- **Self-Improvement**: Learns from session performance and patches its own skill files
- **Human Escalation**: Routes low-confidence items for human review
- **Crash Recovery**: Checkpoint-based recovery for interrupted sessions

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        AGENT.md                             │
│                   (Orchestrator Prompt)                     │
└─────────────────────┬───────────────────────────────────────┘
                      │ delegates to
        ┌─────────────┼─────────────┬─────────────┐
        ▼             ▼             ▼             ▼
┌───────────┐ ┌───────────────┐ ┌──────────┐ ┌─────────────────┐
│monitor-rss│→│analyze-threat │→│ generate │→│ perform-        │
│  SKILL    │ │    SKILL      │ │ -report  │ │ retrospective   │
└───────────┘ └───────┬───────┘ └──────────┘ └────────┬────────┘
                      │ delegates to                   │ edits
              ┌───────┴───────┐                       ▼
              ▼               ▼               ┌───────────────┐
        ┌──────────┐   ┌─────────────┐        │ Other SKILLs  │
        │file-     │   │malware-     │        │ (with backup) │
        │analyzer  │   │triage       │        └───────────────┘
        └──────────┘   └─────────────┘
```

## Installation

1. Ensure Claude Code CLI is installed and configured
2. Clone this repository
3. Configure feeds in `config/feeds.json`
4. Set up cron job for automated execution

### Cron Setup (Hourly Execution)

```bash
0 * * * * cd /path/to/ttp-agent && claude -p "Execute TTP Agent main loop" >> /var/log/ttp-agent.log 2>&1
```

## Directory Structure

```
ttp-agent/
├── AGENT.md                    # Master orchestrator prompt
├── README.md                   # This file
├── skills/
│   ├── monitor-rss/            # RSS feed monitoring
│   │   └── SKILL.md
│   ├── analyze-threat/         # TTP extraction & mapping
│   │   └── SKILL.md
│   ├── generate-report/        # Report generation
│   │   └── SKILL.md
│   ├── perform-retrospective/  # Self-improvement engine
│   │   └── SKILL.md
│   ├── malware-triage/         # Malware analysis (sub-skill)
│   │   └── SKILL.md
│   └── file-analyzer/          # Script analysis (sub-skill)
│       └── SKILL.md
├── memory/
│   └── active_context.md       # Current session state & checkpoints
├── config/
│   └── feeds.json              # RSS feed configuration
├── state/
│   ├── processed_log.json      # Deduplication history
│   ├── escalation_queue.json   # Items needing human review
│   ├── skill_edits.json        # Skill modification tracking
│   ├── session_history.json    # Performance metrics history
│   ├── patch_log.md            # Human-readable patch history
│   └── skip_list.json          # Items to ignore
├── logs/
│   └── {YYYY-MM-DD}.jsonl      # Daily log files
└── reports/
    ├── {guid}.md               # Generated reports
    └── manual/                 # Human-provided analyses
```

## Usage

### Manual Execution

```bash
cd /path/to/ttp-agent
claude -p "Execute TTP Agent main loop"
```

### Check Escalation Queue

Review items requiring human attention:

```bash
cat state/escalation_queue.json | jq '.items'
```

### View Recent Logs

```bash
tail -f logs/$(date +%Y-%m-%d).jsonl | jq '.'
```

### Review Skill Patches

```bash
cat state/patch_log.md
```

## Safety Features

### Trust Boundaries
- RSS content is treated as **untrusted** and sanitized before processing
- SKILL.md files are trusted and executed as instructions
- All external input is validated

### Self-Modification Guardrails
- Maximum 1 edit per skill per session
- Automatic backup before any edit
- Forbidden zones that cannot be modified
- Automatic rollback on performance degradation

### Human Escalation
- Items with confidence < 0.5 are escalated
- Clear documentation of escalation reasons
- Structured queue for human review

## Configuration

### feeds.json

Configure RSS feeds to monitor:

```json
{
  "feeds": [
    {
      "name": "feed-name",
      "url": "https://example.com/feed.xml",
      "priority": "high|medium|low",
      "category": "government|vendor|news|research"
    }
  ],
  "settings": {
    "poll_interval_minutes": 60,
    "max_items_per_feed": 20
  }
}
```

## Output Formats

### Threat Intelligence Reports

Reports include:
- Executive summary
- MITRE ATT&CK mappings with evidence
- Indicators of Compromise (IOCs)
- Detection signatures (YARA, Snort/Suricata, SIEM queries)
- ATT&CK Navigator layer (JSON)
- Recommendations

### Log Format (JSONL)

```json
{"ts": "ISO8601", "level": "info", "skill": "monitor-rss", "event": "feed_fetched", "data": {...}}
```

## Resource Limits

| Resource | Limit |
|----------|-------|
| Token budget | 50K per session |
| Time per item | 10 minutes |
| Session timeout | 60 minutes |

## Contributing

When modifying skill files:
1. Never edit sections marked `IMMUTABLE`
2. Test changes thoroughly before committing
3. Document changes in commit messages

## License

See LICENSE file in parent directory.
