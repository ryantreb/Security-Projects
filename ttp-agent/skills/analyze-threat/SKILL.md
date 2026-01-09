# Threat Analysis Skill

## Purpose
Extract TTPs from threat intelligence items, map to MITRE ATT&CK framework, identify IOCs, and delegate specialized analysis to sub-skills.

## Trigger
- New RSS item from monitor-rss skill
- Manual invocation for re-analysis

## Input Schema
```json
{
  "guid": "string",
  "source": "string",
  "title": "string",
  "url": "string",
  "published": "ISO8601",
  "raw_description": "string"
}
```

## Output Schema
```json
{
  "guid": "string",
  "source": "string",
  "title": "string",
  "analyzed_at": "ISO8601",
  "confidence": 0.0-1.0,
  "confidence_factors": {
    "source_reputation": 0.0-1.0,
    "attack_specificity": 0.0-1.0,
    "temporal_relevance": 0.0-1.0,
    "corroboration": 0.0-1.0
  },
  "threat_actor": {
    "name": "string or null",
    "confidence": "high|medium|low|unknown",
    "aliases": []
  },
  "campaign": {
    "name": "string or null",
    "first_seen": "ISO8601 or null",
    "targets": []
  },
  "ttps": [
    {
      "technique_id": "T1566.001",
      "technique_name": "Spearphishing Attachment",
      "tactic": "Initial Access",
      "confidence": "high|medium|low",
      "evidence": "quoted text supporting mapping",
      "source_url": "https://attack.mitre.org/techniques/T1566/001/"
    }
  ],
  "iocs": [
    {
      "type": "domain|ip|ipv6|hash_md5|hash_sha1|hash_sha256|url|email|filepath",
      "value": "...",
      "context": "Description of where/how IOC was found",
      "defanged": true
    }
  ],
  "delegated_analyses": [
    {
      "skill": "malware-triage",
      "input": "hash or identifier",
      "status": "completed|failed|skipped",
      "result_summary": "..."
    }
  ],
  "gaps": ["list of unanswered questions"],
  "raw_url": "original article URL for reference"
}
```

---

## Execution Steps

### Step 1: Fetch Full Content (If Needed)
```
1. IF raw_description < 500 characters:
   a. FETCH full article from input.url using web_fetch
   b. EXTRACT main content (strip navigation, ads, etc.)
   c. SANITIZE using same rules as monitor-rss
   d. SET full_content = fetched content
2. ELSE:
   SET full_content = raw_description
```

### Step 2: Extract Threat Actor / Campaign Info
```
1. SEARCH for named threat actors:
   - Known APT groups (APT28, Lazarus, etc.)
   - Named campaigns (SolarWinds, Log4Shell, etc.)
   - Country attributions (with LOW confidence)

2. IF found:
   a. SET threat_actor.name = extracted name
   b. SET threat_actor.confidence based on:
      - Direct attribution by security vendor: "high"
      - Indirect attribution (TTPs match known actor): "medium"
      - Speculative attribution: "low"
   c. EXTRACT aliases if mentioned
```

### Step 3: Extract IOCs
```
1. APPLY regex patterns for each IOC type:

   DOMAIN:
   - Pattern: [a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}
   - Exclude: common non-threat domains (google.com, microsoft.com, etc.)

   IP (v4):
   - Pattern: \b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b
   - Exclude: private ranges (10.x, 192.168.x, 172.16-31.x), localhost

   IP (v6):
   - Pattern: standard IPv6 regex
   - Exclude: link-local, loopback

   HASH (MD5):
   - Pattern: \b[a-fA-F0-9]{32}\b

   HASH (SHA1):
   - Pattern: \b[a-fA-F0-9]{40}\b

   HASH (SHA256):
   - Pattern: \b[a-fA-F0-9]{64}\b

   URL:
   - Pattern: https?://[^\s<>"{}|\\^`\[\]]+
   - Validate URL structure

   EMAIL:
   - Pattern: [a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}

   FILEPATH:
   - Pattern: (?:[A-Za-z]:\\|/)[^\s<>"{}|\\^`\[\]]+

2. FOR EACH extracted IOC:
   a. DEFANG for safety (replace . with [.], http with hxxp)
   b. EXTRACT surrounding context (20 chars before/after)
   c. ADD to iocs list with type and context
```

### Step 4: Map to MITRE ATT&CK TTPs
```
1. EXTRACT action verbs and objects from content:
   - "downloaded malware" → Download (T1105)
   - "phishing email with attachment" → Spearphishing Attachment (T1566.001)
   - "exploited vulnerability" → Exploitation (varies)
   - "lateral movement via RDP" → Remote Desktop Protocol (T1021.001)
   - "exfiltrated data via DNS" → Exfiltration Over DNS (T1048.003)

2. FOR EACH potential TTP:
   a. IDENTIFY most specific level:
      - Sub-technique (T1566.001) - preferred
      - Technique (T1566) - acceptable
      - Tactic only (Initial Access) - last resort

   b. REQUIRE explicit evidence:
      - QUOTE exact text that supports mapping
      - IF no supporting text: DO NOT map (avoid fabrication)

   c. SET confidence level:
      - "high": Explicit description matching technique
      - "medium": Implied by context
      - "low": Uncertain, could be multiple techniques

3. VALIDATE mappings:
   - Cross-reference with ATT&CK definitions
   - Ensure tactic matches technique
   - Remove duplicate mappings
```

### Step 5: Delegate to Sub-Skills
```
1. CHECK for malware indicators:
   IF any hash_sha256, hash_sha1, hash_md5 found:
     OR keywords: "malware", "payload", "trojan", "ransomware", "backdoor"
     DELEGATE to malware-triage skill

2. CHECK for script artifacts:
   IF keywords: "PowerShell", "script", "VBScript", "JavaScript", "macro"
     AND specific code snippets or hashes found:
     DELEGATE to file-analyzer skill

3. RECORD delegation results in delegated_analyses array
```

### Step 6: Identify Gaps
```
1. LIST unanswered questions:
   - "Initial access vector unknown"
   - "Malware family not identified"
   - "Affected systems/versions not specified"
   - "Remediation steps not provided"
   - "Attribution uncertain"

2. ADD to gaps array for potential follow-up
```

### Step 7: Calculate Confidence Score
```
confidence = (
  0.30 × source_reputation_score +
  0.30 × attack_specificity_score +
  0.20 × temporal_score +
  0.20 × corroboration_score
)
```

### Step 8: Return Analysis Result
```
RETURN complete output schema with all extracted data
```

---

## Confidence Calculation Details

### Source Reputation Score (0.30 weight)
```
Score based on information source:

1.0 - Government/Official sources:
    - CISA, US-CERT, NCSC, CERT-EU
    - Vendor security advisories (Microsoft, Cisco, etc.)

0.8 - Major security vendors:
    - Mandiant, CrowdStrike, Recorded Future
    - Kaspersky, ESET, Symantec, Palo Alto
    - Cisco Talos, Microsoft Security

0.6 - Reputable security news:
    - BleepingComputer, The Hacker News
    - Krebs on Security, Dark Reading
    - Security Week, Threatpost

0.4 - Community/research sources:
    - Individual security researchers
    - GitHub security advisories
    - Conference presentations

0.2 - Unknown/unverified sources:
    - Unrecognized blogs
    - Social media posts
    - Anonymous sources
```

### Attack Specificity Score (0.30 weight)
```
Score based on TTP mapping granularity:

1.0 - Sub-technique level:
    - T1566.001 (Spearphishing Attachment)
    - T1059.001 (PowerShell)

0.8 - Technique level (adjusted from 0.7):
    - T1566 (Phishing)
    - T1059 (Command and Scripting Interpreter)
    Note: Technique-level often provides sufficient actionable intel

0.5 - Tactic level only:
    - Initial Access, Execution, Persistence
    - Limited actionable value

0.0 - No mapping possible:
    - Generic threat mention
    - No technical details
```

### Temporal Relevance Score (0.20 weight)
```
Score based on publication age:

1.0 - Published within 7 days
0.8 - Published 7-14 days ago
0.6 - Published 14-30 days ago
0.4 - Published 30-90 days ago
0.2 - Published >90 days ago

Note: Even old items may be relevant for:
- Historical analysis
- Pattern correlation
- Technique documentation
```

### Corroboration Score (0.20 weight)
```
Score based on source verification:

1.0 - Confirmed by 2+ independent sources:
    - Multiple vendors report same threat
    - Official advisory + vendor report

0.7 - Single high-reputation source:
    - Government advisory
    - Major vendor report

0.5 - Single source, medium reputation:
    - Security news site
    - Known researcher

0.3 - Single source, unknown reputation:
    - New/unknown blog
    - Unverified claim
```

---

## Sub-Skill Delegation Matrix

| Artifact Type | Detection Pattern | Delegated Skill | Input |
|---------------|-------------------|-----------------|-------|
| PE/EXE/DLL | File hash + keywords: malware, payload, trojan | malware-triage | Hash value |
| Script | PowerShell, VBScript, JS, macro mentions | file-analyzer | Code snippet or reference |
| Document | Office macros, PDF exploits | file-analyzer | Hash or description |
| Network traffic | PCAP, packet capture mentions | (inline analysis) | Description |
| None detected | No specific artifacts | (skip delegation) | N/A |

---

## TTP Mapping Reference

### Common Mappings (Quick Reference)

| Keyword/Phrase | Likely TTP | Confidence |
|----------------|------------|------------|
| "phishing email" | T1566 Phishing | high |
| "malicious attachment" | T1566.001 Spearphishing Attachment | high |
| "malicious link" | T1566.002 Spearphishing Link | high |
| "exploited CVE-*" | T1190 Exploit Public-Facing App | high |
| "downloaded payload" | T1105 Ingress Tool Transfer | high |
| "PowerShell command" | T1059.001 PowerShell | high |
| "scheduled task" | T1053.005 Scheduled Task | high |
| "registry persistence" | T1547.001 Registry Run Keys | high |
| "credential dumping" | T1003 OS Credential Dumping | medium |
| "lateral movement" | TA0008 Lateral Movement (tactic) | low |
| "data exfiltration" | TA0010 Exfiltration (tactic) | low |
| "ransomware" | T1486 Data Encrypted for Impact | medium |
| "C2 communication" | T1071 Application Layer Protocol | medium |

### ATT&CK Reference URLs
- Techniques: https://attack.mitre.org/techniques/{ID}/
- Tactics: https://attack.mitre.org/tactics/{ID}/
- Groups: https://attack.mitre.org/groups/
- Software: https://attack.mitre.org/software/

---

## Error Handling

| Error | Action | Impact on Confidence |
|-------|--------|---------------------|
| Full article fetch failed | Use raw_description only | -0.1 to corroboration |
| No TTPs mappable | Set attack_specificity = 0 | May trigger escalation |
| Sub-skill timeout | Log, continue without | Note in gaps |
| Invalid IOC format | Skip invalid, log | None |
| ATT&CK lookup failed | Use cached mappings | None |

---

## Output Example

```json
{
  "guid": "abc123def456",
  "source": "us-cert",
  "title": "AA24-001A: Russian State-Sponsored Actors Target Critical Infrastructure",
  "analyzed_at": "2025-01-06T14:30:00Z",
  "confidence": 0.87,
  "confidence_factors": {
    "source_reputation": 1.0,
    "attack_specificity": 0.8,
    "temporal_relevance": 1.0,
    "corroboration": 0.7
  },
  "threat_actor": {
    "name": "APT29",
    "confidence": "high",
    "aliases": ["Cozy Bear", "The Dukes"]
  },
  "campaign": {
    "name": null,
    "first_seen": null,
    "targets": ["Critical Infrastructure", "Government"]
  },
  "ttps": [
    {
      "technique_id": "T1566.001",
      "technique_name": "Spearphishing Attachment",
      "tactic": "Initial Access",
      "confidence": "high",
      "evidence": "actors sent phishing emails with malicious Word documents",
      "source_url": "https://attack.mitre.org/techniques/T1566/001/"
    },
    {
      "technique_id": "T1059.001",
      "technique_name": "PowerShell",
      "tactic": "Execution",
      "confidence": "high",
      "evidence": "macro executed PowerShell commands to download second-stage payload",
      "source_url": "https://attack.mitre.org/techniques/T1059/001/"
    }
  ],
  "iocs": [
    {
      "type": "domain",
      "value": "malicious[.]example[.]com",
      "context": "C2 server contacted by malware",
      "defanged": true
    },
    {
      "type": "hash_sha256",
      "value": "a1b2c3d4e5f6...",
      "context": "Malicious Word document hash",
      "defanged": false
    }
  ],
  "delegated_analyses": [
    {
      "skill": "malware-triage",
      "input": "a1b2c3d4e5f6...",
      "status": "completed",
      "result_summary": "Identified as SUNBURST variant"
    }
  ],
  "gaps": [
    "Specific CVE exploited not identified",
    "Full list of targeted organizations unknown"
  ],
  "raw_url": "https://www.cisa.gov/news-events/alerts/aa24-001a"
}
```
