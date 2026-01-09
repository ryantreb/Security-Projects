# Report Generation Skill

## Purpose
Transform structured threat analysis into human-readable markdown reports with actionable intelligence.

## Trigger
- Successful completion of analyze-threat skill
- Manual invocation for report regeneration

## Input Schema
```json
{
  "analysis": {
    // Full output from analyze-threat skill
  },
  "format": "full|summary|ioc-only",
  "output_path": "reports/{guid}.md"
}
```

## Output Schema
```json
{
  "report_path": "reports/{guid}.md",
  "report_format": "full|summary|ioc-only",
  "generated_at": "ISO8601",
  "word_count": 0,
  "sections_included": ["summary", "ttps", "iocs", "recommendations"]
}
```

---

## Execution Steps

### Step 1: Validate Input
```
1. VERIFY analysis object contains required fields:
   - guid, title, confidence, ttps, iocs
2. SET format = input.format OR "full"
3. SET output_path = input.output_path OR "reports/{guid}.md"
```

### Step 2: Generate Report Content
```
BASED ON format:
  - "full": Generate all sections
  - "summary": Generate summary + key findings only
  - "ioc-only": Generate IOC table only
```

### Step 3: Write Report File
```
1. CREATE file at output_path
2. WRITE formatted markdown content
3. LOG report generation event
```

### Step 4: Return Result
```
RETURN {
  "report_path": output_path,
  "report_format": format,
  "generated_at": NOW(),
  "word_count": calculated,
  "sections_included": [list of sections]
}
```

---

## Report Template (Full Format)

```markdown
# Threat Intelligence Report: {title}

**Report ID**: {guid}
**Generated**: {generated_at}
**Source**: {source}
**Original URL**: {raw_url}
**Confidence Score**: {confidence} ({confidence_level})

---

## Executive Summary

{1-2 paragraph summary of the threat, its significance, and recommended actions}

### Key Findings
- **Threat Actor**: {threat_actor.name or "Unattributed"} ({threat_actor.confidence} confidence)
- **Campaign**: {campaign.name or "Not part of known campaign"}
- **Primary Targets**: {campaign.targets joined}
- **TTPs Identified**: {ttps.length} techniques mapped to MITRE ATT&CK
- **IOCs Extracted**: {iocs.length} indicators

### Confidence Breakdown
| Factor | Score | Notes |
|--------|-------|-------|
| Source Reputation | {confidence_factors.source_reputation} | {source_notes} |
| Attack Specificity | {confidence_factors.attack_specificity} | {specificity_notes} |
| Temporal Relevance | {confidence_factors.temporal_relevance} | Published {days_ago} days ago |
| Corroboration | {confidence_factors.corroboration} | {corroboration_notes} |

---

## MITRE ATT&CK Mapping

### Attack Flow Diagram
```
{Generate ASCII diagram showing TTP sequence if >2 TTPs}
```

### Techniques Detail

{FOR EACH ttp in ttps:}

#### {ttp.technique_id}: {ttp.technique_name}

- **Tactic**: {ttp.tactic}
- **Confidence**: {ttp.confidence}
- **Reference**: [{ttp.technique_id}]({ttp.source_url})

**Evidence**:
> {ttp.evidence}

{END FOR}

### ATT&CK Navigator Layer

```json
{Generate ATT&CK Navigator JSON for easy import}
```

---

## Indicators of Compromise

### Summary Table

| Type | Value | Context |
|------|-------|---------|
{FOR EACH ioc in iocs:}
| {ioc.type} | `{ioc.value}` | {ioc.context} |
{END FOR}

### Detection Signatures

#### Network-Based Detection
```
{Generate Snort/Suricata rules for network IOCs}
```

#### Host-Based Detection
```
{Generate YARA rules for file hashes}
```

#### SIEM Queries
```
{Generate Splunk/Elastic queries for IOC hunting}
```

---

## Threat Actor Profile

{IF threat_actor.name:}

### {threat_actor.name}

- **Also Known As**: {threat_actor.aliases joined}
- **Attribution Confidence**: {threat_actor.confidence}
- **Known Targets**: {campaign.targets joined}

{Brief profile of threat actor if known}

{ELSE:}

Attribution has not been established for this threat activity.

{END IF}

---

## Recommendations

### Immediate Actions
1. {Prioritized list based on TTPs and IOCs}
2. Block identified IOCs at network perimeter
3. Search for IOCs in historical logs
4. {Additional recommendations based on specific TTPs}

### Detection Opportunities
{Based on TTPs, suggest detection strategies}

### Mitigation Strategies
{Based on TTPs, suggest mitigations from ATT&CK}

---

## Intelligence Gaps

The following questions remain unanswered:

{FOR EACH gap in gaps:}
- {gap}
{END FOR}

---

## Appendix

### Raw IOCs (Copy-Paste Ready)

#### Domains
```
{domains list, one per line, defanged}
```

#### IP Addresses
```
{ips list, one per line, defanged}
```

#### File Hashes
```
{hashes list, one per line}
```

#### URLs
```
{urls list, one per line, defanged}
```

### ATT&CK Navigator JSON
```json
{
  "name": "Report {guid}",
  "versions": {
    "attack": "14",
    "navigator": "4.9.1"
  },
  "domain": "enterprise-attack",
  "techniques": [
    {FOR EACH ttp in ttps:}
    {
      "techniqueID": "{ttp.technique_id}",
      "color": "{color based on confidence}",
      "comment": "{ttp.evidence truncated}"
    },
    {END FOR}
  ]
}
```

### References
- Original Source: {raw_url}
- MITRE ATT&CK: https://attack.mitre.org/
- {Additional references if available}

---

*Report generated by TTP-to-Query Agent*
*Confidence Level: {confidence_level_description}*
```

---

## Report Template (Summary Format)

```markdown
# Threat Summary: {title}

**ID**: {guid} | **Confidence**: {confidence} | **Source**: {source}

## Key Points
- {3-5 bullet point summary}

## Top TTPs
| Technique | Tactic | Confidence |
|-----------|--------|------------|
{Top 5 TTPs only}

## Critical IOCs
| Type | Value |
|------|-------|
{Top 10 IOCs by relevance}

## Recommended Actions
1. {Top 3 recommendations}

[Full Report](reports/{guid}.md)
```

---

## Report Template (IOC-Only Format)

```markdown
# IOC Export: {title}

**ID**: {guid} | **Generated**: {generated_at}

## Indicators of Compromise

{FOR EACH type in [domain, ip, hash_sha256, hash_sha1, hash_md5, url]:}

### {type}s
```
{values, one per line}
```

{END FOR}

## Machine-Readable Formats

### CSV
```csv
type,value,context
{CSV rows}
```

### STIX 2.1
```json
{STIX bundle}
```
```

---

## Confidence Level Descriptions

| Score Range | Level | Description |
|-------------|-------|-------------|
| 0.8 - 1.0 | High | Strong evidence from reputable sources; actionable with high certainty |
| 0.6 - 0.79 | Medium | Moderate evidence; actionable with reasonable certainty |
| 0.4 - 0.59 | Low | Limited evidence; requires additional verification |
| 0.0 - 0.39 | Very Low | Insufficient evidence; not recommended for action without review |

---

## Detection Signature Generation

### Snort/Suricata Rule Template
```
alert tcp $HOME_NET any -> $EXTERNAL_NET any (
  msg:"TTP-Agent: {threat_name} - {ioc_type}";
  content:"{ioc_value}";
  sid:{generated_sid};
  rev:1;
  classtype:trojan-activity;
  reference:url,{raw_url};
)
```

### YARA Rule Template
```yara
rule TTP_Agent_{guid_short} {
    meta:
        description = "{title}"
        reference = "{raw_url}"
        date = "{generated_at}"
        confidence = "{confidence}"

    strings:
        {FOR EACH hash in hashes:}
        $hash_{index} = "{hash.value}"
        {END FOR}

    condition:
        any of them
}
```

### Splunk Query Template
```spl
index=* (
  {FOR EACH ioc in network_iocs:}
  dest="{ioc.value}" OR src="{ioc.value}" OR
  {END FOR}
  {FOR EACH hash in hashes:}
  file_hash="{hash.value}" OR
  {END FOR}
)
| stats count by src, dest, file_hash
| where count > 0
```

---

## Error Handling

| Error | Action |
|-------|--------|
| Missing required fields | Generate partial report, note gaps |
| Output path not writable | Log error, return failure |
| Template rendering error | Fallback to minimal format |
| IOC defanging failure | Include warning in report |

---

## File Naming Convention

```
reports/
├── {guid}.md              # Full report
├── {guid}.summary.md      # Summary version
├── {guid}.iocs.md         # IOC-only export
├── {guid}.navigator.json  # ATT&CK Navigator layer
└── {guid}.stix.json       # STIX bundle (if generated)
```
