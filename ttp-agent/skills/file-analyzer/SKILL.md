# File Analyzer Skill

## Purpose
Analyze script artifacts (PowerShell, VBScript, JavaScript, Office macros) to extract behavioral patterns and map to TTPs.

## Trigger
- Delegated by analyze-threat skill when script indicators detected
- Keywords: "PowerShell", "script", "VBScript", "JavaScript", "macro", "VBA"
- Presence of code snippets or script file references

## Input Schema
```json
{
  "guid": "parent-analysis-guid",
  "artifact_type": "powershell|vbscript|javascript|vba|batch|python|other",
  "content": {
    "type": "snippet|hash|description",
    "value": "code snippet, hash, or textual description"
  },
  "context": "surrounding text describing the script",
  "source_url": "original article URL"
}
```

## Output Schema
```json
{
  "guid": "parent-analysis-guid",
  "artifact_type": "powershell|vbscript|javascript|vba|batch|python|other",
  "status": "analyzed|insufficient_data|error",
  "obfuscation_detected": true|false,
  "obfuscation_techniques": [
    {
      "technique": "base64|string_concat|char_codes|compression|encryption",
      "confidence": "high|medium|low",
      "example": "code sample showing technique"
    }
  ],
  "behavioral_indicators": [
    {
      "behavior": "description of observed behavior",
      "code_evidence": "relevant code snippet",
      "ttp_mapping": "T1xxx.xxx",
      "confidence": "high|medium|low"
    }
  ],
  "extracted_iocs": [
    {
      "type": "url|domain|ip|filepath|registry",
      "value": "extracted value",
      "context": "how it's used in the script"
    }
  ],
  "risk_assessment": {
    "level": "critical|high|medium|low|informational",
    "factors": ["list of risk factors"]
  },
  "deobfuscation_notes": "notes on deobfuscation if performed",
  "recommendations": ["detection/mitigation suggestions"]
}
```

---

## Execution Steps

### Step 1: Validate and Classify Input
```
1. DETERMINE artifact type if not specified:
   - PowerShell: Contains cmdlets, $variables, -Parameters
   - VBScript: Contains Dim, Sub, Function, WScript
   - JavaScript: Contains function, var/let/const, document
   - VBA: Contains Sub, Dim, ActiveDocument, Application
   - Batch: Contains @echo, set, %variables%
   - Python: Contains def, import, print()

2. IF content.type == "hash":
   - Query malware-triage skill for sample details
   - Return limited analysis based on available info

3. IF content.type == "description":
   - Extract behavioral patterns from description
   - Cannot perform code analysis
   - Set status = "insufficient_data" if no code available
```

### Step 2: Detect Obfuscation
```
OBFUSCATION PATTERNS BY TYPE:

PowerShell:
  - Base64: -enc, -EncodedCommand, [Convert]::FromBase64String
  - String concatenation: ('wo'+'rd'), -join, -split
  - Char codes: [char]0x41, [char]65
  - Compression: IO.Compression, GZipStream
  - Variable substitution: ${env:var}
  - Invoke-Expression variants: IEX, .Invoke()
  - Tick insertion: `I`n`v`o`k`e

VBScript/VBA:
  - Chr() concatenation: Chr(65) & Chr(66)
  - Execute/Eval: Execute(), Eval()
  - Replace chains: Replace(Replace(...))
  - Shell execution: WScript.Shell, Shell()

JavaScript:
  - eval(): eval(atob(...))
  - String.fromCharCode: String.fromCharCode(65,66)
  - unescape: unescape('%41%42')
  - document.write with encoded content
  - Function constructor: new Function(...)

FOR EACH detected technique:
  - Record technique name
  - Extract example showing pattern
  - Assess confidence based on clarity
```

### Step 3: Extract Behavioral Indicators
```
ANALYZE code for these behaviors:

EXECUTION / DOWNLOAD:
  - Invoke-WebRequest, wget, curl → T1105 Ingress Tool Transfer
  - DownloadString, DownloadFile → T1105
  - Start-Process, Invoke-Expression → T1059 Command Execution
  - WScript.Shell.Run → T1059.005 (VBS)
  - ActiveXObject → T1059.007 (JS)

PERSISTENCE:
  - Registry keys (HKCU\...\Run) → T1547.001 Registry Run Keys
  - Scheduled tasks (schtasks, New-ScheduledTask) → T1053.005
  - WMI subscriptions → T1546.003
  - Startup folder references → T1547.001

DEFENSE EVASION:
  - AMSI bypass patterns → T1562.001
  - ETW patching → T1562.001
  - Process hollowing setup → T1055.012
  - Disable-WindowsDefender → T1562.001

CREDENTIAL ACCESS:
  - Mimikatz invocation → T1003
  - SAM/SECURITY hive access → T1003.002
  - LSASS references → T1003.001
  - Browser credential paths → T1555.003

DISCOVERY:
  - Get-ADComputer, Get-ADUser → T1087 Account Discovery
  - Net user, net group → T1087.001
  - Systeminfo, hostname → T1082 System Info Discovery
  - Network enumeration → T1016

LATERAL MOVEMENT:
  - Enter-PSSession, Invoke-Command → T1021.006 (WinRM)
  - WMI remote execution → T1047
  - PsExec patterns → T1570

DATA COLLECTION/EXFIL:
  - Compress-Archive → T1560.001 Archive via Utility
  - File copy to network share → T1039
  - HTTP POST with data → T1041 Exfil over C2

FOR EACH identified behavior:
  - Quote relevant code
  - Map to specific TTP
  - Assess confidence based on context clarity
```

### Step 4: Extract IOCs from Code
```
PATTERNS TO EXTRACT:

URLs:
  - Regex: https?://[^\s'\"<>]+
  - PowerShell: strings in quotes after web cmdlets

Domains:
  - From URLs
  - In string variables

IP Addresses:
  - IPv4 pattern in strings
  - Often in download/connect contexts

File Paths:
  - Windows: C:\..., %APPDATA%\...
  - PowerShell: $env:...\...
  - Dropped file locations

Registry Keys:
  - HKLM:\..., HKCU:\...
  - Registry path strings

FOR EACH extracted IOC:
  - Validate format
  - Determine context (download, persist, c2)
  - Defang for output
```

### Step 5: Assess Risk Level
```
RISK FACTORS:

Critical indicators (+3 each):
  - Downloads and executes remote code
  - Disables security products
  - Credential theft patterns
  - Ransomware indicators (encryption loops)

High indicators (+2 each):
  - Establishes persistence
  - Process injection patterns
  - Obfuscation to evade detection
  - Lateral movement capability

Medium indicators (+1 each):
  - System/network discovery
  - Data collection
  - Encoded content
  - Suspicious file operations

Low indicators (+0.5 each):
  - Basic command execution
  - File system access
  - Network connectivity

CALCULATE total score:
  0-2: informational
  2-4: low
  4-6: medium
  6-8: high
  8+: critical
```

### Step 6: Generate Recommendations
```
BASED ON findings, suggest:

1. Detection rules:
   - YARA rule for unique strings
   - Sigma rule for behavior patterns
   - PowerShell ScriptBlock logging guidance

2. Blocking actions:
   - IOCs to block at perimeter
   - Registry paths to monitor
   - Process creation patterns

3. Hunting queries:
   - Specific strings to search
   - Command line patterns
   - File creation patterns
```

### Step 7: Return Results
```
COMPILE all findings into output schema
SET status:
  - "analyzed": Code analyzed successfully
  - "insufficient_data": Only description/hash available
  - "error": Analysis failed
```

---

## Script Analysis Patterns Reference

### PowerShell Red Flags

```powershell
# Download cradles
IEX (New-Object Net.WebClient).DownloadString('http://...')
IEX (IWR 'http://...').Content
$a = [System.Net.WebRequest]::Create('http://...')

# AMSI bypass indicators
[Ref].Assembly.GetType('...AmsiUtils...')
AmsiInitFailed
amsi.dll

# Encoded commands
-enc [base64]
-EncodedCommand
[System.Convert]::FromBase64String

# Credential access
Invoke-Mimikatz
Get-Credential | Out-File
[System.Net.NetworkCredential]
```

### VBA/VBScript Red Flags

```vb
' Shell execution
Shell("cmd.exe /c ...")
WScript.Shell.Run
CreateObject("WScript.Shell")

' Download
XMLHTTP, WinHttp.WinHttpRequest
URLDownloadToFile

' Persistence
RegWrite "HKCU\...\Run"

' Obfuscation
Chr(65) & Chr(66)
Execute(...)
```

### JavaScript Red Flags

```javascript
// Eval-based execution
eval(atob('...'))
eval(unescape('...'))
new Function(decoded)()

// ActiveX (IE/WSH)
new ActiveXObject("WScript.Shell")
new ActiveXObject("MSXML2.XMLHTTP")

// DOM manipulation for payload
document.write(decoded)
document.body.innerHTML = payload
```

---

## Error Handling

| Error | Action | Return Status |
|-------|--------|---------------|
| No code available | Analyze description only | insufficient_data |
| Unrecognized language | Best effort analysis | analyzed (with note) |
| Heavily obfuscated | Note layers, partial analysis | analyzed |
| Malformed input | Log error, skip | error |

---

## Limitations

1. **Static analysis only**: Does not execute code
2. **No deobfuscation runtime**: Cannot fully decode dynamic obfuscation
3. **Context dependent**: May miss behaviors without full context
4. **Language support**: Best for PowerShell/VBS/JS/VBA; limited for others
5. **Snippet limitations**: Partial code may lack critical context
