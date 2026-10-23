# Investigation: LSASS Credential Dumping (PROCESS_ALL_ACCESS)

> **Simulation note:** as with the PowerShell execution and scheduled task cases, this technique was run **manually, as Administrator, directly on the Win10 Target** — not delivered remotely from Kali. The script simulates the memory-access pattern used by credential-dumping tools such as Mimikatz; it does not actually extract or dump credential material, only obtains a process handle to `lsass.exe`.

| Field | Value |
|-------|-------|
| ID | INV-004 |
| Severity | High (full-access handle to LSASS successfully obtained) |
| Status | Closed |
| Analyst | AlertCheck |
| Detection | [detections/lsass-credential-dumping.xml](../detections/lsass-credential-dumping.xml) |
| Triggered rules | 100004 (custom); built-in rule 92900 did **not** fire — see Section 6 |

## 1. Summary

On the Win10 Target, a PowerShell script run as Administrator used `OpenProcess` (via P/Invoke) to request `PROCESS_ALL_ACCESS` (`0x1FFFFF`) to `lsass.exe` — the access level commonly requested by credential-dumping tools. The call **succeeded**, returning a valid process handle.

Reaching this outcome required two lab configuration changes beyond the default install: Sysmon's `ProcessAccess` include filter had to be extended to explicitly log access to `lsass.exe` (the stock SwiftOnSecurity config does not log it by default), and LSA Protection (`RunAsPPL`) had to be disabled on the target, since Protected Process Light would otherwise block a full-access handle from being granted.

Wazuh's built-in rule **92900** did not fire on this access, since it only matches a fixed set of access masks that does not include `0x1FFFFF`. While investigating why, a query for `rule.id:92900` surfaced an unrelated false positive from `svchost.exe` requesting `0x101000` access to `lsass.exe` — a legitimate system access pattern, not an attack. This confirmed both that the built-in rule missed this technique and that it wasn't a clean signal on its own in this environment.

Custom rule **100004** was built to match the specific `PROCESS_ALL_ACCESS` mask (`0x1FFFFF`) against `lsass.exe`, with a negated exclusion for processes already observed to be noisy (`MsMpEng.exe`, `wmiprvse.exe`, `svchost.exe`). Re-running the script after deploying the rule, rule 100004 fired correctly.

**Verdict:** credential-access technique (LSASS memory access with full rights) successfully simulated and detected. The built-in Wazuh rule for this technique class was confirmed both to miss the specific access mask used here and to produce false positives of its own, making the custom rule necessary rather than optional polish.

## 2. Timeline

| Time | Source | Event |
|------|--------|-------|
| 2026-10-23 22:07:49 (local) / 19:07:49.817 UTC | Target | Initial attack run (before rule 100004 existed): PowerShell script obtains handle to `lsass.exe`; Sysmon logs Event ID 10 locally |
| 2026-10-23 ~21:35 (Dashboard time) / 18:27:44.488 UTC (event field) | Wazuh | Query `rule.id:92900` during investigation surfaces an unrelated false positive from `svchost.exe` (0x101000 access to `lsass.exe`) |
| — | Analyst | Custom rule 100004 written and deployed to `/var/ossec/etc/rules/local_rules.xml`; `wazuh-manager` restarted |
| 2026-10-23 22:41:21.175 (Dashboard time) / 19:41:20.465 UTC (event field) | Target / Wazuh | Attack script re-run; Sysmon Event 10 (`GrantedAccess: 0x1fffff`, `SourceImage: powershell.exe`) matches rule 100004, which fires (level 12) |

> Note: as in the RDP brute-force case, there is a small gap between each event's displayed Dashboard time and its own `utcTime` field (a few minutes, consistent with ingestion lag rather than a real clock skew here). The lab-wide NTP sync recommended after the RDP case (see that investigation's Recommendations) has not yet been applied — worth prioritizing before the next scenario so timelines don't need this caveat each time.

## 3. TTP (MITRE ATT&CK)

| Tactic | Technique | ID | Observed as |
|--------|-----------|----|-------------|
| Credential Access | OS Credential Dumping: LSASS Memory | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | `OpenProcess(PROCESS_ALL_ACCESS, ...)` against `lsass.exe`, logged as Sysmon Event 10 |

No actual credential material was extracted in this test — only a process handle was obtained — so this case demonstrates the access-request stage of the technique, not a completed dump.

## 4. Evidence

### 4.1 Infrastructure changes required before the technique would succeed

```xml
<!-- Added to the ProcessAccess include filter in sysmonconfig-export.xml -->
<TargetImage condition="is">C:\Windows\system32\lsass.exe</TargetImage>
```

```powershell
sysmon64.exe -c sysmonconfig-export.xml
```

```
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 0 /f
```
(target rebooted to apply)

### 4.2 Simulated attack script (executed manually, as Administrator, on the target)

```powershell
$sig = @'
[DllImport("kernel32.dll", SetLastError = true)]
public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);
'@
$k32 = Add-Type -MemberDefinition $sig -Name 'K32' -Namespace 'W32' -PassThru
$lsassId = (Get-Process lsass).Id
$h = $k32::OpenProcess(0x1FFFFF, $false, $lsassId)
Write-Host "Handle: $h"
```

Output: `Handle: 1404` — access was granted.

### 4.3 Sysmon Event 10 (ProcessAccess) detail

| Field | Value |
|-------|-------|
| UtcTime | 2026-10-23 19:07:49.817 |
| SourceImage | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| SourceUser | `DESKTOP-478GG5N\Target-host` |
| TargetImage | `C:\Windows\system32\lsass.exe` |
| TargetUser | `NT AUTHORITY\СИСТЕМА` (SYSTEM) |
| GrantedAccess | `0x1fffff` |
| CallTrace | `C:\Windows\SYSTEM32\ntdll.dll+9d4a4\|C:\Windows\System32\KERNELBASE.dll+308ee\|UNKNOWN(00007FFC89818438)` |

### 4.4 Built-in rule 92900 — false positive observed during investigation

```text
rule.id: 92900
```

```json
"data": {
  "win": {
    "eventdata": {
      "sourceImage": "C:\\Windows\\system32\\svchost.exe",
      "targetImage": "C:\\Windows\\system32\\lsass.exe",
      "grantedAccess": "0x101000",
      "sourceUser": "NT AUTHORITY\\СИСТЕМА"
    }
  }
}
```

A legitimate system process requesting a much narrower access mask than `PROCESS_ALL_ACCESS` — confirms rule 92900 alone is not a reliable signal for this technique in this environment.

### 4.5 Custom rule as deployed

```bash
sudo cat /var/ossec/etc/rules/local_rules.xml | grep -A 12 'id="100004"'
```

```xml
<rule id="100004" level="12">
  <if_group>sysmon_event_10</if_group>
  <field name="win.eventdata.targetImage" type="pcre2">(?i)lsass\.exe</field>
  <field name="win.eventdata.grantedAccess" type="pcre2">(?i)0x1[fF]{5}</field>
  <field name="win.eventdata.sourceImage" type="pcre2" negate="yes">(?i)(MsMpEng\.exe|wmiprvse\.exe|svchost\.exe)</field>
  <description>Custom: LSASS Credential Dumping - PROCESS_ALL_ACCESS (MITRE T1003.001)</description>
  <mitre><id>T1003.001</id></mitre>
  <group>credential_access</group>
</rule>
```

### 4.6 Rule 100004 alert (custom, verification run)

```json
"rule": {
  "firedtimes": 1,
  "mail": true,
  "level": 12,
  "description": "Custom: LSASS Credential Dumping - PROCESS_ALL_ACCESS (MITRE T1003.001)",
  "groups": ["windows", "sysmon", "credential_access", "credential_access"],
  "mitre": {
    "technique": ["LSASS Memory"],
    "id": ["T1003.001"],
    "tactic": ["Credential Access"]
  },
  "id": "100004"
},
"location": "EventChannel",
"decoder": { "name": "windows_eventchannel" }
```

### 4.7 Screenshots

| # | Description | File |
|---|-------------|------|
| 1 | PowerShell attack script execution, `Handle: 1404` returned | `../screenshots/lsass-01-powershell-attack.png` |
| 2 | Windows Event Viewer, Sysmon Event 10 detail (`TargetImage: lsass.exe`, `GrantedAccess: 0x1fffff`) | `../screenshots/lsass-02-sysmon-event10.png` |
| 3 | Wazuh Discover, `rule.id: 92900` false positive on `svchost.exe` | `../screenshots/lsass-03-wazuh-fp-svchost.png` |
| 4 | Custom rule 100004 as deployed in `local_rules.xml` | `../screenshots/lsass-04-custom-rule.png` |
| 5 | Wazuh Discover, `rule.id: 100004` successful alert | `../screenshots/lsass-05-wazuh-alert.png` |
| 6 | Rule 100004 alert detail (JSON) with MITRE tags | `../screenshots/lsass-06-wazuh-json-details.png` |

## 5. IOCs

| Type | Value | Context |
|------|-------|---------|
| Process | `lsass.exe` | Target of the memory access |
| Access mask | `0x1FFFFF` (`PROCESS_ALL_ACCESS`) | Requested access level, characteristic of credential-dumping tools |
| Source process | `powershell.exe` | Process that requested the access |
| API call | `OpenProcess` (kernel32.dll, via P/Invoke) | Mechanism used to request the handle |

## 6. Detection

| Rule | Level | Logic |
|------|-------|-------|
| 92900 (built-in) | — | Did not fire — matches only a fixed set of access masks that does not include `0x1FFFFF`; also observed to false-positive on legitimate `svchost.exe` activity in this environment |
| 100004 (custom) | 12 | Sysmon Event 10, `targetImage` matches `lsass.exe`, `grantedAccess` matches `0x1[fF]{5}` (i.e. `0x1FFFFF`), `sourceImage` excludes known-noisy processes |

**Assessment:** the built-in rule provided no coverage for this specific access pattern and was independently shown to be noisy; the custom rule closed both gaps and fired correctly (once) on the verification run.

## 7. Lessons Learned

- The stock SwiftOnSecurity Sysmon config does not log `ProcessAccess` events for `lsass.exe` out of the box — any LSASS-focused detection in this lab (or elsewhere using this baseline config) needs that `TargetImage` explicitly added to the include filter first, or the telemetry simply won't exist to alert on.
- LSA Protection (`RunAsPPL`) genuinely blocks this access pattern when enabled — disabling it here was a deliberate lab choice to make the technique reproducible, not a configuration to recommend in production (see Recommendations, which argue the opposite).
- Relying on a built-in rule's fixed access-mask list is risky in both directions: it missed this technique's actual mask (`0x1FFFFF`) and separately produced a false positive on legitimate `svchost.exe` activity. A custom rule scoped to the specific mask and a short exclusion list for known-legitimate callers proved more precise than either widening or trusting the built-in rule alone.
- The alert JSON for rule 100004 lists `credential_access` twice in its `groups` array — a cosmetic duplication caused by the group being applied both via the enclosing `<group name="...credential_access,">` wrapper and the inner `<group>credential_access</group>` tag on the rule itself. Harmless, but worth removing the redundant inner tag for a cleaner rule definition.
- The lab-wide clock-sync issue flagged after the RDP brute-force case (Kali's unsynced clock) is still unresolved — this case's events show smaller but still-present timestamp drift between Dashboard display time and each event's own `utcTime` field. NTP sync across the lab remains open work.

## 8. Recommendations

| Priority | Recommendation |
|----------|----------------|
| High | In production, keep LSA Protection (`RunAsPPL`) enabled — it is an effective control against exactly this access pattern and was only disabled here to make the lab scenario reproducible |
| High | Extend Sysmon's `ProcessAccess` include filter to cover `lsass.exe` on any host where credential-dumping detection matters; it is not logged by default |
| Medium | Add Credential Guard or an EDR-level LSASS protection control as defense in depth, rather than relying on SIEM detection alone for this technique |
| Medium | Periodically review which processes are excluded in rule 100004's negated `sourceImage` list, since an overly broad exclusion list could itself become a detection gap |
| Low | Remove the redundant inner `<group>credential_access</group>` tag from rule 100004 |
| Low | Apply the still-outstanding NTP sync recommendation from the RDP brute-force investigation across all lab VMs |
