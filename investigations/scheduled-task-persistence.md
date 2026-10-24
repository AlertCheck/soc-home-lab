# Investigation: Scheduled Task Persistence (schtasks.exe)

> **Simulation note:** as with the PowerShell execution case, this command was run **manually, directly on the Win10 Target**, not delivered remotely from Kali. It simulates what an attacker with existing code execution might do to establish persistence.

| Field | Value |
|-------|-------|
| ID | INV-003 |
| Severity | Medium (persistence mechanism successfully created) |
| Status | Closed |
| Analyst | AlertCheck |
| Detection | [detections/scheduled-task-persistence.xml](../detections/scheduled-task-persistence.xml) |
| Triggered rules | 61603 (built-in), 100003 (custom) |

## 1. Summary

On the Win10 Target, the following command was run to create a scheduled task that launches `calc.exe` (a harmless stand-in for a real payload) at every interactive logon:

```
schtasks /create /tn "ScheduledTaskDemo" /tr "calc.exe" /sc onlogon /f
```

Unlike the RDP and PowerShell scenarios in this lab, **this command succeeded** — the target confirmed creation (`УСПЕХ. Запланированная задача "ScheduledTaskDemo" была успешно создана`). This gives the detection a genuine positive case to validate against, rather than only a blocked or failed attempt.

Sysmon logged the process creation as Event ID 1, capturing the full command line, the parent process (`powershell.exe`), and the executing user (`DESKTOP-478GG5N\Target-host`). Wazuh's built-in rule 61603 matched the underlying Sysmon event, and custom rule **100003** — which narrows that match to processes whose `originalFileName` is `schtasks.exe` — fired at level 12, tagged with T1053.005.

**Verdict:** scheduled-task persistence technique executed and detected. The task itself uses a benign payload (`calc.exe`) so no real malicious persistence exists on the lab target beyond the demo task.

## 2. Timeline

| Time | Source | Event |
|------|--------|-------|
| 2026-10-18 16:03:48 (local) / 13:03:48.300 UTC | Target (interactive PowerShell) | `schtasks /create /tn "ScheduledTaskDemo" /tr "calc.exe" /sc onlogon /f` run; target confirms success |
| 2026-10-18 13:03:48.300 UTC | Target (Sysmon) | Event ID 1 (Process Create) logs `schtasks.exe`, PID 3756, parent `powershell.exe` (PID 6172) |
| 2026-10-18 16:03:48.978 (Wazuh Dashboard time) | Wazuh | Rule 100003 fires on the matching Sysmon event |

## 3. TTP (MITRE ATT&CK)

| Tactic | Technique | ID | Observed as |
|--------|-----------|----|-------------|
| Persistence / Privilege Escalation | Scheduled Task/Job: Scheduled Task | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | `schtasks.exe` used to register a task that runs at logon |

## 4. Evidence

### 4.1 Simulated command (executed manually on the target)

```
PS C:\Windows\system32> schtasks /create /tn "ScheduledTaskDemo" /tr "calc.exe" /sc onlogon /f
УСПЕХ. Запланированная задача "ScheduledTaskDemo" была успешно создана.
```

### 4.2 Sysmon Event 1 (Process Create) detail

| Field | Value |
|-------|-------|
| UtcTime | 2026-10-18 13:03:48.300 |
| Image | `C:\Windows\System32\schtasks.exe` |
| OriginalFileName | `schtasks.exe` |
| Description | Task Scheduler Configuration Tool |
| CommandLine | `"C:\Windows\system32\schtasks.exe" /create /tn ScheduledTaskDemo /tr calc.exe /sc onlogon /f` |
| User | `DESKTOP-478GG5N\Target-host` |
| IntegrityLevel | High |
| ParentImage | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| ParentUser | `DESKTOP-478GG5N\Target-host` |
| ProcessGuid | `{1073ad63-c3b4-6ad4-9f03-000000000d00}` |

### 4.3 Wazuh Discover query used

```text
rule.id: 100003
```

### 4.4 Rule 100003 alert (custom)

```json
"rule": {
  "firedtimes": 3,
  "mail": true,
  "level": 12,
  "description": "Custom: Scheduled Task Creation Detected (MITRE T1053.005)",
  "groups": ["windows", "persistence"],
  "mitre": {
    "technique": ["Scheduled Task"],
    "id": ["T1053.005"],
    "tactic": ["Execution", "Persistence", "Privilege Escalation"]
  },
  "id": "100003"
}
```

### 4.5 Custom rule as deployed

```bash
sudo grep -A 8 'id="100003"' /var/ossec/etc/rules/local_rules.xml
```

```xml
<group name="windows,persistence">
  <rule id="100003" level="12">
    <if_sid>61603</if_sid>
    <field name="win.eventdata.originalFileName">schtasks.exe</field>
    <description>Custom: Scheduled Task Creation Detected (MITRE T1053.005)</description>
    <mitre>
      <id>T1053.005</id>
    </mitre>
  </rule>
</group>
```

### 4.6 Screenshots

| # | Description | File |
|---|---|---|
| 1 | Scheduled Task creation command execution (`schtasks.exe`) | [sched-task-01-schtasks-create.png](../screenshots/sched-task-01-schtasks-create.png) |
| 2 | Sysmon Event ID 1 (Process Creation) details | [sched-task-02-sysmon-event1.png](../screenshots/sched-task-02-sysmon-event1.png) |
| 3 | Wazuh Alert triggered (Custom Rule 100003) | [sched-task-03-rule-100003-alert.png](../screenshots/sched-task-03-rule-100003-alert.png) |
| 4 | Rule 100003 alert detail (JSON) | [sched-task-04-rule-100003-detail.png](../screenshots/sched-task-04-rule-100003-detail.png) |
| 5 | Custom rule 100003 configuration in `local_rules.xml` | [sched-task-05-custom-rule-config.png](../screenshots/sched-task-05-custom-rule-config.png) |

## 5. IOCs

| Type | Value | Context |
|------|-------|---------|
| Process | `schtasks.exe` | Task Scheduler CLI tool, used for persistence |
| Task name | `ScheduledTaskDemo` | Created task name |
| Trigger | `onlogon` | Runs at every interactive logon |
| Payload | `calc.exe` | Harmless demo payload standing in for a real one |
| Parent process | `powershell.exe` | Process that spawned `schtasks.exe` |

## 6. Detection

| Rule | Level | Logic |
|------|-------|-------|
| 61603 (built-in) | — | Matches the underlying Sysmon Event 1 (process creation) |
| 100003 (custom) | 12 | Narrows rule 61603 to processes where `originalFileName` is `schtasks.exe` |

**Assessment:** rule 100003 fired 3 times in total during testing. The Discover screenshot shows the alert for this specific run; the other two firings are consistent with the command having been run a few times while validating the rule, rather than something inherent to a single `schtasks.exe` invocation.

## 7. Lessons Learned

- This is the first scenario in the lab where the simulated technique actually succeeded end-to-end (unlike RDP, blocked by NLA, and PowerShell, blocked by a missing C2 listener) — useful for confirming the detection works against a genuine positive case, not only failed attempts.
- Sysmon's parent-process field made it easy to see that `schtasks.exe` was spawned from `powershell.exe` rather than directly from a logon shell — a detail worth correlating with the PowerShell execution rule (100002) if the two techniques are ever chained in a future scenario.
- Basing the custom rule on `originalFileName` rather than `Image` (full path) is more resilient to the binary being invoked from a non-standard path, though it would still miss a renamed copy of `schtasks.exe` with a stripped or altered file version resource.

## 8. Recommendations

| Priority | Recommendation |
|----------|----------------|
| High | Alert on scheduled task creation outside of normal administrative hours or by non-admin users |
| Medium | Cross-check Sysmon-based detection (this rule) against the native Task Scheduler operational log (Event ID 106) for redundancy |
| Medium | Extend monitoring to task **modification** and **deletion** (not just creation), since persistence can also be re-established by editing an existing task |
| Low | Maintain an allowlist of expected scheduled tasks on managed hosts to reduce noise from legitimate administrative task creation |
