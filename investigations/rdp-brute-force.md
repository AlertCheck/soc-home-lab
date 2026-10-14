# Investigation: RDP Brute Force (Kali → Win10 Target)

> **Note:** this document describes a controlled attack inside my own lab. All data (timestamps, counters, session details) is illustrative and should be replaced with values from the actual run. Screenshots go into [`../screenshots/`](../screenshots/).

| Field | Value |
|-------|-------|
| ID | INV-001 |
| Severity | High (if the logon succeeds) |
| Status | Closed (training scenario) |
| Analyst | AlertCheck |
| Detection | [detections/rdp-brute-force.xml](../detections/rdp-brute-force.xml) |
| Triggered rules | 100100, 100101, 100102 |

## 1. Summary

A Kali host (`192.168.230.129`) ran a password-guessing attack with Hydra against the `Target-host` account over RDP on the Win10 Target (`192.168.230.128:3389`). Wazuh recorded a series of Event ID 4625 (LogonType 10) failures and fired on the threshold of 8 failures within 120 seconds (rule 100101, level 10). The attack ended with a successful guess, followed by a successful Event ID 4624 (LogonType 10) logon from the same address, which triggered rule 100102 (level 12).

**Verdict:** confirmed account compromise via RDP (training scenario).

## 2. Timeline (UTC)

| Time (UTC) | Source | Event |
|------------|--------|-------|
| 12:00:03 | Kali | Hydra started against `rdp://192.168.230.128` |
| 12:00:04 | Sysmon Event 3 (Target) | First network connections from 192.168.230.129 to port 3389 |
| 12:00:05 | Security 4625 (Target) | First failed logon, LogonType 10 |
| 12:00:05 | Wazuh | Rule 100100 (level 5) fires on every failure |
| 12:00:17 | Wazuh | 8th failure within 120 seconds, rule 100101 fires (level 10) |
| 12:00:17 – 12:09:40 | Security 4625 (Target) | Guessing continues, about 40 attempts per minute |
| 12:09:44 | Security 4624 (Target) | Successful logon, LogonType 10, source 192.168.230.129 |
| 12:09:44 | Wazuh | Rule 100102 fires (level 12) |
| 12:09:46 | Hydra | Valid login/password pair found, process exits |

## 3. TTP (MITRE ATT&CK)

| Tactic | Technique | ID | Observed as |
|--------|-----------|----|-------------|
| Credential Access | Brute Force: Password Guessing | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | Mass password guessing with Hydra |
| Lateral Movement | Remote Services: Remote Desktop Protocol | [T1021.001](https://attack.mitre.org/techniques/T1021/001/) | RDP logon on port 3389 |
| Defense Evasion / Persistence | Valid Accounts | [T1078](https://attack.mitre.org/techniques/T1078/) | Use of the guessed credentials |
| Reconnaissance | Active Scanning | [T1595](https://attack.mitre.org/techniques/T1595/) | Prior check that port 3389 is open (optional) |

## 4. Evidence

### 4.1 Attack command (Kali)

```bash
hydra -t 4 -V -f -l Target-host -P wordlist.txt rdp://192.168.230.128
```

### 4.2 Sample 4625 event (abridged)

```json
{
  "win": {
    "system": {
      "eventID": "4625",
      "channel": "Security",
      "computer": "Target-host"
    },
    "eventdata": {
      "targetUserName": "Target-host",
      "logonType": "10",
      "ipAddress": "192.168.230.129",
      "status": "0xc000006d",
      "subStatus": "0xc000006a",
      "authenticationPackageName": "NTLM"
    }
  },
  "rule": {
    "id": "100100",
    "level": 5,
    "mitre": { "id": ["T1110", "T1021.001"] }
  }
}
```

`subStatus 0xc000006a` means a wrong password for an existing account.

### 4.3 Sample 4624 event (abridged)

```json
{
  "win": {
    "system": { "eventID": "4624",
