# Investigation: RDP Brute Force (Kali → Win10 Target)

| Field | Value |
|-------|-------|
| ID | INV-001 |
| Severity | Medium (brute force detected, no confirmed compromise) |
| Status | Closed |
| Analyst | AlertCheck |
| Detection | [detections/rdp-brute-force.xml](../detections/rdp-brute-force.xml) |
| Triggered rules | 60122 (built-in), 100001 (custom correlation) |

## 1. Summary

A Kali host (`192.168.230.129`) ran a password-guessing attack with Hydra against the `Target-host` account over RDP on the Win10 Target (`192.168.230.128:3389`), using the first 50 entries of `rockyou.txt`. The target has Network Level Authentication (NLA) enabled, so failed attempts were logged as Event ID 4625 with **LogonType 3** (Network) rather than LogonType 10 (RemoteInteractive) — NLA rejects the credentials before a full RDP session is negotiated. Hydra's RDP module could not sustain the connection rate and aborted with `all children were disabled due to too many connection errors`; **no valid password was found and no successful logon (Event 4624) occurred**.

Wazuh correlated the resulting burst of failed logons with custom rule **100001** (5+ hits of built-in rule 60122 within 300 seconds, level 12), tagged with the correct MITRE techniques (T1110 / T1110.001).

**Verdict:** brute-force attempt detected; NLA prevented the attack from completing. No compromise observed in this run.

## 2. Timeline (UTC — convert from your tool's local display before filling in)

| Time | Source | Event |
|------|--------|-------|
| `<time>` | Kali | Hydra started against `rdp://192.168.230.128` |
| `<time>` | Target (Security log) | First Event 4625, LogonType 3, from 192.168.230.129 |
| `<time>` | Wazuh | Rule 60122 fires on each failed logon |
| `<time>` | Wazuh | Rule 100001 fires (5th failure within 300s) — 1st occurrence |
| `<time>` | Wazuh | Rule 100001 fires — 2nd occurrence |
| `<time>` | Kali / Hydra | Hydra aborts: `all children were disabled due to too many connection errors`; `0 of 1 target completed, 0 valid password found` |

> Note: the Kali terminal clock showed a `-0400` offset during this run while the Wazuh Dashboard and Windows Event Viewer used a different timezone. Times above should be normalized to UTC (or one consistent zone) before publishing — see Lessons Learned.

## 3. TTP (MITRE ATT&CK)

| Tactic | Technique | ID | Observed as |
|--------|-----------|----|-------------|
| Credential Access | Brute Force: Password Guessing | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | Repeated failed RDP logons via Hydra |
| Credential Access | Brute Force | [T1110](https://attack.mitre.org/techniques/T1110/) | Correlated burst flagged by rule 100001 |

T1021.001 (Remote Desktop Protocol) and T1078 (Valid Accounts) are **not** claimed here, since no successful logon occurred in this run.

## 4. Evidence

### 4.1 Reconnaissance

```bash
nmap -p 3389 192.168.230.128
```
Result: `3389/tcp open ms-wbt-server`.

### 4.2 Attack command (Kali)

```bash
hydra -l Target-host -P /tmp/passwords.txt 192.168.230.128 rdp -V -f -t 1 -W 3
```

### 4.3 Attack outcome

```text
[ERROR] all children were disabled due too many connection errors
0 of 1 target completed, 0 valid password found
```

### 4.4 Sample 4625 event (fields as observed, Windows Event Viewer)

| Field | Value |
|-------|-------|
| TargetUserName | Target-host |
| LogonType | 3 |
| Status | 0xc000006d |
| SubStatus | 0xc000006a (wrong password for existing account) |
| AuthenticationPackageName | NTLM |
| WorkstationName | kali |
| IpAddress | 192.168.230.129 |

### 4.5 Rule 60122 alert (built-in, default MITRE mapping)

Note the default mapping to T1531 (Account Access Removal), which is corrected by rule 100001 below.

```json
"mitre": {
  "technique": ["Account Access Removal"],
  "id": ["T1531"],
  "tactic": ["Impact"]
},
"id": "60122"
```

### 4.6 Rule 100001 alert (custom correlation)

```json
"rule": {
  "firedtimes": <n>,
  "level": 12,
  "description": "Custom: RDP Brute Force Attack Detected (MITRE T1110)",
  "mitre": {
    "technique": ["Brute Force", "Password Guessing"],
    "id": ["T1110", "T1110.001"],
    "tactic": ["Credential Access"]
  },
  "id": "100001",
  "frequency": 5
}
```

### 4.7 Wazuh Dashboard queries used

```text
rule.id: 60122
rule.id: 100001
```

### 4.8 Screenshots

| # | Description | File |
|---|-------------|------|
| 1 | Connectivity check: ping to the target | `../screenshots/01-ping.png` |
| 2 | nmap confirming RDP (3389) open on the target | `../screenshots/02-nmap.png` |
| 3 | Password list built from rockyou.txt (50 entries) | `../screenshots/03-dictionary.png` |
| 4 | Hydra attack in progress | `../screenshots/04-hydra-running.png` |
| 5 | Hydra aborting due to NLA (connection errors) | `../screenshots/05-hydra-finished.png` |
| 6 | Wazuh Discover: raw Event 4625 hits (30 in the search window) | `../screenshots/06-events-4625.png` |
| 7 | Wazuh Discover: `rule.id:60122` hits | `../screenshots/07-rule-60122.png` |
| 8 | Rule 60122 alert detail (JSON) — default MITRE mapping T1531 | `../screenshots/08-alert-detail.png` |
| 9 | MITRE ATT&CK dashboard, tactics overview | `../screenshots/09-mitre.png` |
| 10 | Windows Event Viewer, Event 4625 detail (LogonType 3) | `../screenshots/10-event-4625-detail.png` |
| 11 | Custom rule 100001 as deployed in `local_rules.xml` | `../screenshots/11-custom-rule.png` |
| 12 | Wazuh Discover: `rule.id:100001` hits | `../screenshots/12-rule-100001.png` |
| 13 | Rule 100001 alert detail (JSON) — corrected MITRE mapping T1110/T1110.001 | `../screenshots/13-rule-100001-detail.png` |
| 14 | MITRE ATT&CK Framework view, T1110 / T1110.001 technique counts | `../screenshots/14-mitre-with-t1110.png` |

## 5. IOCs

| Type | Value | Context |
|------|-------|---------|
| IPv4 | 192.168.230.129 | Attack source (Kali) |
| Account | Target-host | Targeted account |
| Port | 3389/TCP | Targeted service |
| Tool | Hydra (RDP module) | Password-guessing tool |
| Event ID | 4625, LogonType 3, status 0xc000006d, subStatus 0xc000006a | Failed logons (NLA pre-auth rejection) |

## 6. Detection

| Rule | Level | Logic |
|------|-------|-------|
| 60122 (built-in) | 5 | Single Windows logon failure, unknown user or bad password |
| 100001 (custom) | 12 | 5 or more hits of rule 60122 within 300 seconds, re-tagged with T1110 / T1110.001 |

**Assessment:** the correlation rule fired `<n>` times during the run, confirming the burst of failed logons was caught even though the underlying attack never reached a full RDP session.

## 7. Lessons Learned

- NLA is an effective control against naive brute-force tools: it rejects credentials before a full RDP session is established, which both blocks automated tools like this Hydra run and changes the logged LogonType from 10 to 3. Any detection rule written against LogonType 10 alone would have missed this attack entirely.
- Wazuh's built-in rule 60122 carries an incorrect default MITRE mapping (T1531 / Impact) for a credential-guessing event; a custom correlation rule was needed to apply the correct T1110 / T1110.001 / Credential Access tags.
- The Kali VM's clock was not in sync with the rest of the lab (seen as a `-0400` offset in nmap output vs. the Dashboard's timezone), which made building an accurate timeline harder. NTP sync across all lab VMs is needed before the next scenario.
- A single-threaded, 3-second-delay Hydra run (`-t 1 -W 3`) is slow and still triggered connection errors against NLA; this is worth revisiting with different Hydra tuning in a future scenario, or accepting that NLA makes naive RDP brute force impractical by design.

## 8. Recommendations

| Priority | Recommendation |
|----------|----------------|
| High | Keep NLA enabled on all RDP-exposed hosts — it already proved effective here |
| High | Do not expose RDP to the internet; allow access only through a VPN or RD Gateway |
| High | Enable account lockout after N failed attempts (Account Lockout Policy) |
| Medium | Add Wazuh Active Response to temporarily block the source IP on rule 100001 |
| Medium | Add a companion rule for a successful logon shortly after rule 100001 fires, once validated against a real successful-logon event |
| Medium | Sync clocks across all lab VMs (NTP) before the next scenario |
| Low | Review other built-in Wazuh rules for similarly incorrect default MITRE mappings |
