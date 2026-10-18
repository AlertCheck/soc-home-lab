# Investigation: RDP Brute Force Attack (T1110)

## Summary
Simulation of a brute force attack against the Remote Desktop Protocol (RDP) service on the Windows Target. The attacker used the Hydra tool and a dictionary of common passwords.

The attack was interrupted by the Windows security mechanism (NLA), however, all login attempts were successfully logged by Wazuh via the Security event log (Event ID 4625).

## MITRE ATT&CK Mapping
*   **Tactic:** Credential Access
*   **Technique:** [T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)
*   **Sub-technique:** [T1110.001 - Password Guessing](https://attack.mitre.org/techniques/T1110/001/)

## Attack Simulation & Network Behavior

**Attacker:** Kali Linux (`192.168.230.129`)
**Target:** Windows 10 Pro (`192.168.230.128`)
**Tool:** Hydra v9.6

**Attack command:**
```bash
hydra -l Target-host -P /tmp/passwords.txt 192.168.230.128 rdp -V -f -t 1 -W 3
