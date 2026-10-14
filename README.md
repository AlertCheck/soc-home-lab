# SOC Home Lab

![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)
![SIEM: Wazuh 4.9.2](https://img.shields.io/badge/SIEM-Wazuh%204.9.2-blue)
![Status: in progress](https://img.shields.io/badge/status-in%20progress-orange)

A hands-on **blue team** SOC lab: deploy a SIEM, collect telemetry from a Windows target, attack it from Kali, write detections, and document investigations.

## Overview

This repository documents a home SOC lab built on a single workstation. A Wazuh SIEM runs in WSL2, a Windows 10 target streams Sysmon and Security telemetry to it, and a Kali machine generates attacks. Each attack scenario ends with a Wazuh detection and a written investigation.

## Goals

- Practice the full cycle: **attack → telemetry → detection → investigation → lessons learned**.
- Build a portfolio of detections (Wazuh rules) and incident write-ups in a format close to real SOC work.
- Map every observed TTP to [MITRE ATT&CK](https://attack.mitre.org/).

## Architecture

```mermaid
flowchart LR
    subgraph HOST["Windows 10 Pro host"]
        direction TB
        subgraph WSL["WSL2 Ubuntu 24.04"]
            WZ["Wazuh Indexer + Manager + Dashboard"]
        end
        PP["netsh portproxy<br/>443 / 1514 / 1515 / 55000"]
        subgraph VMW["VMware Workstation Player"]
            WIN["Win10 Target<br/>192.168.230.128<br/>Sysmon + Wazuh Agent"]
            KALI["Kali Attacker<br/>192.168.230.x"]
        end
        PP --> WZ
    end

    KALI -- "RDP brute force :3389" --> WIN
    WIN -- "agent events :1514" --> PP
    ANALYST(("Analyst")) -- "https://localhost" --> PP
```

Details: [docs/architecture.md](docs/architecture.md).

## Tech Stack

| Layer | Component | Version |
|-------|-----------|---------|
| SIEM | Wazuh (Indexer, Manager, Dashboard) | 4.9.2 |
| SIEM platform | WSL2, Ubuntu | 24.04 |
| Telemetry | Sysmon + SwiftOnSecurity config | 15.22 |
| Telemetry | Wazuh Agent | 4.9.2 |
| Hypervisor | VMware Workstation Player | 17.6.3 |
| Target | Windows 10 Pro | 22H2 |
| Attacker | Kali Linux | 2026.1 |

Full list with links: [docs/tools.md](docs/tools.md).

## Progress

- [x] Wazuh 4.9.2 deployed in WSL2 (Ubuntu 24.04, systemd enabled)
- [x] WSL2 resource limits via `.wslconfig` (8 GB RAM, 4 CPUs, swap on a dedicated disk)
- [x] Host-to-WSL port forwarding automated ([scripts/update-portproxy.ps1](scripts/update-portproxy.ps1))
- [x] VMware Workstation Player, isolated VMnet1 network (Host-Only)
- [x] Windows 10 Target: Sysmon + SwiftOnSecurity, Wazuh Agent, PowerShell Script Block Logging, Defender
- [x] RDP enabled on the Target (3389)
- [x] Kali Attacker deployed
- [x] First detection: [detections/rdp-brute-force.xml](detections/rdp-brute-force.xml)
- [x] First investigation: [investigations/rdp-brute-force.md](investigations/rdp-brute-force.md)

## Detections and Investigations

| Scenario | Detection | Investigation | ATT&CK |
|----------|-----------|---------------|--------|
| RDP brute force | [rdp-brute-force.xml](detections/rdp-brute-force.xml) | [rdp-brute-force.md](investigations/rdp-brute-force.md) | T1110, T1021.001 |

## MITRE ATT&CK Mapping

| Technique | ID | Scenario | Detection rule |
|-----------|----|----------|----------------|
| Brute Force: Password Guessing | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | RDP brute force | 100101 |
| Remote Services: Remote Desktop Protocol | [T1021.001](https://attack.mitre.org/techniques/T1021/001/) | RDP brute force | 100100, 100101, 100102 |
| Valid Accounts | [T1078](https://attack.mitre.org/techniques/T1078/) | RDP logon after brute force | 100102 |

## Repository Structure

```text
soc-home-lab/
├── README.md
├── LICENSE
├── docs/
│   ├── architecture.md
│   └── tools.md
├── detections/
│   └── rdp-brute-force.xml
├── investigations/
│   └── rdp-brute-force.md
├── screenshots/
└── scripts/
    └── update-portproxy.ps1
```

## Getting Started

1. **SIEM.** In WSL2 (Ubuntu 24.04) install Wazuh 4.9 using the official quickstart:
```bash
   curl -sO https://packages.wazuh.com/4.9/wazuh-install.sh
   sudo bash ./wazuh-install.sh -a
```
2. **Port forwarding.** On the Windows host, run [scripts/update-portproxy.ps1](scripts/update-portproxy.ps1) as Administrator (re-run it after every WSL restart).
3. **Target.** On the Windows 10 VM install Sysmon with the SwiftOnSecurity config:
```powershell
   sysmon64.exe -accepteula -i sysmonconfig.xml
```
   Install the Wazuh Agent with `WAZUH_MANAGER` set to the host IP on VMnet1 (`192.168.230.1`).
4. **Detections.** Copy files from [detections/](detections/) to `/var/ossec/etc/rules/` on the Wazuh Manager and restart it:
```bash
   sudo systemctl restart wazuh-manager
```
5. **Attack.** Run the scenario from Kali and compare the alerts with the matching file in [investigations/](investigations/).

See [docs/architecture.md](docs/architecture.md) for the network layout and resource limits.

## Roadmap

- [ ] Detection and write-up for suspicious PowerShell execution (Script Block Logging, T1059.001)
- [ ] Detection for persistence creation (Run keys, scheduled tasks; T1547, T1053)
- [ ] Detection for LSASS dumping via Sysmon Event ID 10 (T1003.001)
- [ ] Atomic Red Team integration for reproducible tests
- [ ] Convert rules to Sigma format
- [ ] Add a Linux target with a Wazuh agent
- [ ] Active Response: block the source of a brute-force attack
- [ ] Wazuh dashboards for lab scenarios

## Lab Safety

- The VMnet1 network is isolated (Host-Only); the targets have no outbound access through this segment.
- All passwords and secrets in this repository are replaced with `<REDACTED>`.
- Attacks are performed **only** against my own virtual machines.

## License

This project is licensed under the [MIT License](LICENSE).
