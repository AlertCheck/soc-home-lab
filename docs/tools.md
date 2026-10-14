# Tools

Versions reflect the current state of the lab.

## SIEM

| Tool | Version | Purpose | Link |
|------|---------|---------|------|
| Wazuh Indexer | 4.9.2 | Storage and search for events and alerts | [wazuh.com](https://wazuh.com/) |
| Wazuh Manager | 4.9.2 | Event intake, decoders, rules, correlation | [github.com/wazuh/wazuh](https://github.com/wazuh/wazuh) |
| Wazuh Dashboard | 4.9.2 | Web UI, dashboards, threat hunting | [documentation.wazuh.com](https://documentation.wazuh.com/) |
| WSL2 (Ubuntu) | 24.04 | Runtime environment for the Wazuh stack | [learn.microsoft.com/windows/wsl](https://learn.microsoft.com/windows/wsl/) |

## Telemetry

| Tool | Version | Purpose | Link |
|------|---------|---------|------|
| Sysmon | 15.22 | Extended Windows telemetry: processes, network, registry | [Sysinternals Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon) |
| sysmon-config (SwiftOnSecurity) | latest at install time | Baseline low-noise Sysmon configuration | [github.com/SwiftOnSecurity/sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config) |
| Wazuh Agent | 4.9.2 | Ships Windows and Sysmon events to the Manager | [documentation.wazuh.com](https://documentation.wazuh.com/current/installation-guide/wazuh-agent/index.html) |
| PowerShell Script Block Logging | built into Windows | Logs executed PowerShell code (Event ID 4104) | [about_Logging_Windows](https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_logging_windows) |
| Microsoft Defender | built into Windows | Antivirus, additional event source | [learn.microsoft.com/defender-endpoint](https://learn.microsoft.com/defender-endpoint/) |

## Hypervisor

| Tool | Version | Purpose | Link |
|------|---------|---------|------|
| VMware Workstation Player | 17.6.3 | Runs the lab virtual machines | [vmware.com](https://www.vmware.com/products/desktop-hypervisor/workstation-and-fusion) |
| VMnet1 (Host-Only) | 192.168.230.0/24 | Isolated network between the host and the VMs | [VMware documentation](https://docs.vmware.com/) |
| Docker Desktop | installed, not in use | Disk image relocated to a separate drive | [docker.com](https://www.docker.com/products/docker-desktop/) |

## Attack

| Tool | Version | Purpose | Link |
|------|---------|---------|------|
| Kali Linux | 2026.1 | Attacker platform | [kali.org](https://www.kali.org/) |
| THC-Hydra | bundled with Kali | Password guessing (RDP brute force) | [github.com/vanhauser-thc/thc-hydra](https://github.com/vanhauser-thc/thc-hydra) |
| Atomic Red Team | planned | Reproducible tests for ATT&CK techniques | [github.com/redcanaryco/atomic-red-team](https://github.com/redcanaryco/atomic-red-team) |

## Target OS

| Tool | Version | Purpose | Link |
|------|---------|---------|------|
| Windows 10 Pro | 22H2 | Target system, source of Security and Sysmon events | [microsoft.com/windows](https://www.microsoft.com/windows/) |
| RDP (Remote Desktop) | built into Windows | Target service for the brute-force scenario (3389) | [learn.microsoft.com/windows-server/remote](https://learn.microsoft.com/windows-server/remote/remote-desktop-services/welcome-to-rds) |

## Reference Resources

| Resource | Purpose | Link |
|----------|---------|------|
| MITRE ATT&CK | Classification of techniques and tactics | [attack.mitre.org](https://attack.mitre.org/) |
| Windows Security Events | Description of Event IDs 4624 / 4625 | [Ultimate Windows Security](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/) |
| Sigma | Portable detection rule format (planned) | [github.com/SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) |
