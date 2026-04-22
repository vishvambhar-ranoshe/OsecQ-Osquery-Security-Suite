# OsecQ - Osquery Security Suite

<div align="center">

```text
  ██████╗ ███████╗███████╗ ██████╗ ██████╗
 ██╔═══██╗██╔════╝██╔════╝██╔════╝██╔═══██╗
 ██║   ██║███████╗█████╗  ██║     ██║   ██║
 ██║   ██║╚════██║██╔══╝  ██║     ██║▄▄ ██║
 ╚██████╔╝███████║███████╗╚██████╗╚██████╔╝
  ╚═════╝ ╚══════╝╚══════╝ ╚═════╝ ╚══▀▀═╝
```

**A Python-powered terminal security suite built on osquery**

*Reconnaissance · Threat Hunting · Live Monitoring · Incident Response*

![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-blue?style=flat-square&logo=kali-linux)
![Python](https://img.shields.io/badge/Python-3.x-green?style=flat-square&logo=python)
![Engine](https://img.shields.io/badge/Engine-osquery-orange?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-red?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)

</div>

---

## What Is OsecQ?

OsecQ is a unified, menu-driven terminal security suite that turns **osquery into a complete endpoint investigation platform**. Instead of running dozens of separate Linux commands across multiple terminals, OsecQ brings everything into one interface  powered by SQL queries against the live operating system.

**Built for:**

| Role | Use Case |
|---|---|
| 🔴 Penetration Testers | Rapid system reconnaissance on target machines |
| 🔵 Blue Team Analysts | Continuous monitoring and threat detection |
| 🟡 Incident Responders | Structured investigation by MITRE ATT&CK phase |
| 🟢 Security Students | Learn endpoint security through hands-on SQL queries |

---

## Why OsecQ?

| Traditional Approach | OsecQ Approach |
|---|---|
| `ps` + `netstat` + `who` + `find` + `md5sum` | One unified SQL interface |
| Different syntax for every tool | Standard SQL for everything |
| Manual correlation of results | JOINed queries across tables |
| Results disappear after terminal closes | Auto-saved JSON + TXT reports |
| No alerting on findings | Critical findings auto-flagged and saved instantly |

---

## Features

- **Live Banner Dashboard** — privilege level, osquery status, process count, active connections and findings count updated on every menu open
- **4 Security Modules** — each with full scan, quick scan, and individual query modes
- **74+ Pre-built Queries** — covering the full attack lifecycle
- **Critical Finding Alerts** — web shells, reverse shells, backdoor accounts auto-flagged and saved instantly
- **Auto Report Saving** — every investigation saved as JSON + TXT automatically
- **MITRE ATT&CK Aligned** — IR module organized by all 8 attack phases
- **Continuous Monitor Mode** — live refresh with delta tracking between cycles
- **Zero Extra Dependencies** — just Python 3, osquery, and tabulate

---

## Modules

### 1. Reconnaissance

Build a complete picture of the machine before deeper investigation.

| Query | What It Finds |
|---|---|
| System Identity | Hostname, UUID, CPU, RAM, hardware vendor |
| OS and Kernel | Version, arch, boot arguments |
| System Uptime | High = unpatched · Low = recent reboot |
| User Accounts | Human, system, root-equivalent accounts |
| Privileged Groups | sudo, docker, shadow, adm, wheel members |
| Login Sessions | Current and historical, remote SSH logins |
| Network Interfaces | IPs, MACs, gateway, DNS resolvers |
| Disk Mounts | Usage percentages per filesystem |
| Disk Encryption | LUKS status per block device |
| Shell History | Command count per user |

**Total: 20 queries**

---

### 2. Threat Hunting

Proactively hunt for indicators of compromise across the full attack lifecycle.

| Query | Severity |
|---|---|
| Backdoor root accounts — UID=0 other than root | Critical |
| Web shell detection — shell spawned by web server | Critical |
| Reverse shell candidates — interpreter with external socket | Critical |
| LD_PRELOAD injection — rootkit / library injection | Critical |
| Deleted but running binaries — malware evasion | Critical |
| Processes running from /tmp or /dev/shm | High |
| SUID binary audit — privilege escalation surface | High |
| Cron job persistence — attacker-planted entries | High |
| SSH authorized_keys — backdoor SSH key detection | High |
| Systemd service persistence — malicious services | High |
| Startup script changes — .bashrc, profile.d, rc.local | High |
| Critical binary hashes — trojaned system tool detection | High |
| Suspicious shell history — wget, curl, nc, base64 | Medium |
| Kernel module anomalies — rootkit indicators | High |
| Promiscuous mode NICs — network sniffing detection | Medium |

> Critical findings are **auto-saved** to `reports/` as FINDING files the moment they are detected.

**Total: 20 queries**

---

### 3. System Monitor

Watch the system continuously with live delta tracking between cycles.

**Modes:**

| Mode | Refresh Interval | Best For |
|---|---|---|
| Snapshot | Once | Quick point-in-time check |
| Continuous Watch | Every 60 seconds | Ongoing background monitoring |
| Fast Watch | Every 30 seconds | Active incident response |

**What it tracks:**

| Query | Alert |
|---|---|
| Active user sessions | — |
| Recently started processes | — |
| Top memory consumers | — |
| Established connections | — |
| Listening TCP ports | — |
| Connections to rare ports | Yes |
| Processes in /tmp or /dev/shm | Yes |
| Root processes | — |
| Zombie processes | Yes |
| Files modified in /etc last hour | — |
| New files in /tmp last hour | — |
| Cron jobs watch | — |
| SSH authorized_keys watch | — |
| Process count per user | — |
| Open files in suspicious paths | Yes |
| Disk usage | — |

> In continuous mode, OsecQ tracks result counts between cycles and shows delta indicators  you see the exact moment a new connection opens or a new process starts.

**Total: 20 queries**

---

### 4. Incident Response

Structured investigation aligned with MITRE ATT&CK framework.

| Phase | Queries |
|---|---|
| Phase 1 — Initial Access | SSH brute force detection, web file drops |
| Phase 2 — Execution | Web shells, interpreter processes, cmdline patterns |
| Phase 3 — Persistence | Cron, systemd, SSH keys, startup scripts, SUID, backdoor accounts |
| Phase 4 — Privilege Escalation | Sudo members, docker group, root processes, sudoers integrity |
| Phase 5 — Defense Evasion | Deleted binaries, LD_PRELOAD, binary hash verification, kernel modules |
| Phase 6 — Lateral Movement | SSH keys, known_hosts, outbound SSH, credential file access |
| Phase 7 — Command and Control | Reverse shells, C2 ports, unusual DNS resolvers |
| Phase 8 — Exfiltration | High write processes, archive creation, upload activity |

**Modes:**
- **Full IR Investigation** — run all 8 phases sequentially
- **Single Phase** — focus on one specific attack phase
- **Single Query** — run one specific IR query

**Total: 25+ queries across 8 phases**

---

## Project Structure

```text
OsecQ/
│
├── main.py                      ← Entry point, main menu, startup checks
│
├── core/
│   ├── display.py               ← Colors, banner, tables, menus, live strip
│   ├── runner.py                ← osquery execution engine
│   └── reporter.py              ← Save reports as JSON and TXT
│
├── modules/
│   ├── recon.py                 ← Reconnaissance module
│   ├── threat_hunt.py           ← Threat hunting module
│   ├── monitor.py               ← Continuous monitoring module
│   └── incident_response.py     ← Incident response module
│
├── queries/
│   ├── recon.json               ← 20 recon query definitions
│   ├── threat_hunt.json         ← 20 threat hunting query definitions
│   ├── monitor.json             ← 20 monitoring query definitions
│   └── ir.json                  ← 25+ IR queries across 8 attack phases
│
└── reports/                     ← Auto-saved investigation reports
```

---

## How It Works

```text
User selects option
        ↓
Module loads query definitions from JSON file
        ↓
runner.py executes: osqueryi --json "SELECT ..."
        ↓
osquery reads directly from Linux kernel
        ↓
Results parsed into Python list of dicts
        ↓
display.py renders as color-coded terminal tables
        ↓
reporter.py auto-saves JSON + TXT to reports/
        ↓
Critical findings saved instantly as FINDING files
```

---

## Report System

Every investigation automatically generates two files:

```text
reports/osecq_recon_20260422_083045.json          ← Structured data
reports/osecq_recon_20260422_083045.txt           ← Human readable
reports/osecq_FINDING_20260422_083102.json        ← Critical finding
```

Critical findings are saved **the moment they are detected** — independent of the main report. Evidence is never lost even if the session is interrupted.

---

## Security Coverage

| Domain | Queries | Key Detections |
|---|---|---|
| User Accounts | 8 | Backdoors, UID=0 anomalies, privilege audit |
| Processes | 12 | Web shells, reverse shells, malware execution |
| Network | 10 | C2 connections, rare ports, reverse shells |
| File System | 10 | FIM, SUID binaries, integrity hashes |
| Persistence | 8 | Cron, systemd, SSH keys, startup scripts |
| Privilege Escalation | 6 | SUID abuse, sudo, docker group |
| Defense Evasion | 6 | Rootkits, deleted binaries, LD_PRELOAD |
| Lateral Movement | 5 | SSH pivoting, credential theft |
| Command and Control | 5 | Reverse shells, C2 ports, DNS hijacking |
| Exfiltration | 4 | Uploads, archiving, high write activity |
| **Total** | **74+** | **Across 4 modules** |

---

## Requirements

| Requirement | Version |
|---|---|
| Kali Linux | Any |
| Python | 3.x |
| osquery | 5.x+ |
| tabulate | Latest |
| pyfiglet | Latest |

---

## Installation

**Step 1 — Install osquery:**

```bash
sudo apt update && sudo apt install osquery -y
```

**Step 2 — Clone OsecQ:**

```bash
git clone https://github.com/vishvambhar-ranoshe/OsecQ-Osquery-Security-Suite.git
cd OsecQ-Osquery-Security-Suite
```

**Step 3 — Install Python dependencies:**

```bash
pip3 install -r requirements.txt --break-system-packages
```

**Step 4 — Create log directory:**

```bash
sudo mkdir -p /var/log/osquery
sudo chmod 755 /var/log/osquery
```

**Step 5 — Launch OsecQ:**

```bash
sudo python3 main.py
```

---

## Usage

```bash
# Always run with sudo for full kernel-level visibility
sudo python3 main.py
```

**Main Menu:**

```text
  [1]  Reconnaissance          System identity, users, network, disk
  [2]  Threat Hunting          Full attack lifecycle — IOC detection
  [3]  System Monitor          Live monitoring — snapshot and continuous
  [4]  Incident Response       IR queries by MITRE attack phase
  [5]  View Reports            Browse saved investigation reports
  [6]  About                   Tool info and query statistics
  [0]  Exit
```

**Test the banner:**

```bash
sudo python3 -c "from core.display import print_banner; print_banner()"
```

---

## Key Design Decisions

**Queries in JSON, not Python**
Add, edit, or remove queries without touching any code. The JSON files are the intelligence. The Python is the engine.

**Auto-save everything**
Evidence disappears during investigations. Processes get killed, files get deleted. Auto-saving every query result preserves system state at investigation time.

**Critical findings saved separately**
Web shells, reverse shells, backdoor accounts are saved instantly as independent FINDING files. Even if the main report fails, critical evidence is preserved.

**osquery reads from kernel directly**
Cannot be fooled by LD_PRELOAD rootkits that hook userspace tools like ps, netstat, and ls. OsecQ sees exactly what the kernel sees.

---

## Limitations

- Requires osquery installed separately on the target machine
- Event tables such as file_events and process_events require osqueryd daemon running
- Local machine only — no remote querying (use Fleet for multi-host deployments)
- No historical session comparison between runs

---

## Future Roadmap

- [ ] YARA scanning module — malware pattern matching against file content
- [ ] Fleet integration — query multiple machines from one interface
- [ ] Timeline view — correlate events across modules by timestamp
- [ ] Slack and email alerting — push critical findings to communication channels
- [ ] Custom query builder — write and save your own queries from the UI

---

## Contributing

Pull requests are welcome. To add new queries:

1. Edit the relevant JSON file in `queries/`
2. Add a new object with `name`, `desc`, and `sql` fields
3. Test with `sudo osqueryi "YOUR SQL HERE;"`
4. Submit a PR describing what the query detects and why it matters

---

## Disclaimer

OsecQ is intended for authorized security testing, incident response, and defensive security operations on systems you own or have explicit written permission to investigate. Unauthorized use against systems you do not own is illegal and unethical.

---

## Author

**Vishvambhar Ranoshe**

> All the way to building a production-grade security suite with 74+ detection queries, real-time monitoring, MITRE ATT&CK aligned IR, and an auto-saving report engine. Not assembled from tutorials, engineered through understanding.

---

## License

MIT License — free to use, modify, and distribute with attribution.

---

<div align="center">

**"Security through intelligent querying."** 🔐

*Built with osquery + Python on Kali Linux*

*If this helped you — give it a ⭐ on GitHub*

</div>
