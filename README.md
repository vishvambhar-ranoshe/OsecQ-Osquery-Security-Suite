OsecQ — Osquery Security Suite
markdown# OsecQ — Osquery Security Suite

<div align="center">
██████╗ ███████╗███████╗ ██████╗ ██████╗
██╔═══██╗██╔════╝██╔════╝██╔════╝██╔═══██╗
██║   ██║███████╗█████╗  ██║     ██║   ██║
██║   ██║╚════██║██╔══╝  ██║     ██║▄▄ ██║
╚██████╔╝███████║███████╗╚██████╗╚██████╔╝
╚═════╝ ╚══════╝╚══════╝ ╚═════╝ ╚══▀▀═╝

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

OsecQ is a unified, menu-driven terminal security suite that turns **osquery into a complete endpoint investigation platform**. Instead of running dozens of separate Linux commands across multiple terminals, OsecQ brings everything into one interface — powered by SQL queries against the live operating system.

Built for:
- 🔴 **Penetration Testers** — rapid system reconnaissance on target machines
- 🔵 **Blue Team Analysts** — continuous monitoring and threat detection
- 🟡 **Incident Responders** — structured investigation by MITRE ATT&CK phase
- 🟢 **Security Students** — learn endpoint security through hands-on SQL queries

---

## Why OsecQ?

| Traditional Approach | OsecQ Approach |
|---|---|
| `ps aux` + `netstat` + `who` + `find` + `md5sum` | One SQL interface |
| Different syntax for every tool | Standard SQL for everything |
| Manual correlation of results | JOINed queries across tables |
| Results disappear after terminal closes | Auto-saved JSON + TXT reports |
| No alerting on findings | Critical findings auto-flagged |
| One command = one answer | One query = correlated intelligence |

---

## Features

- **Live Banner Dashboard** — privilege level, osquery status, process count, active connections, findings count — updated every time you open a menu
- **4 Security Modules** — each with full scan, quick scan, and individual query modes
- **74+ Pre-built Queries** — covering the full attack lifecycle
- **Critical Finding Alerts** — web shells, reverse shells, backdoor accounts auto-flagged and saved instantly
- **Auto Report Saving** — every investigation saved as JSON + TXT
- **MITRE ATT&CK Aligned** — IR module organized by all 8 attack phases
- **Continuous Monitor Mode** — live refresh with delta tracking between cycles
- **Zero Dependencies** — just Python 3, osquery, and tabulate

---

## Modules

### 1. Reconnaissance
Build a complete picture of the machine before deeper investigation.
✔ Machine identity      — hostname, UUID, CPU, RAM, hardware vendor
✔ OS and kernel         — version, arch, boot arguments
✔ System uptime         — high = unpatched, low = recent reboot
✔ User accounts         — human, system, root-equivalent accounts
✔ Privileged groups     — sudo, docker, shadow, adm, wheel members
✔ Login sessions        — current and historical, remote SSH logins
✔ Network interfaces    — IPs, MACs, gateway, DNS resolvers
✔ Disk mounts           — usage percentages per filesystem
✔ Disk encryption       — LUKS status per block device
✔ Shell history         — command count per user

**Total: 20 queries**

---

### 2. Threat Hunting
Proactively hunt for indicators of compromise across the full attack lifecycle.
🔴 Backdoor root accounts       — UID=0 accounts other than root
🔴 Web shell detection          — shell spawned by web server process
🔴 Reverse shell candidates     — interpreter with external socket
🔴 LD_PRELOAD injection         — rootkit / library injection indicator
🔴 Deleted but running binaries — malware evasion technique
Processes from /tmp /dev/shm — suspicious execution locations
SUID binary audit            — privilege escalation surface
Cron job persistence         — attacker-planted cron entries
SSH authorized_keys          — backdoor SSH key detection
Systemd service persistence  — malicious service files
Startup script changes       — .bashrc, profile.d, rc.local
Critical binary hashes       — trojaned system tool detection
Suspicious shell history     — wget, curl, nc, base64 commands
Kernel module anomalies      — rootkit kernel module indicators
Promiscuous mode NICs        — network sniffing detection

**🔴 = Auto-saved to reports/ as FINDING file when detected**

**Total: 20 queries**

---

### 3. System Monitor
Watch the system continuously with live delta tracking.

**Modes:**
| Mode | Refresh | Use Case |
|---|---|---|
| Snapshot | Once | Quick point-in-time check |
| Continuous Watch | 60s | Ongoing monitoring |
| Fast Watch | 30s | Active incident response |

**Tracks:**
✔ Active user sessions          ✔ Recently started processes
✔ Top memory consumers          ✔ Established connections
✔ Listening TCP ports           ✔ Connections to rare ports ⚠
✔ Processes in /tmp ⚠           ✔ Root processes
✔ Zombie processes ⚠            ✔ Files modified in /etc (1h)
✔ New files in /tmp (1h)        ✔ Cron jobs watch
✔ SSH authorized_keys watch     ✔ Process count per user
✔ Open files in /tmp ⚠          ✔ Disk usage

**⚠ = Alert-enabled — fires immediately when results appear**

**In continuous mode:** Tracks result counts between cycles and shows `▲ +N` or `▼ -N` delta indicators — you see the exact moment a new connection opens or a new process starts.

**Total: 20 queries**

---

### 4. Incident Response
Structured investigation aligned with MITRE ATT&CK framework.
Phase 1  →  Initial Access       SSH brute force, web file drops
Phase 2  →  Execution            Web shells, interpreter processes, cmdline patterns
Phase 3  →  Persistence          Cron, systemd, SSH keys, startup scripts, SUID
Phase 4  →  Privilege Escalation Sudo, docker group, root processes, sudoers
Phase 5  →  Defense Evasion      Deleted binaries, LD_PRELOAD, binary hashes, modules
Phase 6  →  Lateral Movement     SSH keys, known_hosts, outbound SSH, credentials
Phase 7  →  Command & Control    Reverse shells, C2 ports, DNS hijacking
Phase 8  →  Exfiltration         High write processes, archive creation, uploads

**Modes:**
- Full IR Investigation — all 8 phases sequentially
- Single Phase — focus on one specific phase
- Single Query — run one specific IR query

**Total: 25+ queries across 8 phases**

---

## Project Structure
OsecQ/
│
├── main.py                    ← Entry point, main menu, startup checks
│
├── core/
│   ├── display.py             ← Colors, banner, tables, menus, live strip
│   ├── runner.py              ← osquery execution engine
│   └── reporter.py            ← Save reports as JSON and TXT
│
├── modules/
│   ├── recon.py               ← Reconnaissance module
│   ├── threat_hunt.py         ← Threat hunting module
│   ├── monitor.py             ← Continuous monitoring module
│   └── incident_response.py   ← Incident response module
│
├── queries/
│   ├── recon.json             ← 20 recon query definitions
│   ├── threat_hunt.json       ← 20 threat hunting query definitions
│   ├── monitor.json           ← 20 monitoring query definitions
│   └── ir.json                ← 25+ IR queries across 8 attack phases
│
└── reports/                   ← Auto-saved investigation reports

---

## Requirements

| Requirement | Version | Install |
|---|---|---|
| Kali Linux | Any | — |
| Python | 3.x | Pre-installed |
| osquery | 5.x+ | See below |
| tabulate | Latest | `pip3 install tabulate` |

---

## Installation

**Step 1 — Install osquery:**

```bash
# Add osquery repository
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 1484120AC4E9F8A1A577AEEE97A80C63C9D8B80B
sudo add-apt-repository 'deb [arch=amd64] https://pkg.osquery.io/deb deb main'
sudo apt update
sudo apt install osquery -y
```

**Step 2 — Clone OsecQ:**

```bash
git clone https://github.com/YOUR_USERNAME/OsecQ.git
cd OsecQ
```

**Step 3 — Install Python dependency:**

```bash
pip3 install tabulate --break-system-packages
```

**Step 4 — Create log directory:**

```bash
sudo mkdir -p /var/log/osquery
sudo chmod 755 /var/log/osquery
```

**Step 5 — Run OsecQ:**

```bash
sudo python3 main.py
```

---

## Usage

```bash
# Always run with sudo for full table visibility
sudo python3 main.py
```

**Main Menu:**
[1]  Reconnaissance          System identity, users, network, disk
[2]  Threat Hunting          Full attack lifecycle — IOC detection
[3]  System Monitor          Live monitoring — snapshot & continuous
[4]  Incident Response       IR queries by MITRE attack phase
[5]  View Reports            Browse saved investigation reports
[6]  About                   Tool info and query statistics
[0]  Exit

**Quick threat hunt from terminal:**

```bash
# Run threat hunting module directly
sudo python3 -c "from modules.threat_hunt import run_quick; run_quick()"
```

**Test banner:**

```bash
sudo python3 -c "from core.display import print_banner; print_banner()"
```

---

## Report System

Every investigation automatically generates:
reports/osecq_recon_20260422_083045.json         ← Structured JSON
reports/osecq_recon_20260422_083045.txt          ← Human readable TXT
reports/osecq_FINDING_20260422_083102.json       ← Critical finding (instant save)

**Critical findings are saved the moment they are detected** — independent of the main report. Evidence is never lost.

---

## Security Coverage
Domain                  Queries    Key Detections
─────────────────────────────────────────────────────────────────
User Accounts              8       Backdoors, UID=0 anomalies
Processes                 12       Web shells, reverse shells
Network                   10       C2 connections, rare ports
File System               10       FIM, SUID, integrity hashes
Persistence Mechanisms     8       Cron, systemd, SSH keys
Privilege Escalation       6       SUID, sudo, docker group
Defense Evasion            6       Rootkits, deleted binaries
Lateral Movement           5       SSH pivoting, credentials
Command & Control          5       Reverse shells, C2 ports
Exfiltration               4       Uploads, archiving, writes
─────────────────────────────────────────────────────────────────
TOTAL                     74+      Across 4 modules

---

## How It Works
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

---

## Key Design Decisions

**Queries in JSON, not Python** — Add, edit, or remove queries without touching any code. The JSON files are the intelligence. The Python is the engine.

**Auto-save everything** — Evidence disappears. Processes get killed, files get deleted. Auto-saving every query result preserves the system state at investigation time.

**Critical findings saved separately** — Web shells, reverse shells, backdoor accounts saved instantly as independent FINDING files. Even if the main report fails, critical evidence is preserved.

**osquery reads from kernel directly** — Cannot be fooled by LD_PRELOAD rootkits that hook userspace tools like ps, netstat, ls. OsecQ sees what the kernel sees.

---

## Limitations

- Requires osquery installed separately
- Event tables (file_events, process_events) require osqueryd daemon
- Local machine only — no remote querying (use Fleet for multi-host)
- No historical session comparison

---

## Future Roadmap

- [ ] YARA scanning module — malware pattern matching
- [ ] Fleet integration — query multiple machines
- [ ] Timeline view — correlate events by timestamp
- [ ] Baseline comparison — detect drift from known-good state
- [ ] HTML report export — browser-viewable reports
- [ ] Slack / email alerting — push critical findings
- [ ] Custom query builder — write and save queries from the UI
- [ ] CVE checker — cross-reference installed packages against CVE database

---

## Contributing

Pull requests welcome. To add queries:

1. Edit the relevant JSON file in `queries/`
2. Add a new object with `name`, `desc`, and `sql` fields
3. Test with `sudo osqueryi "YOUR SQL HERE;"`
4. Submit PR with description of what the query detects

---

## Disclaimer

OsecQ is intended for authorized security testing, incident response, and defensive security operations on systems you own or have explicit permission to investigate. Unauthorized use against systems you do not own is illegal.

---

## Author

**Vishu**
Built during a 10-day osquery learning journey — from zero to advanced.

---

## License

MIT License — free to use, modify, and distribute.

---

<div align="center">

**"Security through intelligent querying."** 🔐

*Built with osquery + Python on Kali Linux*

</div>
