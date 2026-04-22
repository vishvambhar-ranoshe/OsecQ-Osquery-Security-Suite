#!/usr/bin/env python3
# main.py
# OsecQ — Osquery Security Suite
# Entry point — Main Menu
# Built by Vishu | Kali Linux

import sys
import os

# ─── Ensure project root is in path ──────────────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core import display as D
from core.runner import health_check, check_privileges
from core.reporter import list_reports
from modules import recon
from modules import threat_hunt
from modules import monitor
from modules import incident_response

# ─── Startup Health Check ─────────────────────────────────────────────────────

def startup_check():
    """Verify osquery is installed and working before launch."""
    D.print_banner()
    D.print_section("STARTUP — System Check")

    D.running("Checking osquery installation")
    health = health_check()
    D.done()

    if health['ok']:
        D.ok(f"osquery found      → {health['path']}")
        D.ok(f"osquery version    → {health['version']}")
    else:
        D.error(f"osquery check failed: {health['error']}")
        D.error("Please install osquery: sudo apt install osquery")
        D.error("Or visit: https://osquery.io/downloads")
        print()
        sys.exit(1)

    # Privilege check
    check_privileges()

    # Reports directory
    os.makedirs('reports', exist_ok=True)
    D.ok("Reports directory  → ready")

    print()
    D.ok("All checks passed. Starting OsecQ...")
    import time
    time.sleep(1)

# ─── Reports Viewer ───────────────────────────────────────────────────────────

def view_reports():
    D.print_banner()
    D.print_section("SAVED REPORTS")

    reports = list_reports()

    if not reports:
        D.warn("No reports found in reports/ directory.")
        D.info("Run any module to generate reports.")
        D.pause()
        return

    D.info(f"Found {len(reports)} report(s):\n")

    for i, r in enumerate(reports, start=1):
        ext   = '.json' if r['name'].endswith('.json') else '.txt'
        color = D.Color.CYAN if ext == '.json' else D.Color.YELLOW
        print(f"  {D.c(f'[{i}]', color)}  "
              f"{D.Color.BOLD}{r['name']:<55}{D.Color.RESET}  "
              f"{D.c(str(r['size_kb'])+'KB', D.Color.DIM)}  "
              f"{D.c(r['modified'], D.Color.DIM)}")

    print()
    D.info("Reports are saved in: reports/")
    D.info("Open with: cat reports/<filename>")
    D.info("JSON view: python3 -m json.tool reports/<filename>")
    D.pause()

# ─── About Screen ─────────────────────────────────────────────────────────────

def show_about():
    D.print_banner()
    D.print_section("ABOUT OsecQ")

    about = f"""
  {D.c('Tool     :', D.Color.CYAN)}  OsecQ — Osquery Security Suite
  {D.c('Author   :', D.Color.CYAN)}  Vishu
  {D.c('Platform :', D.Color.CYAN)}  Kali Linux
  {D.c('Engine   :', D.Color.CYAN)}  osquery + Python 3
  {D.c('Purpose  :', D.Color.CYAN)}  Endpoint security monitoring & threat hunting

  {D.c('Modules  :', D.Color.CYAN)}
    {D.c('1.', D.Color.YELLOW)} Reconnaissance      — System & network identity
    {D.c('2.', D.Color.YELLOW)} Threat Hunting      — Full attack lifecycle detection
    {D.c('3.', D.Color.YELLOW)} System Monitor      — Live continuous monitoring
    {D.c('4.', D.Color.YELLOW)} Incident Response   — IR by attack phase (MITRE)

  {D.c('Reports  :', D.Color.CYAN)}
     All results auto-saved as JSON + TXT
     Location: ./reports/
     Critical findings saved instantly

  {D.c('Queries  :', D.Color.CYAN)}
     {D.c('recon.json',       D.Color.DIM)}       — 20 recon queries
     {D.c('threat_hunt.json', D.Color.DIM)}  — 20 hunting queries
     {D.c('monitor.json',     D.Color.DIM)}     — 20 monitor queries
     {D.c('ir.json',          D.Color.DIM)}           — 8 phases, 25+ IR queries

  {D.c('Usage    :', D.Color.CYAN)}
     sudo python3 main.py
"""
    print(about)
    D.pause()

# ─── Main Menu ────────────────────────────────────────────────────────────────

def main_menu():
    while True:
        D.print_banner()

        options = [
            ('1', 'Reconnaissance',     'System identity, users, network, disk'),
            ('2', 'Threat Hunting',     'Full attack lifecycle — IOC detection'),
            ('3', 'System Monitor',     'Live monitoring — snapshot & continuous'),
            ('4', 'Incident Response',  'IR queries by MITRE attack phase'),
            ('5', 'View Reports',       'Browse saved investigation reports'),
            ('6', 'About',              'Tool info and query statistics'),
        ]

        D.print_menu("MAIN MENU — OsecQ Security Suite", options)

        # Quick status strip
        from core.runner import is_root
        root_status = (D.c('ROOT ✔', D.Color.GREEN)
                       if is_root()
                       else D.c('NOT ROOT ⚠', D.Color.YELLOW))
        print(f"  {D.c('Privilege:', D.Color.DIM)} {root_status}"
              f"   {D.c('Reports:', D.Color.DIM)} "
              f"{D.c(str(len(list_reports())), D.Color.CYAN)} saved")
        print()

        choice = D.prompt("Main Menu")

        if choice == '0':
            D.print_banner()
            D.print_section("GOODBYE")
            D.ok("OsecQ session ended.")
            D.info("Stay sharp. Hunt threats. 🔐")
            print()
            sys.exit(0)

        elif choice == '1':
            recon.menu()

        elif choice == '2':
            threat_hunt.menu()

        elif choice == '3':
            monitor.menu()

        elif choice == '4':
            incident_response.menu()

        elif choice == '5':
            view_reports()

        elif choice == '6':
            show_about()

        else:
            D.error("Invalid choice. Please select 1-6 or 0 to exit.")
            D.pause()

# ─── Entry Point ──────────────────────────────────────────────────────────────

if __name__ == '__main__':
    try:
        startup_check()
        main_menu()
    except KeyboardInterrupt:
        print()
        D.warn("Interrupted by user. Exiting OsecQ.")
        print()
        sys.exit(0)
