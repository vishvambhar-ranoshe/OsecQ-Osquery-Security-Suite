# core/display.py
# OsecQ — Osquery Security Suite
# Display engine: banner, colors, tables, menus, live info strip

import os
import re
import platform
import subprocess
import json
from datetime import datetime
from tabulate import tabulate

# ─── ANSI Color Codes ────────────────────────────────────────────────────────

class Color:
    RED     = '\033[91m'
    GREEN   = '\033[92m'
    YELLOW  = '\033[93m'
    BLUE    = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN    = '\033[96m'
    WHITE   = '\033[97m'
    BOLD    = '\033[1m'
    DIM     = '\033[2m'
    RESET   = '\033[0m'

def c(text, color):
    return f"{color}{text}{Color.RESET}"

# ─── ANSI Strip Helper ────────────────────────────────────────────────────────

def _strip_ansi(text):
    return re.sub(r'\033\[[0-9;]*m', '', text)

# ─── Live System Data ────────────────────────────────────────────────────────

def _get_live_data():
    data = {}

    data['hostname'] = os.uname().nodename
    data['user']     = os.environ.get('USER',
                       os.environ.get('LOGNAME', 'unknown'))
    data['arch']     = platform.machine()

    try:
        raw = open('/proc/uptime').read().split()[0]
        hrs = float(raw) / 3600
        if hrs < 1:
            data['uptime'] = f"{int(hrs*60)}m"
        elif hrs < 24:
            data['uptime'] = f"{hrs:.1f}h"
        else:
            data['uptime'] = f"{int(hrs//24)}d {int(hrs%24)}h"
    except Exception:
        data['uptime'] = 'N/A'

    try:
        with open('/etc/os-release') as f:
            for line in f:
                if line.startswith('PRETTY_NAME'):
                    data['os'] = line.split('=')[1].strip().strip('"')
                    break
    except Exception:
        data['os'] = platform.system()

    data['kernel']  = platform.release()[:30]
    data['is_root'] = os.geteuid() == 0
    data['priv']    = 'ROOT' if data['is_root'] else 'USER'

    def run_oq(sql):
        r = subprocess.run(
            ['osqueryi', '--json',
             '--disable_extensions',
             '--config_path', '/dev/null',
             '--disable_logging', sql],
            capture_output=True, text=True, timeout=5
        )
        clean = '\n'.join([
            l for l in r.stdout.splitlines()
            if not l.startswith('W') and not l.startswith('E')
        ]).strip()
        return json.loads(clean) if clean else []

    try:
        result = run_oq('SELECT pid FROM osquery_info;')
        data['osquery'] = 'ONLINE' if result else 'OFFLINE'
    except Exception:
        data['osquery'] = 'OFFLINE'

    try:
        r = subprocess.run(['pgrep', '-x', 'osqueryd'],
                           capture_output=True, text=True)
        data['daemon'] = 'ACTIVE' if r.returncode == 0 else 'INACTIVE'
    except Exception:
        data['daemon'] = 'UNKNOWN'

    try:
        result = run_oq(
            'SELECT COUNT(*) AS enc FROM disk_encryption WHERE encrypted=1;')
        data['encryption'] = 'YES' if result and int(
            result[0].get('enc', 0)) > 0 else 'NO'
    except Exception:
        data['encryption'] = 'N/A'

    try:
        r = subprocess.run(['ufw', 'status'],
                           capture_output=True, text=True)
        data['firewall'] = ('ACTIVE'
                            if 'active' in r.stdout.lower()
                            else 'INACTIVE')
    except Exception:
        data['firewall'] = 'N/A'

    try:
        data['processes'] = len([
            p for p in os.listdir('/proc') if p.isdigit()
        ])
    except Exception:
        data['processes'] = 0

    try:
        result = run_oq(
            'SELECT COUNT(*) AS cnt FROM listening_ports WHERE protocol=6;')
        data['ports'] = result[0].get('cnt', '?') if result else '?'
    except Exception:
        data['ports'] = '?'

    try:
        result = run_oq(
            "SELECT COUNT(*) AS cnt FROM process_open_sockets "
            "WHERE state='ESTABLISHED' AND family=2 "
            "AND remote_address!='127.0.0.1';")
        data['connections'] = result[0].get('cnt', '?') if result else '?'
    except Exception:
        data['connections'] = '?'

    try:
        result = run_oq(
            "SELECT COUNT(*) AS cnt FROM logged_in_users WHERE type='user';")
        data['sessions'] = result[0].get('cnt', '?') if result else '?'
    except Exception:
        data['sessions'] = '?'

    try:
        reports_dir = os.path.join(
            os.path.dirname(os.path.dirname(__file__)), 'reports')
        all_files        = (os.listdir(reports_dir)
                            if os.path.exists(reports_dir) else [])
        data['reports']  = len([f for f in all_files
                                 if f.endswith('.json')
                                 and 'FINDING' not in f])
        data['findings'] = len([f for f in all_files if 'FINDING' in f])
    except Exception:
        data['reports']  = 0
        data['findings'] = 0

    data['session_time'] = datetime.now().strftime('%H:%M:%S')
    data['full_time']    = datetime.now().strftime('%Y-%m-%d  %H:%M:%S')

    return data

# ─── Main Banner ──────────────────────────────────────────────────────────────

def print_banner():
    os.system('clear')

    art = r"""
  ██████╗ ███████╗███████╗ ██████╗ ██████╗
 ██╔═══██╗██╔════╝██╔════╝██╔════╝██╔═══██╗
 ██║   ██║███████╗█████╗  ██║     ██║   ██║
 ██║   ██║╚════██║██╔══╝  ██║     ██║▄▄ ██║
 ╚██████╔╝███████║███████╗╚██████╗╚██████╔╝
  ╚═════╝ ╚══════╝╚══════╝ ╚═════╝ ╚══▀▀═╝
"""
    print(f"{Color.CYAN}{Color.BOLD}{art}{Color.RESET}", end='')
    print(
        f"  {c('[ Osquery Security Suite ]', Color.MAGENTA + Color.BOLD)}"
        f"  {c('Built by Vishu', Color.DIM)}"
        f"  {c('|', Color.DIM)}"
        f"  {c('Powered by Osquery', Color.DIM)}\n"
    )

    try:
        data    = _get_live_data()
        finds   = data.get('findings',    0)
        conn    = str(data.get('connections', '0'))
        priv    = data.get('priv',        'USER')
        host    = data.get('hostname',    'unknown')
        oq      = data.get('osquery',     'OFFLINE')
        oq_c    = Color.GREEN if oq == 'ONLINE' else Color.YELLOW
        now_str = data.get('full_time',   '')

        if finds > 0:
            summary = (
                f"{c('⚠', Color.RED)}  "
                f"{c(priv + ' session', Color.YELLOW)} on "
                f"{c(host, Color.CYAN)} · "
                f"osquery {c(oq.lower(), oq_c)} · "
                f"{c(str(finds) + ' finding(s) pending review', Color.RED + Color.BOLD)} · "
                f"{c(now_str, Color.DIM)}"
            )
        elif conn not in ('0', '?', ''):
            summary = (
                f"{c('●', Color.YELLOW)}  "
                f"{c(priv + ' session', Color.GREEN)} on "
                f"{c(host, Color.CYAN)} · "
                f"osquery {c(oq.lower(), oq_c)} · "
                f"{c(conn + ' active connection(s) — monitor network', Color.YELLOW)} · "
                f"{c(now_str, Color.DIM)}"
            )
        else:
            summary = (
                f"{c('✔', Color.GREEN)}  "
                f"Clean baseline on "
                f"{c(host, Color.CYAN)} · "
                f"No findings · "
                f"{c('Good time to start a threat hunt', Color.GREEN)} · "
                f"{c(now_str, Color.DIM)}"
            )

        print(f"  {summary}\n")

    except Exception:
        print(
            f"  {c('Engine:', Color.DIM)} {c('osquery + Python 3', Color.CYAN)}"
            f"   {c('Time:', Color.DIM)} "
            f"{c(datetime.now().strftime('%Y-%m-%d  %H:%M:%S'), Color.CYAN)}\n"
        )

# ─── Section Headers ──────────────────────────────────────────────────────────

def print_section(title):
    print(f"\n{Color.CYAN}{Color.BOLD}{'─' * 60}{Color.RESET}")
    print(f"{Color.CYAN}{Color.BOLD}  ⚡  {title}{Color.RESET}")
    print(f"{Color.CYAN}{Color.BOLD}{'─' * 60}{Color.RESET}\n")

def print_subsection(title):
    print(f"\n{Color.YELLOW}{Color.BOLD}  ▶  {title}{Color.RESET}")
    print(f"{Color.DIM}  {'─' * 50}{Color.RESET}")

# ─── Status Messages ──────────────────────────────────────────────────────────

def ok(msg):
    print(f"  {c('✔', Color.GREEN)}  {msg}")

def warn(msg):
    print(f"  {c('⚠', Color.YELLOW)}  {c(msg, Color.YELLOW)}")

def error(msg):
    print(f"  {c('✖', Color.RED)}  {c(msg, Color.RED)}")

def info(msg):
    print(f"  {c('ℹ', Color.BLUE)}  {msg}")

def critical(msg):
    print(f"\n  {c('🔴 CRITICAL', Color.RED)}"
          f"{Color.BOLD}  {msg}{Color.RESET}\n")

def finding(msg):
    print(f"  {c('🎯 FINDING', Color.MAGENTA)}"
          f"{Color.BOLD}  {msg}{Color.RESET}")

# ─── Table Renderer ───────────────────────────────────────────────────────────

def print_table(data, headers=None):
    if not data:
        warn("No results returned.")
        return

    if isinstance(data[0], dict):
        if headers:
            rows = [[row.get(h, '') for h in headers] for row in data]
            cols = headers
        else:
            cols = list(data[0].keys())
            rows = [[row.get(col, '') for col in cols] for row in data]
    else:
        rows = data
        cols = headers or []

    print()
    print(tabulate(rows, headers=cols, tablefmt="rounded_outline"))
    print(c(f"\n  {len(rows)} row(s) returned.", Color.DIM))

# ─── Result Badge ─────────────────────────────────────────────────────────────

def result_badge(count, label="results"):
    if count == 0:
        return c(f"[{count} {label}]", Color.GREEN)
    elif count <= 3:
        return c(f"[{count} {label}]", Color.YELLOW)
    else:
        return c(f"[{count} {label}]", Color.RED)

# ─── Menu Renderer ────────────────────────────────────────────────────────────

def print_menu(title, options):
    print_section(title)
    for key, label, desc in options:
        print(f"  {c(f'[{key}]', Color.CYAN)}  "
              f"{Color.BOLD}{label:<32}{Color.RESET}  "
              f"{c(desc, Color.DIM)}")
    print()
    print(f"  {c('[0]', Color.RED)}  "
          f"{Color.BOLD}{'Back / Exit':<32}{Color.RESET}")
    print()

# ─── Input Prompt ─────────────────────────────────────────────────────────────

def prompt(msg="Select option"):
    try:
        return input(
            f"\n  {c('OsecQ', Color.CYAN)}"
            f"{c(' ⚔ ', Color.MAGENTA)}"
            f"{msg}: "
        ).strip()
    except KeyboardInterrupt:
        print()
        return '0'

# ─── Spinner ──────────────────────────────────────────────────────────────────

def running(msg):
    print(f"  {c('⟳', Color.CYAN)}  {msg}...", end='', flush=True)

def done():
    print(f"\r  {c('✔', Color.GREEN)}  Done.           ")

# ─── Pause ────────────────────────────────────────────────────────────────────

def pause():
    try:
        input(f"\n  {c('Press ENTER to continue...', Color.DIM)}")
    except KeyboardInterrupt:
        pass
