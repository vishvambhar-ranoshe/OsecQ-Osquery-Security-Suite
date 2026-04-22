# modules/monitor.py
# Continuous Monitoring Module — Live System Watch

import json
import os
import time
from datetime import datetime
from core import display as D
from core.runner import run_batch, run_query, check_privileges
from core.reporter import save_report

# ─── Load Queries ─────────────────────────────────────────────────────────────

QUERY_FILE = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    'queries', 'monitor.json'
)

def load_queries():
    with open(QUERY_FILE, 'r') as f:
        data = json.load(f)
    return data['queries']

# ─── Alert Thresholds ─────────────────────────────────────────────────────────

# If these queries return ANY results → alert immediately
ALERT_QUERIES = {
    "Processes in Temp Dirs",
    "Connections to Rare Ports",
    "Zombie Processes",
    "Open Files in Suspicious Paths",
}

def check_alerts(name, results):
    """Check if result triggers an alert."""
    if name in ALERT_QUERIES and results:
        D.critical(f"ALERT — {name} — {len(results)} finding(s)!")
        return True
    return False

# ─── Single Snapshot ──────────────────────────────────────────────────────────

def run_snapshot():
    """Run all monitor queries once and display results."""
    D.print_banner()
    D.print_section("SYSTEM MONITOR — Live Snapshot")
    check_privileges()

    queries = load_queries()
    D.info(f"Running {len(queries)} monitoring queries...")
    print()

    results     = run_batch(queries)
    alert_count = 0

    for item in results:
        D.print_subsection(f"{item['name']}  —  {item['desc']}")

        alerted = check_alerts(item['name'], item['results'])
        if alerted:
            alert_count += 1

        if item['results']:
            D.print_table(item['results'])
        else:
            D.ok("No results.")

        print(f"  {D.c('Time:', D.Color.DIM)} {item['time']}s  "
              f"{D.result_badge(item['count'])}")

    # Summary
    D.print_section("SNAPSHOT SUMMARY")
    D.info(f"Snapshot taken at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    if alert_count > 0:
        D.critical(f"{alert_count} alert(s) triggered — review findings above!")
    else:
        D.ok("All clear — no alerts triggered.")

    # Save report
    print()
    paths = save_report(results, label='monitor_snapshot')
    D.ok(f"JSON report → {paths['json']}")
    D.ok(f"TXT  report → {paths['txt']}")
    D.pause()

# ─── Continuous Watch ─────────────────────────────────────────────────────────

def run_continuous(interval=60):
    """
    Continuously monitor the system at set intervals.
    Runs until user presses Ctrl+C.

    Args:
        interval: seconds between each scan (default 60)
    """
    D.print_banner()
    D.print_section(f"CONTINUOUS MONITOR — Refresh every {interval}s")
    check_privileges()

    # Only run alert-worthy queries in continuous mode
    all_queries = load_queries()
    watch_names = [
        "Active User Sessions",
        "Recently Started Processes",
        "Established Connections",
        "Connections to Rare Ports",
        "Processes in Temp Dirs",
        "Root Processes",
        "Zombie Processes",
        "New Files in /tmp (1h)",
        "Files Modified in /etc (1h)",
        "Cron Jobs Watch",
        "SSH Authorized Keys Watch",
        "Open Files in Suspicious Paths",
    ]
    queries = [q for q in all_queries if q['name'] in watch_names]

    D.info(f"Watching {len(queries)} live indicators...")
    D.warn("Press Ctrl+C to stop monitoring.")
    print()

    cycle    = 0
    history  = {}  # track previous counts per query

    try:
        while True:
            cycle += 1
            now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

            os.system('clear')
            D.print_banner()
            print(f"  {D.c('Cycle:', D.Color.CYAN)} {D.c(str(cycle), D.Color.BOLD)}"
                  f"   {D.c('Time:', D.Color.CYAN)} {D.c(now, D.Color.BOLD)}"
                  f"   {D.c('Interval:', D.Color.CYAN)} {D.c(f'{interval}s', D.Color.BOLD)}")
            print(f"  {D.c('Press Ctrl+C to stop', D.Color.DIM)}")
            print(f"\n{D.c('─' * 70, D.Color.CYAN)}\n")

            alert_count = 0

            for q in queries:
                name    = q['name']
                results = run_query(q['sql'])
                count   = len(results) if results else 0
                prev    = history.get(name, 0)

                # Detect changes from previous cycle
                if count != prev and prev > 0:
                    delta = count - prev
                    tag   = (D.c(f'▲ +{delta}', D.Color.RED)
                             if delta > 0
                             else D.c(f'▼ {delta}', D.Color.GREEN))
                else:
                    tag = D.c('→ same', D.Color.DIM)

                # Alert check
                alerted = check_alerts(name, results)
                if alerted:
                    alert_count += 1

                # Status line
                badge  = D.result_badge(count)
                change = f"  {tag}" if cycle > 1 else ''
                print(f"  {D.c('▶', D.Color.CYAN)}  "
                      f"{D.Color.BOLD}{name:<40}{D.Color.RESET}"
                      f"  {badge}{change}")

                # Show table only if results exist and alert triggered
                if alerted and results:
                    D.print_table(results)

                history[name] = count

            # Footer
            print(f"\n{D.c('─' * 70, D.Color.CYAN)}")
            if alert_count > 0:
                D.critical(f"{alert_count} active alert(s) this cycle!")
            else:
                print(f"  {D.c('✔', D.Color.GREEN)}  "
                      f"{D.c('All clear this cycle.', D.Color.GREEN)}")

            print(f"\n  {D.c(f'Next refresh in {interval}s...', D.Color.DIM)}")
            time.sleep(interval)

    except KeyboardInterrupt:
        print()
        D.warn("Monitoring stopped by user.")
        D.info(f"Total cycles completed: {cycle}")
        D.pause()

# ─── Run Single Query ─────────────────────────────────────────────────────────

def run_single(index):
    queries = load_queries()
    if index < 0 or index >= len(queries):
        D.error("Invalid query index.")
        return

    q = queries[index]
    D.print_subsection(f"{q['name']}  —  {q['desc']}")
    D.running(q['name'])

    results = run_query(q['sql'])
    D.done()

    check_alerts(q['name'], results)
    D.print_table(results)
    print(f"  {D.result_badge(len(results) if results else 0)}")

# ─── Interactive Menu ─────────────────────────────────────────────────────────

def menu():
    queries = load_queries()

    while True:
        D.print_banner()
        D.print_section("MONITOR MODULE")
        check_privileges()

        options = [
            ('S', 'Snapshot',          'Run all monitor queries once'),
            ('C', 'Continuous Watch',  'Live watch — refresh every 60s'),
            ('F', 'Fast Watch',        'Live watch — refresh every 30s'),
        ]
        for i, q in enumerate(queries, start=1):
            tag = ' ⚠' if q['name'] in ALERT_QUERIES else ''
            options.append((str(i), q['name'] + tag, q['desc']))

        D.print_menu("Select Monitor Mode", options)
        D.warn("⚠ = Alert-enabled query")
        choice = D.prompt()

        if choice == '0':
            break
        elif choice.upper() == 'S':
            run_snapshot()
        elif choice.upper() == 'C':
            run_continuous(interval=60)
        elif choice.upper() == 'F':
            run_continuous(interval=30)
        else:
            try:
                idx = int(choice) - 1
                D.print_banner()
                run_single(idx)
                D.pause()
            except ValueError:
                D.error("Invalid choice. Try again.")
                D.pause()
