# modules/threat_hunt.py
# Threat Hunting Module — Full Attack Lifecycle Detection

import json
import os
from core import display as D
from core.runner import run_batch, run_query, check_privileges
from core.reporter import save_report, save_finding

# ─── Load Queries ─────────────────────────────────────────────────────────────

QUERY_FILE = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    'queries', 'threat_hunt.json'
)

def load_queries():
    with open(QUERY_FILE, 'r') as f:
        data = json.load(f)
    return data['queries']

# ─── Critical Finding Check ───────────────────────────────────────────────────

CRITICAL_QUERIES = {
    "Backdoor Root Accounts",
    "Web Shell Detection",
    "Reverse Shell Candidates",
    "LD_PRELOAD Injection",
    "Deleted But Running Binaries",
}

def check_critical(name, results):
    """Fire alert if a critical query returns results."""
    if name in CRITICAL_QUERIES and results:
        D.critical(f"{name} — {len(results)} finding(s) detected!")
        path = save_finding(
            title=name,
            description=f"Critical threat hunting query returned {len(results)} result(s)",
            data=results
        )
        D.warn(f"Finding saved → {path}")
        return True
    return False

# ─── Run Full Hunt ────────────────────────────────────────────────────────────

def run_all():
    D.print_banner()
    D.print_section("THREAT HUNTING — Full Attack Lifecycle Scan")
    check_privileges()

    queries = load_queries()
    D.info(f"Loaded {len(queries)} threat hunting queries")
    D.warn("Critical findings will be flagged and auto-saved.")
    print()

    results = run_batch(queries)

    critical_count = 0
    finding_count  = 0

    for item in results:
        D.print_subsection(f"{item['name']}  —  {item['desc']}")

        # Check for critical findings first
        is_critical = check_critical(item['name'], item['results'])
        if is_critical:
            critical_count += 1

        # Display results
        if item['results']:
            finding_count += item['count']
            D.print_table(item['results'])
        else:
            D.ok("Clean — no findings.")

        print(f"  {D.c('Time:', D.Color.DIM)} {item['time']}s  "
              f"{D.result_badge(item['count'])}")

    # Summary
    D.print_section("HUNT SUMMARY")
    if critical_count > 0:
        D.critical(f"{critical_count} CRITICAL queries returned results!")
    else:
        D.ok("No critical findings detected.")

    D.info(f"Total findings across all queries: {finding_count}")

    # Save full report
    print()
    paths = save_report(results, label='threat_hunt')
    D.ok(f"JSON report saved → {paths['json']}")
    D.ok(f"TXT  report saved → {paths['txt']}")
    D.pause()

# ─── Quick Hunt — Critical Only ───────────────────────────────────────────────

def run_quick():
    """Run only the critical detection queries — fast triage."""
    D.print_banner()
    D.print_section("QUICK HUNT — Critical Detections Only")
    check_privileges()

    queries  = load_queries()
    critical = [q for q in queries if q['name'] in CRITICAL_QUERIES]

    D.info(f"Running {len(critical)} critical detection queries...")
    print()

    results      = run_batch(critical)
    found_any    = False

    for item in results:
        D.print_subsection(item['name'])
        if item['results']:
            found_any = True
            D.critical(f"{item['count']} finding(s)!")
            D.print_table(item['results'])
            save_finding(
                title=item['name'],
                description=item['desc'],
                data=item['results']
            )
        else:
            D.ok("Clean.")

    print()
    if found_any:
        D.critical("SYSTEM MAY BE COMPROMISED — Review findings above!")
    else:
        D.ok("Quick hunt complete — No critical findings detected.")

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

    check_critical(q['name'], results)
    D.print_table(results)
    print(f"  {D.result_badge(len(results) if results else 0)}")

# ─── Interactive Menu ─────────────────────────────────────────────────────────

def menu():
    queries = load_queries()

    while True:
        D.print_banner()
        D.print_section("THREAT HUNTING MODULE")
        check_privileges()

        options = [
            ('A', 'Run ALL Hunt Queries',    'Full attack lifecycle scan'),
            ('Q', 'Quick Hunt',              'Critical detections only — fast triage'),
        ]
        for i, q in enumerate(queries, start=1):
            tag = ' 🔴' if q['name'] in CRITICAL_QUERIES else ''
            options.append((str(i), q['name'] + tag, q['desc']))

        D.print_menu("Select Hunt Query", options)
        D.warn("🔴 = Critical detection query")
        choice = D.prompt()

        if choice == '0':
            break
        elif choice.upper() == 'A':
            run_all()
        elif choice.upper() == 'Q':
            run_quick()
        else:
            try:
                idx = int(choice) - 1
                D.print_banner()
                run_single(idx)
                D.pause()
            except ValueError:
                D.error("Invalid choice. Try again.")
                D.pause()
