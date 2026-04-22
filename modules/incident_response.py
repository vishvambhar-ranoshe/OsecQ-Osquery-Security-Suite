# modules/incident_response.py
# Incident Response Module — Organized by Attack Phase

import json
import os
from datetime import datetime
from core import display as D
from core.runner import run_batch, run_query, check_privileges
from core.reporter import save_report, save_finding

# ─── Load Queries ─────────────────────────────────────────────────────────────

QUERY_FILE = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    'queries', 'ir.json'
)

def load_phases():
    with open(QUERY_FILE, 'r') as f:
        data = json.load(f)
    return data['phases']

# ─── Flatten All Queries ──────────────────────────────────────────────────────

def flatten_queries(phases):
    """Return all queries as a flat list with phase tag."""
    flat = []
    for phase in phases:
        for q in phase['queries']:
            q['phase'] = phase['phase']
            flat.append(q)
    return flat

# ─── Critical IR Queries ──────────────────────────────────────────────────────

CRITICAL_IR = {
    "Shell Spawned by Server",
    "Reverse Shell Candidates",
    "Backdoor Root Accounts",
    "LD_PRELOAD Injection",
    "Deleted But Running Binaries",
    "Connections to C2 Ports",
}

# ─── Run Full IR Investigation ────────────────────────────────────────────────

def run_full_ir():
    """Run all IR queries across all attack phases."""
    D.print_banner()
    D.print_section("INCIDENT RESPONSE — Full Investigation")
    check_privileges()

    phases      = load_phases()
    all_results = []
    total_found = 0
    crit_count  = 0

    D.info(f"Running IR queries across {len(phases)} attack phases...")
    D.warn("This is a comprehensive investigation — may take 1-2 minutes.")
    print()

    for phase in phases:
        D.print_section(phase['phase'])
        queries = phase['queries']
        results = run_batch(queries)

        for item in results:
            item['phase'] = phase['phase']
            all_results.append(item)

            D.print_subsection(f"{item['name']}  —  {item['desc']}")

            if item['name'] in CRITICAL_IR and item['results']:
                crit_count += 1
                D.critical(f"{item['name']} — {item['count']} finding(s)!")
                save_finding(
                    title=item['name'],
                    description=item['desc'],
                    data=item['results']
                )

            if item['results']:
                total_found += item['count']
                D.print_table(item['results'])
            else:
                D.ok("Clean.")

            print(f"  {D.c('Time:', D.Color.DIM)} {item['time']}s  "
                  f"{D.result_badge(item['count'])}")

    # ── IR Summary ────────────────────────────────────────────────────────────
    D.print_section("INVESTIGATION SUMMARY")
    print(f"  {D.c('Timestamp  :', D.Color.DIM)} "
          f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  {D.c('Phases     :', D.Color.DIM)} {len(phases)}")
    print(f"  {D.c('Queries Run:', D.Color.DIM)} {len(all_results)}")
    print(f"  {D.c('Total Hits :', D.Color.DIM)} {total_found}")
    print()

    if crit_count > 0:
        D.critical(f"{crit_count} CRITICAL finding(s) detected!")
        D.warn("Check reports/ directory for saved finding files.")
    else:
        D.ok("No critical findings detected.")

    # Save full IR report
    print()
    paths = save_report(all_results, label='incident_response')
    D.ok(f"JSON report → {paths['json']}")
    D.ok(f"TXT  report → {paths['txt']}")
    D.pause()

# ─── Run Single Phase ─────────────────────────────────────────────────────────

def run_phase(phase_index):
    """Run all queries for a single attack phase."""
    phases = load_phases()

    if phase_index < 0 or phase_index >= len(phases):
        D.error("Invalid phase index.")
        return

    phase = phases[phase_index]
    D.print_banner()
    D.print_section(f"IR — {phase['phase']}")
    check_privileges()

    queries = phase['queries']
    D.info(f"Running {len(queries)} queries for this phase...")
    print()

    results    = run_batch(queries)
    phase_hits = 0

    for item in results:
        D.print_subsection(f"{item['name']}  —  {item['desc']}")

        if item['name'] in CRITICAL_IR and item['results']:
            D.critical(f"{item['name']} — {item['count']} finding(s)!")
            save_finding(
                title=item['name'],
                description=item['desc'],
                data=item['results']
            )

        if item['results']:
            phase_hits += item['count']
            D.print_table(item['results'])
        else:
            D.ok("Clean.")

        print(f"  {D.c('Time:', D.Color.DIM)} {item['time']}s  "
              f"{D.result_badge(item['count'])}")

    print()
    D.info(f"Phase complete. Total findings: {phase_hits}")

    # Save phase report
    paths = save_report(results, label=f"ir_phase_{phase_index+1}")
    D.ok(f"Report saved → {paths['json']}")
    D.pause()

# ─── Run Single Query ─────────────────────────────────────────────────────────

def run_single(phase_index, query_index):
    phases = load_phases()
    if phase_index < 0 or phase_index >= len(phases):
        D.error("Invalid phase.")
        return

    queries = phases[phase_index]['queries']
    if query_index < 0 or query_index >= len(queries):
        D.error("Invalid query.")
        return

    q = queries[query_index]
    D.print_subsection(f"{q['name']}  —  {q['desc']}")
    D.running(q['name'])

    results = run_query(q['sql'])
    D.done()

    if q['name'] in CRITICAL_IR and results:
        D.critical(f"{q['name']} — {len(results)} finding(s)!")
        save_finding(
            title=q['name'],
            description=q['desc'],
            data=results
        )

    D.print_table(results)
    print(f"  {D.result_badge(len(results) if results else 0)}")

# ─── Interactive Menu ─────────────────────────────────────────────────────────

def menu():
    phases = load_phases()

    while True:
        D.print_banner()
        D.print_section("INCIDENT RESPONSE MODULE")
        check_privileges()

        # Top level — choose phase or run all
        options = [
            ('A', 'Full IR Investigation', 'Run ALL phases — complete investigation'),
        ]
        for i, phase in enumerate(phases, start=1):
            q_count = len(phase['queries'])
            options.append((
                str(i),
                phase['phase'],
                f"{q_count} queries"
            ))

        D.print_menu("Select IR Phase", options)
        choice = D.prompt()

        if choice == '0':
            break
        elif choice.upper() == 'A':
            run_full_ir()
        else:
            try:
                phase_idx = int(choice) - 1
                if phase_idx < 0 or phase_idx >= len(phases):
                    D.error("Invalid choice.")
                    D.pause()
                    continue

                # Phase submenu
                phase   = phases[phase_idx]
                queries = phase['queries']

                while True:
                    D.print_banner()
                    D.print_section(phase['phase'])

                    sub_options = [
                        ('A', 'Run ALL queries in this phase', '')
                    ]
                    for j, q in enumerate(queries, start=1):
                        tag = ' 🔴' if q['name'] in CRITICAL_IR else ''
                        sub_options.append((str(j), q['name'] + tag, q['desc']))

                    D.print_menu(f"Phase: {phase['phase']}", sub_options)
                    D.warn("🔴 = Critical IR query")
                    sub_choice = D.prompt()

                    if sub_choice == '0':
                        break
                    elif sub_choice.upper() == 'A':
                        run_phase(phase_idx)
                    else:
                        try:
                            q_idx = int(sub_choice) - 1
                            D.print_banner()
                            run_single(phase_idx, q_idx)
                            D.pause()
                        except ValueError:
                            D.error("Invalid choice.")
                            D.pause()

            except ValueError:
                D.error("Invalid choice. Try again.")
                D.pause()
