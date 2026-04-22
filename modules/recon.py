# modules/recon.py
# System Reconnaissance Module

import json
import os
from core import display as D
from core.runner import run_batch, check_privileges
from core.reporter import save_report

# ─── Load Queries ─────────────────────────────────────────────────────────────

QUERY_FILE = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    'queries', 'recon.json'
)

def load_queries():
    with open(QUERY_FILE, 'r') as f:
        data = json.load(f)
    return data['queries']

# ─── Run All Recon ────────────────────────────────────────────────────────────

def run_all():
    D.print_banner()
    D.print_section("SYSTEM RECONNAISSANCE — Full Scan")
    check_privileges()

    queries = load_queries()
    D.info(f"Loaded {len(queries)} reconnaissance queries")
    print()

    results = run_batch(queries)

    # Display results
    for item in results:
        D.print_subsection(f"{item['name']}  —  {item['desc']}")
        D.print_table(item['results'])
        print(f"  {D.c('Time:', D.Color.DIM)} {item['time']}s  "
              f"{D.result_badge(item['count'])}")

    # Save report
    print()
    paths = save_report(results, label='recon')
    D.ok(f"JSON report saved → {paths['json']}")
    D.ok(f"TXT  report saved → {paths['txt']}")
    D.pause()

# ─── Run Single Query ─────────────────────────────────────────────────────────

def run_single(index):
    queries  = load_queries()
    if index < 0 or index >= len(queries):
        D.error("Invalid query index.")
        return

    q = queries[index]
    D.print_subsection(f"{q['name']}  —  {q['desc']}")
    D.running(q['name'])

    from core.runner import run_query
    results = run_query(q['sql'])

    D.done()
    D.print_table(results)
    print(f"  {D.c('Time:', D.Color.DIM)} query complete  "
          f"{D.result_badge(len(results) if results else 0)}")

# ─── Interactive Menu ─────────────────────────────────────────────────────────

def menu():
    queries = load_queries()

    while True:
        D.print_banner()
        D.print_section("RECONNAISSANCE MODULE")
        check_privileges()

        # Build menu options
        options = [('A', 'Run ALL Recon Queries', 'Full system reconnaissance scan')]
        for i, q in enumerate(queries, start=1):
            options.append((str(i), q['name'], q['desc']))

        D.print_menu("Select Recon Query", options)
        choice = D.prompt()

        if choice == '0':
            break
        elif choice.upper() == 'A':
            run_all()
        else:
            try:
                idx = int(choice) - 1
                D.print_banner()
                run_single(idx)
                D.pause()
            except ValueError:
                D.error("Invalid choice. Try again.")
                D.pause()
