# core/runner.py
# osquery execution engine — all queries run through here

import subprocess
import json
import os
from datetime import datetime
from core.display import ok, warn, error, running, done

# ─── osquery Binary Detection ────────────────────────────────────────────────

def find_osqueryi():
    """Find osqueryi binary on the system."""
    locations = [
        '/usr/bin/osqueryi',
        '/usr/local/bin/osqueryi',
        '/opt/osquery/bin/osqueryi',
    ]
    for loc in locations:
        if os.path.exists(loc):
            return loc
    # fallback: try which
    try:
        result = subprocess.run(['which', 'osqueryi'],
                                capture_output=True, text=True)
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    return None

OSQUERYI = find_osqueryi()

# ─── Core Query Runner ────────────────────────────────────────────────────────

def run_query(sql, database_path=None, timeout=30):
    """
    Execute a single osquery SQL statement.

    Args:
        sql           : SQL query string
        database_path : path to osqueryd RocksDB (for event tables)
        timeout       : max seconds to wait

    Returns:
        list of dicts on success
        empty list on no results
        None on error
    """
    if not OSQUERYI:
        error("osqueryi not found. Is osquery installed?")
        return None

    cmd = [OSQUERYI, '--json']

    if database_path and os.path.exists(database_path):
        cmd += ['--database_path', database_path]

    cmd.append(sql)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )

        if result.returncode != 0 and result.stderr:
            error(f"osquery error: {result.stderr.strip()}")
            return None

        output = result.stdout.strip()
        if not output:
            return []

        data = json.loads(output)
        return data

    except subprocess.TimeoutExpired:
        error(f"Query timed out after {timeout}s")
        return None
    except json.JSONDecodeError as e:
        error(f"Failed to parse osquery output: {e}")
        return None
    except Exception as e:
        error(f"Unexpected error: {e}")
        return None

# ─── Named Query Runner ───────────────────────────────────────────────────────

def run_named_query(name, sql, database_path=None, show_spinner=True):
    """
    Run a query with a label and spinner.

    Returns:
        (name, results) tuple
    """
    if show_spinner:
        running(name)

    results = run_query(sql, database_path=database_path)

    if show_spinner:
        done()

    return name, results

# ─── Batch Query Runner ───────────────────────────────────────────────────────

def run_batch(queries, database_path=None):
    """
    Run multiple queries.

    Args:
        queries: list of dicts with keys:
                 'name'  → display label
                 'sql'   → SQL string
                 'desc'  → description (optional)

    Returns:
        list of dicts:
        {
          'name':    query name,
          'desc':    description,
          'sql':     original sql,
          'results': list of dicts or None,
          'count':   int,
          'time':    execution time in seconds
        }
    """
    batch_results = []

    for q in queries:
        name = q.get('name', 'unnamed')
        sql  = q.get('sql',  '')
        desc = q.get('desc', '')

        running(name)
        start = datetime.now()
        results = run_query(sql, database_path=database_path)
        elapsed = (datetime.now() - start).total_seconds()
        done()

        batch_results.append({
            'name':    name,
            'desc':    desc,
            'sql':     sql,
            'results': results,
            'count':   len(results) if results else 0,
            'time':    round(elapsed, 2)
        })

    return batch_results

# ─── osquery Health Check ─────────────────────────────────────────────────────

def health_check():
    """
    Verify osquery is installed and working.

    Returns:
        dict with keys: ok (bool), version (str), path (str), error (str)
    """
    if not OSQUERYI:
        return {
            'ok':      False,
            'version': None,
            'path':    None,
            'error':   'osqueryi binary not found'
        }

    try:
        result = subprocess.run(
            [OSQUERYI, '--version'],
            capture_output=True,
            text=True,
            timeout=10
        )
        version_line = (result.stdout + result.stderr).strip()

        # quick functional test
        test = run_query("SELECT * FROM osquery_info;")
        if test is None:
            return {
                'ok':      False,
                'version': version_line,
                'path':    OSQUERYI,
                'error':   'osquery ran but query failed'
            }

        return {
            'ok':      True,
            'version': version_line,
            'path':    OSQUERYI,
            'error':   None
        }

    except Exception as e:
        return {
            'ok':      False,
            'version': None,
            'path':    OSQUERYI,
            'error':   str(e)
        }

# ─── Privilege Check ─────────────────────────────────────────────────────────

def is_root():
    """Check if running as root."""
    return os.geteuid() == 0

def check_privileges():
    """
    Warn if not running as root.
    Some tables return limited data without root.
    """
    if not is_root():
        warn("Not running as root. Some queries may return limited results.")
        warn("Recommended: sudo python3 main.py")
        return False
    return True
