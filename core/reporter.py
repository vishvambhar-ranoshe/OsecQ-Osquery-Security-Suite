# core/reporter.py
# Saves query results to disk as JSON and TXT reports

import os
import json
from datetime import datetime

REPORTS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'reports')

# ─── Ensure Reports Directory Exists ─────────────────────────────────────────

def ensure_dir():
    os.makedirs(REPORTS_DIR, exist_ok=True)

# ─── Timestamp Helper ─────────────────────────────────────────────────────────

def timestamp():
    return datetime.now().strftime("%Y%m%d_%H%M%S")

def readable_time():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# ─── Save JSON Report ─────────────────────────────────────────────────────────

def save_json(data, label="report"):
    """
    Save a list of batch results as a JSON report.

    Args:
        data  : list of dicts (from run_batch output)
        label : prefix for filename (e.g. 'recon', 'threat_hunt')

    Returns:
        filepath string
    """
    ensure_dir()
    filename = f"osecq_{label}_{timestamp()}.json"
    filepath = os.path.join(REPORTS_DIR, filename)

    report = {
        "tool":       "OsecQ — Osquery Security Suite",
        "author":     "Vishu",
        "generated":  readable_time(),
        "label":      label,
        "total_queries": len(data),
        "results":    data
    }

    with open(filepath, 'w') as f:
        json.dump(report, f, indent=4)

    return filepath

# ─── Save TXT Report ──────────────────────────────────────────────────────────

def save_txt(data, label="report"):
    """
    Save a human-readable text report.

    Args:
        data  : list of dicts (from run_batch output)
        label : prefix for filename

    Returns:
        filepath string
    """
    ensure_dir()
    filename = f"osecq_{label}_{timestamp()}.txt"
    filepath = os.path.join(REPORTS_DIR, filename)

    lines = []
    lines.append("=" * 70)
    lines.append("  OsecQ — Osquery Security Suite")
    lines.append("  Built by Vishu | Kali Linux")
    lines.append(f"  Generated : {readable_time()}")
    lines.append(f"  Report    : {label.upper()}")
    lines.append("=" * 70)
    lines.append("")

    for item in data:
        lines.append(f"┌─ {item.get('name', 'Unknown')}")
        lines.append(f"│  Description : {item.get('desc', 'N/A')}")
        lines.append(f"│  Exec Time   : {item.get('time', 0)}s")
        lines.append(f"│  Results     : {item.get('count', 0)} row(s)")
        lines.append("│")

        results = item.get('results')
        if not results:
            lines.append("│  [ No results ]")
        else:
            # column headers
            cols = list(results[0].keys())
            lines.append("│  " + "  |  ".join(cols))
            lines.append("│  " + "─" * 50)
            for row in results:
                values = [str(row.get(col, '')) for col in cols]
                lines.append("│  " + "  |  ".join(values))

        lines.append("└" + "─" * 60)
        lines.append("")

    lines.append("=" * 70)
    lines.append("  END OF REPORT")
    lines.append("=" * 70)

    with open(filepath, 'w') as f:
        f.write('\n'.join(lines))

    return filepath

# ─── Save Both Formats ────────────────────────────────────────────────────────

def save_report(data, label="report"):
    """
    Save both JSON and TXT reports.

    Returns:
        dict with keys: json, txt
    """
    json_path = save_json(data, label)
    txt_path  = save_txt(data, label)
    return {
        'json': json_path,
        'txt':  txt_path
    }

# ─── List Saved Reports ───────────────────────────────────────────────────────

def list_reports():
    """
    Return list of all saved report files.

    Returns:
        list of dicts: {name, path, size_kb, modified}
    """
    ensure_dir()
    reports = []

    for fname in sorted(os.listdir(REPORTS_DIR), reverse=True):
        fpath = os.path.join(REPORTS_DIR, fname)
        if os.path.isfile(fpath):
            stat = os.stat(fpath)
            reports.append({
                'name':     fname,
                'path':     fpath,
                'size_kb':  round(stat.st_size / 1024, 2),
                'modified': datetime.fromtimestamp(
                                stat.st_mtime
                            ).strftime("%Y-%m-%d %H:%M:%S")
            })

    return reports

# ─── Quick Finding Saver ──────────────────────────────────────────────────────

def save_finding(title, description, data):
    """
    Save a single critical finding immediately to disk.
    Used by threat hunting module for urgent findings.

    Returns:
        filepath string
    """
    ensure_dir()
    filename = f"osecq_FINDING_{timestamp()}.json"
    filepath = os.path.join(REPORTS_DIR, filename)

    finding = {
        "tool":        "OsecQ — Osquery Security Suite",
        "type":        "CRITICAL FINDING",
        "generated":   readable_time(),
        "title":       title,
        "description": description,
        "data":        data
    }

    with open(filepath, 'w') as f:
        json.dump(finding, f, indent=4)

    return filepath
