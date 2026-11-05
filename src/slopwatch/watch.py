"""The daily watchtower run.

1. Re-check every hallucinated (missing/empty) name -> detect flips (someone registered it).
2. Statically scan flipped and brand-new recommended packages (see scanner.py; nothing executes).
3. Write alerts to data/alerts.json and refresh data/watchlist.json.

The watchlist is what CI needs (the full database stays local). It contains UNREGISTERED fake
names - an attacker's shopping list - so it is only ever committed ENCRYPTED (.enc, see vault.py).
Plain-text copies (data/watchlist.json, data/alerts.json) are git-ignored.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from rich.console import Console
from rich.table import Table

from .registry import SCHEMA as REGISTRY_SCHEMA
from .registry import check_all
from .scanner import SCHEMA as SCAN_SCHEMA
from .scanner import new_client, save, scan
from .vault import has_key, read_text, write_text

console = Console()
DATA = Path(__file__).resolve().parents[2] / "data"
WATCH_STATUSES = ("missing", "empty", "new")
RESCAN_AFTER = timedelta(days=7)


def import_watchlist(conn, path: Path) -> int:
    """Seed the packages table from a watchlist (used in CI, where there is no local database)."""
    if not path.exists():
        return 0
    items = json.loads(read_text(path))
    for it in items:
        conn.execute(
            "INSERT OR IGNORE INTO packages (ecosystem, name, status, checked_at, first_missing_at) VALUES (?, ?, ?, ?, ?)",
            (it["ecosystem"], it["name"], it["status"], it.get("checked_at") or "", it.get("first_missing_at")),
        )
    conn.commit()
    return len(items)


def export_watchlist(conn, path: Path) -> int:
    rows = [dict(r) for r in conn.execute(
        f"SELECT ecosystem, name, status, first_release, first_missing_at, checked_at FROM packages "
        f"WHERE status IN ({','.join('?' * len(WATCH_STATUSES))}) ORDER BY ecosystem, name", WATCH_STATUSES)]
    write_text(path, json.dumps(rows, indent=1))
    return len(rows)


def _scan_targets(conn, flipped: list[dict]) -> list[tuple[str, str]]:
    targets = {(f["ecosystem"], f["name"]) for f in flipped}
    last_scan = {(r["ecosystem"], r["name"]): r["t"] for r in conn.execute(
        "SELECT ecosystem, name, MAX(scanned_at) t FROM scans GROUP BY 1, 2")}
    cutoff = (datetime.now(timezone.utc) - RESCAN_AFTER).isoformat()
    for r in conn.execute("SELECT ecosystem, name FROM packages WHERE status = 'new'"):
        key = (r["ecosystem"], r["name"])
        if key not in last_scan or last_scan[key] < cutoff:
            targets.add(key)
    return sorted(targets)


def run_watch(conn, watchlist: Path | None = None, do_scan: bool = True) -> dict:
    conn.executescript(REGISTRY_SCHEMA)
    conn.executescript(SCAN_SCHEMA)
    if watchlist:
        console.print(f"Loaded {import_watchlist(conn, watchlist)} names from {watchlist.name}")

    to_recheck = [(r["ecosystem"], r["name"]) for r in conn.execute(
        "SELECT ecosystem, name FROM packages WHERE status IN ('missing', 'empty', 'error')")]
    _, flips = check_all(conn, only=to_recheck)

    scans = []
    if do_scan:
        targets = _scan_targets(conn, flips)
        console.print(f"Scanning {len(targets)} package(s) statically...")
        with new_client() as client:
            for eco, name in targets:
                r = scan(client, eco, name)
                save(conn, r)
                scans.append(r)
                console.print(f"  {eco}/{name} {r.version or ''}: [bold]{r.level}[/] (score {r.score})"
                              + (f" - {r.error}" if r.error else ""))

    alerts = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "flips": flips,
        "risky_packages": [
            {"ecosystem": s.ecosystem, "name": s.name, "version": s.version, "score": s.score, "level": s.level,
             "findings": [f"{f.rule} ({f.file}:{f.line})" for f in s.findings]}
            for s in scans if s.level in ("medium", "high")
        ],
    }
    DATA.mkdir(exist_ok=True)
    text = json.dumps(alerts, indent=1)
    (DATA / "alerts.json").write_text(text, encoding="utf-8")  # plain, git-ignored, for local use / CI steps
    if has_key():
        write_text(DATA / "alerts.json.enc", text)
    default_wl = DATA / ("watchlist.json.enc" if has_key() else "watchlist.json")
    n = export_watchlist(conn, watchlist or default_wl)
    console.print(f"Watchlist now holds {n} names.")
    return alerts


def print_alerts(alerts: dict) -> None:
    if not alerts["flips"] and not alerts["risky_packages"]:
        console.print("[green]No alerts: no hallucinated name was registered and no risky package found.[/]")
        return
    if alerts["flips"]:
        t = Table("ecosystem", "name", "was", "now", "first release", title="[red]Hallucinated names that got REGISTERED[/]")
        for f in alerts["flips"]:
            t.add_row(f["ecosystem"], f["name"], f["old_status"], f["new_status"], (f["first_release"] or "")[:10])
        console.print(t)
    if alerts["risky_packages"]:
        t = Table("ecosystem", "name", "version", "level", "score", "findings", title="[red]Risky packages (static scan)[/]")
        for p in alerts["risky_packages"]:
            t.add_row(p["ecosystem"], p["name"], p["version"] or "", p["level"], str(p["score"]), "\n".join(p["findings"][:6]))
        console.print(t)
