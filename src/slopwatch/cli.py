"""Command line: `uv run slopwatch <command>`."""

from __future__ import annotations

import argparse

from rich.console import Console
from rich.table import Table

from .db import connect
from .extract import extract_pending
from .harvest import harvest
from .prompts import load_into_db
from .providers import MODELS, PROVIDERS, client_for

console = Console()


def cmd_prompts(args) -> None:
    conn = connect()
    added = load_into_db(conn)
    total = conn.execute("SELECT COUNT(*) FROM prompts").fetchone()[0]
    console.print(f"Added {added} new prompts ({total} total).")


def cmd_harvest(args) -> None:
    models = args.models or MODELS
    results = harvest(models, runs=args.runs, limit=args.limit, temperature=args.temperature)
    t = Table("model", "planned", "ok", "errors", "note")
    for r in results:
        t.add_row(r["model"], str(r["planned"]), str(r["ok"]), str(r["err"]), r["stopped"])
    console.print(t)
    n_resp, n_ment = extract_pending(connect())
    console.print(f"Extracted {n_ment} package mentions from {n_resp} new responses.")


def cmd_extract(args) -> None:
    conn = connect()
    if args.redo:
        conn.execute("DELETE FROM mentions")
        conn.execute("UPDATE responses SET extracted = 0")
        conn.commit()
    n_resp, n_ment = extract_pending(conn)
    console.print(f"Extracted {n_ment} package mentions from {n_resp} responses.")


def cmd_stats(args) -> None:
    conn = connect()
    t = Table("model", "responses", "errors", "avg latency s", "unique pkgs (install)", "unique pkgs (import)")
    for r in conn.execute(
        """
        SELECT r.model,
               SUM(r.content IS NOT NULL) AS ok,
               SUM(r.content IS NULL)     AS err,
               ROUND(AVG(CASE WHEN r.content IS NOT NULL THEN r.latency_s END), 1) AS lat,
               (SELECT COUNT(DISTINCT m.ecosystem || m.name) FROM mentions m JOIN responses r2 ON r2.id = m.response_id
                 WHERE r2.model = r.model AND m.kind = 'install') AS inst,
               (SELECT COUNT(DISTINCT m.ecosystem || m.name) FROM mentions m JOIN responses r2 ON r2.id = m.response_id
                 WHERE r2.model = r.model AND m.kind = 'import') AS imp
        FROM responses r GROUP BY r.model ORDER BY r.model
        """
    ):
        t.add_row(r["model"], str(r["ok"]), str(r["err"]), str(r["lat"]), str(r["inst"]), str(r["imp"]))
    console.print(t)

    top = Table("ecosystem", "package", "kind", "times recommended")
    for r in conn.execute(
        "SELECT ecosystem, name, kind, COUNT(*) c FROM mentions GROUP BY 1, 2, 3 ORDER BY c DESC LIMIT ?",
        (args.top,),
    ):
        top.add_row(r["ecosystem"], r["name"], r["kind"], str(r["c"]))
    console.print(top)


def cmd_check(args) -> None:
    from .registry import check_all

    counts, flips = check_all(connect(), recheck=args.recheck)
    console.print("Results: " + (", ".join(f"{k}={v}" for k, v in sorted(counts.items())) or "nothing new to check"))
    for f in flips:
        console.print(f"[bold red]FLIP[/] {f['ecosystem']}/{f['name']}: {f['old_status']} -> {f['new_status']}")


def cmd_report(args) -> None:
    from .report import model_table, suspicious_existing, top_hallucinations, verdicts

    conn = connect()
    v = verdicts(conn)
    unchecked = sum(1 for x in v if x["status"] == "unchecked")
    if unchecked:
        console.print(f"[yellow]{unchecked} mentions not checked yet - run `slopwatch check` first.[/]")

    t = Table("model", "install mentions", "hallucinated", "rate", "unique fake names", "new/empty pkgs",
              "unexplained imports", title="Package hallucination by model (install commands)")
    for r in model_table(v):
        t.add_row(r["model"], str(r["install_mentions"]), str(r["hallucinated"]), f"{r['rate']:.1%}",
                  str(r["unique_hallucinated"]), str(r["new_or_empty"]), str(r["import_unexplained"]))
    console.print(t)

    t = Table("ecosystem", "hallucinated name", "times", "models", "prompts", "seen as",
              title="Most repeated hallucinations (repeatable = predictable = squattable)")
    for r in top_hallucinations(v, args.top):
        t.add_row(r["ecosystem"], r["name"], str(r["times"]), r["models"], str(r["prompts"]), r["kinds"])
    console.print(t)

    t = Table("ecosystem", "package", "status", "first release", "versions", "times", "summary",
              title="Recommended packages that are brand new or empty (inspect in Phase 3)")
    for r in suspicious_existing(conn, args.top):
        t.add_row(r["ecosystem"], r["name"], r["status"], (r["first_release"] or "")[:10], str(r["n_versions"]),
                  str(r["times"]), (r["summary"] or "")[:50])
    console.print(t)


def cmd_watch(args) -> None:
    from pathlib import Path

    from .watch import print_alerts, run_watch

    alerts = run_watch(connect(), watchlist=Path(args.watchlist) if args.watchlist else None, do_scan=not args.no_scan)
    print_alerts(alerts)


def cmd_scan(args) -> None:
    from .scanner import new_client, save, scan

    with new_client() as client:
        r = scan(client, args.ecosystem, args.name)
    save(connect(), r)
    console.print(f"{r.ecosystem}/{r.name} {r.version or ''}: [bold]{r.level}[/] (score {r.score})" + (f" - {r.error}" if r.error else ""))
    t = Table("rule", "points", "file:line", "evidence")
    for f in r.findings:
        t.add_row(f.rule, str(f.points), f"{f.file}:{f.line}", f.snippet)
    console.print(t)


def cmd_keygen(args) -> None:
    from pathlib import Path

    from .vault import KEY_ENV, has_key, new_key

    if has_key() and not args.force:
        console.print(f"{KEY_ENV} already exists in your environment/.env (use --force to replace; old .enc files become unreadable).")
        return
    key = new_key()
    env = Path(__file__).resolve().parents[2] / ".env"
    lines = [ln for ln in env.read_text(encoding="utf-8").splitlines() if not ln.startswith(KEY_ENV + "=")] if env.exists() else []
    env.write_text("\n".join(lines + [f"{KEY_ENV}={key}"]) + "\n", encoding="utf-8")
    console.print(f"New key saved to .env as {KEY_ENV}. Add the same value as a GitHub Actions secret named {KEY_ENV}.")


def cmd_crypt(args) -> None:
    from pathlib import Path

    from .vault import decrypt_bytes, encrypt_bytes

    src, dst = Path(args.src), Path(args.dst)
    fn = encrypt_bytes if args.action == "encrypt" else decrypt_bytes
    dst.write_bytes(fn(src.read_bytes()))
    console.print(f"{args.action}ed {src} -> {dst}")


def cmd_alerts(args) -> None:
    import json
    from pathlib import Path

    from .vault import read_text
    from .watch import print_alerts

    data = Path(__file__).resolve().parents[2] / "data"
    path = data / "alerts.json.enc" if (data / "alerts.json.enc").exists() else data / "alerts.json"
    print_alerts(json.loads(read_text(path)))


def cmd_site(args) -> None:
    from .site import build_site

    path = build_site(connect())
    console.print(f"Dashboard written to {path}")


def cmd_leakcheck(args) -> None:
    """Block commits that contain an unregistered hallucinated name (run by the git pre-commit hook)."""
    import re
    import subprocess
    import sys

    from .registry import IMPORT_TO_DIST, SCHEMA

    conn = connect()
    conn.executescript(SCHEMA)
    names = {r["name"] for r in conn.execute("SELECT name FROM packages WHERE status IN ('missing', 'empty')")}
    names -= set(IMPORT_TO_DIST) | {v for v in IMPORT_TO_DIST.values()}  # documented import mappings are fine
    files = subprocess.run(["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
                           capture_output=True, text=True, check=True).stdout.split()
    leaks = []
    for f in files:
        if f.endswith(".enc"):
            continue
        try:
            text = open(f, encoding="utf-8", errors="ignore").read()
        except OSError:
            continue
        for n in names:
            if re.search(r"(?<![\w@/.-])" + re.escape(n) + r"(?![\w/-])", text):
                leaks.append((f, n))
    if leaks:
        for f, n in leaks:
            console.print(f"[red]LEAK[/] {f}: contains unregistered fake name '{n}'")
        console.print("[red]Commit blocked.[/] Mask the name or remove the file from the commit.")
        sys.exit(1)
    console.print(f"[green]Leak check passed[/]: {len(files)} staged file(s), {len(names)} protected name(s).")


def cmd_models(args) -> None:
    ids = sorted(m.id for m in client_for(PROVIDERS[args.provider]).models.list())
    console.print("\n".join(ids))


def main() -> None:
    ap = argparse.ArgumentParser(prog="slopwatch", description="Measure AI package hallucinations.")
    sub = ap.add_subparsers(required=True)

    p = sub.add_parser("prompts", help="Build the prompt set from prompts/tasks_*.txt into the database")
    p.set_defaults(func=cmd_prompts)

    p = sub.add_parser("harvest", help="Send prompts to models and store responses")
    p.add_argument("--models", nargs="+", help=f"provider:model specs (default: {', '.join(MODELS)})")
    p.add_argument("--limit", type=int, help="max prompts per model in this session")
    p.add_argument("--runs", type=int, default=1, help="ask each prompt this many times (repeatability)")
    p.add_argument("--temperature", type=float, default=0.7)
    p.set_defaults(func=cmd_harvest)

    p = sub.add_parser("extract", help="Extract package names from stored responses")
    p.add_argument("--redo", action="store_true", help="wipe and re-extract everything (after improving the extractor)")
    p.set_defaults(func=cmd_extract)

    p = sub.add_parser("stats", help="Show per-model progress and the most recommended packages")
    p.add_argument("--top", type=int, default=20)
    p.set_defaults(func=cmd_stats)

    p = sub.add_parser("check", help="Look up every extracted package name on PyPI / npm")
    p.add_argument("--recheck", choices=["missing", "all"], help="re-check names already looked up")
    p.set_defaults(func=cmd_check)

    p = sub.add_parser("report", help="Hallucination rates per model and the most repeated fake names")
    p.add_argument("--top", type=int, default=25)
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("watch", help="Daily run: re-check fake names, detect registrations, scan suspicious packages")
    p.add_argument("--watchlist", help="JSON watchlist to load/update (CI mode); default data/watchlist.json is only written")
    p.add_argument("--no-scan", action="store_true", help="only re-check names, skip static scans")
    p.set_defaults(func=cmd_watch)

    p = sub.add_parser("scan", help="Statically scan one package (never installs or runs it)")
    p.add_argument("ecosystem", choices=["pypi", "npm"])
    p.add_argument("name")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("keygen", help="Create the encryption key for sensitive files (saved to .env)")
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_keygen)

    p = sub.add_parser("crypt", help="Encrypt or decrypt a file with SLOPWATCH_KEY")
    p.add_argument("action", choices=["encrypt", "decrypt"])
    p.add_argument("src")
    p.add_argument("dst")
    p.set_defaults(func=cmd_crypt)

    p = sub.add_parser("alerts", help="Show the latest alerts (decrypts data/alerts.json.enc, e.g. after a CI run)")
    p.set_defaults(func=cmd_alerts)

    p = sub.add_parser("site", help="Build the public dashboard into docs/ (safe, masked data only)")
    p.set_defaults(func=cmd_site)

    p = sub.add_parser("leakcheck", help="Fail if staged git files contain an unregistered fake name")
    p.set_defaults(func=cmd_leakcheck)

    p = sub.add_parser("models", help="List models a provider currently offers")
    p.add_argument("provider", choices=list(PROVIDERS))
    p.set_defaults(func=cmd_models)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
