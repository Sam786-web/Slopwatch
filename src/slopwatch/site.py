"""Builds the public dashboard (docs/index.html, served by GitHub Pages).

Only safe-to-publish data leaves the database:
  - aggregate rates (per model, ecosystem, task category, prompt style)
  - UNREGISTERED fake names are MASKED (first 2 chars + length) so the page isn't a squatting list
  - names are shown in full only once someone has registered them (public already; publishing warns devs)
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from .prompts import ECOSYSTEMS, PROMPT_DIR, TEMPLATES
from .registry import SCHEMA as REGISTRY_SCHEMA
from .scanner import SCHEMA as SCAN_SCHEMA
from .report import model_table, verdicts

ROOT = Path(__file__).resolve().parents[2]
TEMPLATE = Path(__file__).with_name("site_template.html")
MIN_SAMPLE = 30  # install mentions below this are flagged "low sample" on the page


def mask(name: str) -> str:
    return f"{name[:2]}{'•' * 6}"


def task_categories() -> dict[tuple[str, str], str]:
    """(ecosystem, task) -> category, from the '# --- category ---' headers in the task files."""
    out = {}
    for eco, cfg in ECOSYSTEMS.items():
        cat = "other"
        for line in (PROMPT_DIR / cfg["file"]).read_text(encoding="utf-8").splitlines():
            m = re.match(r"#\s*-+\s*(.+?)\s*-+\s*$", line.strip())
            if m:
                cat = m.group(1).strip()
            elif line.strip() and not line.lstrip().startswith("#"):
                out[(eco, line.strip())] = cat
    return out


def _rate(group: dict) -> dict:
    n, bad = group["n"], group["bad"]
    return {"mentions": n, "hallucinated": bad, "rate": round(bad / n, 4) if n else 0.0, "low_sample": n < MIN_SAMPLE}


def build_stats(conn) -> dict:
    conn.executescript(REGISTRY_SCHEMA)  # tables may not exist yet on a fresh database
    conn.executescript(SCAN_SCHEMA)
    v = verdicts(conn)
    prompts = {r["id"]: dict(r) for r in conn.execute("SELECT id, ecosystem, task, template FROM prompts")}
    cats = task_categories()

    installs = [x for x in v if x["kind"] == "install" and x["status"] != "unchecked"]
    by_eco, by_cat, by_tpl = (defaultdict(lambda: {"n": 0, "bad": 0}) for _ in range(3))
    for x in installs:
        p = prompts.get(x["prompt_id"], {})
        bad = x["status"] == "missing"
        for d, key in ((by_eco, x["ecosystem"]), (by_cat, cats.get((p.get("ecosystem"), p.get("task")), "other")),
                       (by_tpl, p.get("template", "?"))):
            d[key]["n"] += 1
            d[key]["bad"] += bad

    fake = defaultdict(lambda: {"times": 0, "models": set()})
    for x in installs:
        if x["status"] == "missing":
            f = fake[(x["ecosystem"], x["registry_name"])]
            f["times"] += 1
            f["models"].add(x["model"].split(":", 1)[1])

    events = [dict(r) for r in conn.execute(
        "SELECT e.ecosystem, e.name, e.new_status, e.detected_at, "
        " (SELECT level FROM scans s WHERE s.ecosystem = e.ecosystem AND s.name = e.name ORDER BY scanned_at DESC LIMIT 1) AS scan_level, "
        " (SELECT score FROM scans s WHERE s.ecosystem = e.ecosystem AND s.name = e.name ORDER BY scanned_at DESC LIMIT 1) AS scan_score "
        "FROM events e ORDER BY e.detected_at DESC")]
    registered = {(e["ecosystem"], e["name"]) for e in events}
    watched = conn.execute("SELECT COUNT(*) FROM packages WHERE status IN ('missing', 'empty')").fetchone()[0]

    models = model_table(v)
    resp = conn.execute("SELECT COUNT(*) n, COUNT(DISTINCT model) m, MIN(created_at) first, MAX(created_at) last "
                        "FROM responses WHERE content IS NOT NULL").fetchone()
    total_n = sum(m["install_mentions"] for m in models)
    total_bad = sum(m["hallucinated"] for m in models)

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="minutes"),
        "totals": {
            "prompts": conn.execute("SELECT COUNT(*) FROM prompts").fetchone()[0],
            "responses": resp["n"], "models": resp["m"],
            "install_mentions": total_n, "hallucinated": total_bad,
            "rate": round(total_bad / total_n, 4) if total_n else 0.0,
            "unique_fake_names": len(fake), "watched": watched, "registered": len(events),
            "period": [resp["first"], resp["last"]],
        },
        "models": [
            {"model": m["model"].split(":", 1)[1], "provider": m["model"].split(":", 1)[0],
             "mentions": m["install_mentions"], "hallucinated": m["hallucinated"], "rate": round(m["rate"], 4),
             "unique": m["unique_hallucinated"], "low_sample": m["install_mentions"] < MIN_SAMPLE}
            for m in sorted(models, key=lambda m: -m["rate"])
        ],
        "ecosystems": {k: _rate(g) for k, g in sorted(by_eco.items())},
        "categories": dict(sorted(((k, _rate(g)) for k, g in by_cat.items()), key=lambda kv: -kv[1]["rate"])),
        "templates": {k: {**_rate(g), "text": TEMPLATES.get(k, "")} for k, g in by_tpl.items()},
        "fake_names": [
            {"ecosystem": eco, "label": name if (eco, name) in registered else mask(name), "length": len(name),
             "times": f["times"], "models": sorted(f["models"]), "registered": (eco, name) in registered}
            for (eco, name), f in sorted(fake.items(), key=lambda kv: -kv[1]["times"])
        ],
        "registered": events,
        "graph": build_graph(installs, registered),
    }


def build_graph(installs: list[dict], registered: set) -> dict:
    """Model -> package network for the 3D view. Fake names keep masked labels and opaque ids."""
    pkg = defaultdict(lambda: {"times": 0, "models": defaultdict(int), "status": ""})
    for x in installs:
        p = pkg[(x["ecosystem"], x["registry_name"])]
        p["times"] += 1
        p["status"] = x["status"]
        p["models"][x["model"].split(":", 1)[1]] += 1
    models = sorted({m for p in pkg.values() for m in p["models"]})
    nodes = [{"id": f"m{i}", "type": "model", "label": m} for i, m in enumerate(models)]
    mid = {m: f"m{i}" for i, m in enumerate(models)}
    links = []
    for i, ((eco, name), p) in enumerate(sorted(pkg.items(), key=lambda kv: -kv[1]["times"])):
        fake = p["status"] in ("missing", "empty")
        if not fake and p["times"] < 2:
            continue  # keep the network readable: one-off real packages are left out
        shown = name if (not fake or (eco, name) in registered) else mask(name)
        nid = f"p{i}"
        nodes.append({"id": nid, "type": "fake" if fake else "real", "label": shown, "ecosystem": eco,
                      "times": p["times"], "status": p["status"], "models": sorted(p["models"])})
        links += [{"source": mid[m], "target": nid, "value": n, "fake": fake} for m, n in p["models"].items()]
    return {"nodes": nodes, "links": links}


def build_site(conn, out_dir: Path | None = None) -> Path:
    out_dir = out_dir or ROOT / "docs"
    out_dir.mkdir(parents=True, exist_ok=True)
    stats = build_stats(conn)
    payload = json.dumps(stats, ensure_ascii=False).replace("</", "<\\/")  # safe inside <script>
    html = TEMPLATE.read_text(encoding="utf-8").replace("__SLOPWATCH_DATA__", payload)
    (out_dir / "index.html").write_text(html, encoding="utf-8")
    (out_dir / "data.json").write_text(json.dumps(stats, indent=1, ensure_ascii=False), encoding="utf-8")
    (out_dir / ".nojekyll").write_text("", encoding="utf-8")
    return out_dir / "index.html"
