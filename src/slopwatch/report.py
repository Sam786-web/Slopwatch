"""Turns mentions + registry results into research numbers.

Primary metric (strict): share of package names in INSTALL commands that don't exist on the
registry. These are exactly what a developer would copy-paste.
Secondary (weaker): imports whose package can't be found AND that aren't explained by an
install command in the same response (import names often differ from package names).
"""

from __future__ import annotations

import re
from collections import defaultdict

from .registry import import_to_pypi


def _squash(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", s.lower())


def verdicts(conn) -> list[dict]:
    """One row per mention, with the registry status of the package it implies."""
    status = {(r["ecosystem"], r["name"]): r["status"] for r in conn.execute("SELECT ecosystem, name, status FROM packages")}
    rows = conn.execute(
        "SELECT m.response_id, m.ecosystem, m.name, m.kind, r.model, r.prompt_id "
        "FROM mentions m JOIN responses r ON r.id = m.response_id"
    ).fetchall()

    installs_by_resp: dict[int, set[str]] = defaultdict(set)
    for r in rows:
        if r["kind"] == "install":
            installs_by_resp[r["response_id"]].add(_squash(r["name"]))

    out = []
    for r in rows:
        reg_name = r["name"]
        if r["ecosystem"] == "pypi" and r["kind"] == "import":
            reg_name = import_to_pypi(r["name"])
            if reg_name is None:
                continue  # ambiguous / local module: can't judge
        st = status.get((r["ecosystem"], reg_name), "unchecked")
        if st == "missing" and r["kind"] == "import":
            imp = _squash(r["name"])
            # e.g. `pip install python-snap7` + `import snap7`: explained, not a hallucination
            if any(imp in inst or inst in imp for inst in installs_by_resp[r["response_id"]]):
                st = "explained"
        out.append({**dict(r), "registry_name": reg_name, "status": st})
    return out


def model_table(v: list[dict]) -> list[dict]:
    agg: dict[str, dict] = defaultdict(lambda: defaultdict(int))
    names: dict[str, dict[str, set]] = defaultdict(lambda: defaultdict(set))
    for x in v:
        a = agg[x["model"]]
        if x["kind"] == "install":
            a["install"] += 1
            if x["status"] == "missing":
                a["install_missing"] += 1
                names[x["model"]]["missing"].add((x["ecosystem"], x["registry_name"]))
            if x["status"] in ("new", "empty"):
                a["install_suspicious"] += 1
        else:
            a["import"] += 1
            if x["status"] == "missing":
                a["import_missing"] += 1
    out = []
    for model, a in sorted(agg.items()):
        out.append({
            "model": model,
            "install_mentions": a["install"],
            "hallucinated": a["install_missing"],
            "rate": (a["install_missing"] / a["install"]) if a["install"] else 0.0,
            "unique_hallucinated": len(names[model]["missing"]),
            "new_or_empty": a["install_suspicious"],
            "import_unexplained": a["import_missing"],
        })
    return out


def top_hallucinations(v: list[dict], limit: int = 25) -> list[dict]:
    """Hallucinated names ranked by how predictable they are (distinct responses, models)."""
    by: dict[tuple, dict] = {}
    for x in v:
        if x["status"] != "missing":
            continue
        key = (x["ecosystem"], x["registry_name"])
        d = by.setdefault(key, {"ecosystem": key[0], "name": key[1], "responses": set(), "models": set(),
                                "prompts": set(), "kinds": set()})
        d["responses"].add(x["response_id"])
        d["models"].add(x["model"].split(":", 1)[1])
        d["prompts"].add(x["prompt_id"])
        d["kinds"].add(x["kind"])
    ranked = sorted(by.values(), key=lambda d: (len(d["responses"]), len(d["models"])), reverse=True)
    return [
        {"ecosystem": d["ecosystem"], "name": d["name"], "times": len(d["responses"]),
         "models": ", ".join(sorted(d["models"])), "prompts": len(d["prompts"]), "kinds": "+".join(sorted(d["kinds"]))}
        for d in ranked[:limit]
    ]


def suspicious_existing(conn, limit: int = 25) -> list[dict]:
    """Recommended packages that exist but are brand new or empty: worth a closer look in Phase 3."""
    return [dict(r) for r in conn.execute(
        "SELECT p.ecosystem, p.name, p.status, p.first_release, p.n_versions, p.summary, "
        "       (SELECT COUNT(*) FROM mentions m WHERE m.ecosystem = p.ecosystem AND m.name = p.name) AS times "
        "FROM packages p WHERE p.status IN ('new', 'empty') AND times > 0 ORDER BY times DESC LIMIT ?", (limit,))]
