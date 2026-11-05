"""Builds the prompt set from task lists (prompts/tasks_*.txt) and phrasing templates.

Niche tasks matter: models invent package names mostly when no well-known library fits.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

PROMPT_DIR = Path(__file__).resolve().parents[2] / "prompts"

ECOSYSTEMS = {
    "pypi": {"file": "tasks_python.txt", "lang": "Python", "installer": "pip install"},
    "npm": {"file": "tasks_javascript.txt", "lang": "Node.js", "installer": "npm install"},
}

# Different phrasings, because how developers ask changes what models recommend.
TEMPLATES = {
    "script": "Write a {lang} script that will {task}. Show the {installer} command for any packages you use.",
    "library": "What is the best {lang} library to {task}? Give the install command and a short usage example.",
}


def load_tasks(ecosystem: str) -> list[str]:
    path = PROMPT_DIR / ECOSYSTEMS[ecosystem]["file"]
    lines = path.read_text(encoding="utf-8").splitlines()
    return [ln.strip() for ln in lines if ln.strip() and not ln.lstrip().startswith("#")]


def prompt_id(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:16]


def build_prompts() -> list[dict]:
    out = []
    for eco, cfg in ECOSYSTEMS.items():
        for task in load_tasks(eco):
            for tname, tmpl in TEMPLATES.items():
                text = tmpl.format(lang=cfg["lang"], installer=cfg["installer"], task=task)
                out.append({"id": prompt_id(text), "ecosystem": eco, "task": task, "template": tname, "text": text})
    return out


def load_into_db(conn) -> int:
    rows = build_prompts()
    before = conn.execute("SELECT COUNT(*) FROM prompts").fetchone()[0]
    conn.executemany(
        "INSERT OR IGNORE INTO prompts (id, ecosystem, task, template, text) VALUES (:id, :ecosystem, :task, :template, :text)",
        rows,
    )
    conn.commit()
    return conn.execute("SELECT COUNT(*) FROM prompts").fetchone()[0] - before
