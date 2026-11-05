"""SQLite storage. One file (data/slopwatch.db) holds prompts, raw responses and extracted package mentions."""

from __future__ import annotations

import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parents[2] / "data" / "slopwatch.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS prompts (
    id          TEXT PRIMARY KEY,          -- stable hash of the prompt text
    ecosystem   TEXT NOT NULL,             -- 'pypi' or 'npm'
    task        TEXT NOT NULL,
    template    TEXT NOT NULL,
    text        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS responses (
    id          INTEGER PRIMARY KEY,
    prompt_id   TEXT NOT NULL REFERENCES prompts(id),
    model       TEXT NOT NULL,             -- 'provider:model'
    run         INTEGER NOT NULL DEFAULT 0,-- repeat index, used to measure repeatability
    temperature REAL NOT NULL,
    content     TEXT,
    error       TEXT,
    latency_s   REAL,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    extracted   INTEGER NOT NULL DEFAULT 0,
    UNIQUE (prompt_id, model, run)
);

CREATE TABLE IF NOT EXISTS mentions (
    id          INTEGER PRIMARY KEY,
    response_id INTEGER NOT NULL REFERENCES responses(id),
    ecosystem   TEXT NOT NULL,             -- 'pypi' or 'npm'
    name        TEXT NOT NULL,             -- normalized package / import name
    kind        TEXT NOT NULL,             -- 'install' (from an install command) or 'import'
    UNIQUE (response_id, ecosystem, name, kind)
);

CREATE INDEX IF NOT EXISTS idx_mentions_name ON mentions(ecosystem, name);
"""


def connect(path: Path = DB_PATH) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")  # lets several harvester threads write safely
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript(SCHEMA)
    return conn
