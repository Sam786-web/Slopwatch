"""Sends every prompt to every model and stores the raw responses.

- One worker thread per model, each with its own rate limit, so slow models don't block fast ones.
- Resumable: (prompt, model, run) pairs already answered are skipped, so you can stop with
  Ctrl+C and rerun anytime.
- A model that keeps failing (e.g. its free daily quota is used up) is stopped after a few
  consecutive errors instead of burning through the whole prompt list.
"""

from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor

from openai import APIStatusError
from rich.console import Console

from .db import connect
from .providers import MODEL_OPTS, client_for, split_model

console = Console()
MAX_CONSECUTIVE_ERRORS = 5
SYSTEM = None  # no system prompt: we want each model's default developer-facing behaviour


def _todo(conn, model: str, runs: int, limit: int | None) -> list[tuple[str, str, int]]:
    rows = []
    for run in range(runs):
        q = (
            "SELECT p.id, p.text FROM prompts p WHERE NOT EXISTS ("
            " SELECT 1 FROM responses r WHERE r.prompt_id = p.id AND r.model = ? AND r.run = ? AND r.content IS NOT NULL)"
            " ORDER BY p.id"
        )
        rows += [(r["id"], r["text"], run) for r in conn.execute(q, (model, run)).fetchall()]
    return rows[:limit] if limit else rows


def _worker(spec: str, runs: int, limit: int | None, temperature: float, stop: threading.Event) -> dict:
    provider, model = split_model(spec)
    conn = connect()
    todo = _todo(conn, spec, runs, limit)
    stats = {"model": spec, "planned": len(todo), "ok": 0, "err": 0, "stopped": ""}
    if not todo:
        return stats
    client = client_for(provider)
    opts = MODEL_OPTS.get(spec, {})
    interval = 60.0 / opts.get("rpm", provider.rpm)
    extra = {"max_tokens": opts["max_tokens"]} if "max_tokens" in opts else {}
    consecutive = 0
    console.print(f"[cyan]{spec}[/]: {len(todo)} prompts to run")

    for i, (pid, text, run) in enumerate(todo, 1):
        if stop.is_set():
            stats["stopped"] = "interrupted"
            break
        t0 = time.perf_counter()
        content, error = None, None
        try:
            resp = client.chat.completions.create(
                model=model, messages=[{"role": "user", "content": text}], temperature=temperature, **extra
            )
            content = resp.choices[0].message.content or ""
        except APIStatusError as e:
            error = f"{e.status_code}: {str(e)[:300]}"
        except Exception as e:  # network errors, timeouts
            error = f"{type(e).__name__}: {str(e)[:300]}"
        latency = time.perf_counter() - t0

        conn.execute(
            "INSERT INTO responses (prompt_id, model, run, temperature, content, error, latency_s) "
            "VALUES (?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT (prompt_id, model, run) DO UPDATE SET content=excluded.content, error=excluded.error, "
            "latency_s=excluded.latency_s, created_at=datetime('now'), extracted=0",
            (pid, spec, run, temperature, content, error, latency),
        )
        conn.commit()

        if error:
            stats["err"] += 1
            consecutive += 1
            console.print(f"[red]{spec}[/] error {consecutive}/{MAX_CONSECUTIVE_ERRORS}: {error[:120]}")
            if consecutive >= MAX_CONSECUTIVE_ERRORS:
                stats["stopped"] = "too many errors (quota used up?)"
                break
        else:
            stats["ok"] += 1
            consecutive = 0
        if i % 10 == 0:
            console.print(f"[cyan]{spec}[/]: {i}/{len(todo)}")
        time.sleep(max(0.0, interval - latency))  # respect the rate limit
    conn.close()
    return stats


def harvest(models: list[str], runs: int = 1, limit: int | None = None, temperature: float = 0.7) -> list[dict]:
    stop = threading.Event()
    with ThreadPoolExecutor(max_workers=len(models)) as pool:
        futures = [pool.submit(_worker, m, runs, limit, temperature, stop) for m in models]
        try:
            return [f.result() for f in futures]
        except KeyboardInterrupt:
            console.print("[yellow]Stopping after current requests... (progress is saved)[/]")
            stop.set()
            return [f.result() for f in futures]
