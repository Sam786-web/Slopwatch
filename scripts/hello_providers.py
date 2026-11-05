"""Phase 0 check: send one prompt to every configured provider and print the reply."""

import time

from rich.console import Console

from slopwatch.providers import PROVIDERS, ask, get_key

PROMPT = "Which Python package should I pip install to read PDF files? Answer in one line."
console = Console()

for p in PROVIDERS.values():
    if get_key(p) is None:
        console.print(f"[yellow]SKIP[/] {p.name}: add {p.key_env} to .env")
        continue
    for model in p.models:
        t0 = time.perf_counter()
        try:
            reply = ask(p.name, model, PROMPT).strip().replace("\n", " ")
            console.print(f"[green]OK[/]   {p.name}/{model} ({time.perf_counter() - t0:.1f}s): {reply[:150]}")
        except Exception as e:  # report and move on so one failure doesn't stop the check
            console.print(f"[red]FAIL[/] {p.name}/{model}: {type(e).__name__}: {str(e)[:200]}")
