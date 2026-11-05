import json

import pytest

from slopwatch import registry
from slopwatch.db import connect
from slopwatch.site import build_site, mask
from slopwatch.vault import VaultError, new_key, read_text, write_text


def test_vault_roundtrip_and_wrong_key(tmp_path):
    key = new_key()
    p = tmp_path / "watchlist.json.enc"
    write_text(p, '[{"name": "secret-pkg"}]', key)
    assert b"secret-pkg" not in p.read_bytes()          # really encrypted on disk
    assert read_text(p, key) == '[{"name": "secret-pkg"}]'
    with pytest.raises(VaultError):
        read_text(p, new_key())


def test_plain_files_pass_through(tmp_path):
    p = tmp_path / "x.json"
    write_text(p, "hello", new_key())
    assert p.read_text() == "hello"


def test_mask_hides_name():
    assert mask("@example-org/not-a-real-pkg") == "@e••••••"


def test_site_never_publishes_unregistered_names(tmp_path):
    conn = connect(tmp_path / "t.db")
    conn.executescript(registry.SCHEMA)
    conn.execute("INSERT INTO prompts VALUES ('p1', 'npm', 'parse MIDI files', 'script', 'Write...')")
    conn.execute("INSERT INTO responses (id, prompt_id, model, temperature, content) VALUES (1, 'p1', 'groq:m', 0.7, 'x')")
    for name in ("totally-fake-pkg", "squatted-pkg", "express"):
        conn.execute("INSERT INTO mentions (response_id, ecosystem, name, kind) VALUES (1, 'npm', ?, 'install')", (name,))
    for name, st in (("totally-fake-pkg", "missing"), ("squatted-pkg", "new"), ("express", "established")):
        conn.execute("INSERT INTO packages (ecosystem, name, status, checked_at) VALUES ('npm', ?, ?, '')", (name, st))
    # squatted-pkg was missing earlier and then got registered:
    conn.execute("INSERT INTO events (ecosystem, name, old_status, new_status, detected_at) "
                 "VALUES ('npm', 'squatted-pkg', 'missing', 'new', '2026-11-05')")
    conn.commit()

    html = build_site(conn, tmp_path / "site").read_text(encoding="utf-8")
    data = json.loads((tmp_path / "site" / "data.json").read_text(encoding="utf-8"))
    assert "totally-fake-pkg" not in html and "totally-fake-pkg" not in json.dumps(data)
    assert "squatted-pkg" in html                       # registered names are shown, as a warning
    assert data["totals"]["hallucinated"] == 1 and data["totals"]["install_mentions"] == 3
