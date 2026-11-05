"""Static scanner for suspicious packages.

SAFETY: nothing is ever installed, extracted to disk or executed. The archive is downloaded into
memory (size-capped) and its text files are read with per-file and total size limits, so path
traversal and zip bombs can't hurt us. We only run regexes over the text.

The rules are transparent heuristics aimed at what malicious packages actually do:
code that runs at install/import time, obfuscated exec, data exfiltration and credential theft.
A high score means "a human should look at this", not "proven malware".
"""

from __future__ import annotations

import hashlib
import io
import json
import re
import tarfile
import zipfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from urllib.parse import quote

import httpx

from .registry import USER_AGENT

MAX_DOWNLOAD = 15 * 1024 * 1024      # bytes per archive
MAX_FILE = 2 * 1024 * 1024           # bytes read per file inside the archive
MAX_TOTAL = 40 * 1024 * 1024         # bytes read across all files
MAX_MEMBERS = 3000
CODE_EXT = (".py", ".pth", ".js", ".mjs", ".cjs", ".ts", ".sh", ".bat", ".cmd", ".ps1", ".json", ".cfg", ".toml")

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY,
    ecosystem   TEXT NOT NULL,
    name        TEXT NOT NULL,
    version     TEXT,
    sha256      TEXT,
    score       INTEGER NOT NULL,
    level       TEXT NOT NULL,      -- low | medium | high | error
    findings    TEXT NOT NULL,      -- JSON list
    scanned_at  TEXT NOT NULL,
    UNIQUE (ecosystem, name, version)
);
"""


@dataclass
class Finding:
    rule: str
    points: int
    file: str
    line: int
    snippet: str


@dataclass
class ScanResult:
    ecosystem: str
    name: str
    version: str | None = None
    sha256: str | None = None
    score: int = 0
    level: str = "low"
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None


# (rule id, points, regex, file filter). File filter: None = all code files.
RULES: list[tuple[str, int, re.Pattern, tuple[str, ...] | None]] = [
    ("exec-of-decoded-data", 40,
     re.compile(r"(?:exec|eval)\s*\(\s*(?:compile\s*\()?\s*(?:base64|codecs|zlib|marshal|bytes\.fromhex|binascii)", re.I), None),
    ("marshal-loads", 30, re.compile(r"marshal\.loads\s*\("), (".py",)),
    ("js-eval-of-decoded", 40,
     re.compile(r"(?:eval|Function)\s*\(\s*(?:atob|Buffer\.from\([^)]*['\"]base64['\"])", re.I), (".js", ".mjs", ".cjs", ".ts")),
    ("exfil-endpoint", 35,
     re.compile(r"discord(?:app)?\.com/api/webhooks|api\.telegram\.org/bot|webhook\.site|pastebin\.com/raw|"
                r"ngrok(?:-free)?\.(?:io|app)|oast\.(?:fun|me|pro|live|site)|burpcollaborator|requestbin|pipedream\.net", re.I), None),
    ("credential-paths", 30,
     re.compile(r"\.ssh/id_|\.aws/credentials|\.npmrc|\.pypirc|\.git-credentials|Local Storage/leveldb|"
                r"Login Data|wallet\.dat|\.config/gcloud|\.kube/config", re.I), None),
    ("env-dump", 20, re.compile(r"(?:dict\(\s*os\.environ\s*\)|json\.dumps\(\s*os\.environ|JSON\.stringify\(\s*process\.env\s*\))"), None),
    ("download-and-run", 35,
     re.compile(r"(?:curl|wget|Invoke-WebRequest|iwr)\b[^\n]{0,200}(?:\|\s*(?:ba)?sh|-o\s|>\s|;\s*chmod|\|\s*iex)", re.I), None),
    ("shell-exec", 10,
     re.compile(r"\b(?:os\.system|subprocess\.(?:Popen|call|run|check_output)|child_process|execSync|spawnSync)\b"), None),
    ("network-call", 8,
     re.compile(r"\b(?:urllib\.request|requests\.(?:get|post)|http\.client|socket\.socket|https?\.request|fetch\s*\(|axios\.)"), None),
    ("long-obfuscated-line", 15, re.compile(r"^[^\n]{2000,}$", re.M), (".py", ".js", ".mjs", ".cjs")),
    ("hex-escaped-blob", 15, re.compile(r"(?:\\x[0-9a-fA-F]{2}){40,}"), None),
]
INSTALL_TIME_FILES = ("setup.py",)       # Python code that runs during `pip install` of an sdist
PTH_IMPORT = re.compile(r"^\s*import\s", re.M)
SETUP_CMDCLASS = re.compile(r"cmdclass\s*=")
# Scripts npm runs when a package is installed from the registry. ("prepare" only runs for git
# installs and on publish, so it isn't counted.)
NPM_INSTALL_SCRIPTS = ("preinstall", "install", "postinstall")
MINIFIED = re.compile(r"(?:\.min\.(?:js|mjs|cjs)$|(?:^|/)(?:dist|umd|bundle|build)/)", re.I)


def _level(score: int) -> str:
    return "high" if score >= 60 else "medium" if score >= 30 else "low"


# Signals that are normal in legit code (an HTTP library makes network calls). On their own they
# can raise a package to "medium" at most; reaching "high" needs a strong signal.
WEAK_RULES = {"network-call", "shell-exec", "very-new-package", "single-version", "no-source-repo",
              "custom-install-command", "npm-install-script"}
WEAK_CAP = 40


def score_findings(findings: list[Finding]) -> int:
    """Each rule counts once per package (its strongest hit), however many files match."""
    best: dict[str, int] = {}
    for f in findings:
        best[f.rule] = max(best.get(f.rule, 0), f.points)
    weak = sum(p for r, p in best.items() if r.split("@")[0] in WEAK_RULES)
    strong = sum(p for r, p in best.items() if r.split("@")[0] not in WEAK_RULES)
    return min(100, strong + min(weak, WEAK_CAP))


def _download(client: httpx.Client, url: str) -> bytes:
    buf = io.BytesIO()
    with client.stream("GET", url) as r:
        r.raise_for_status()
        for chunk in r.iter_bytes():
            buf.write(chunk)
            if buf.tell() > MAX_DOWNLOAD:
                raise ValueError(f"archive larger than {MAX_DOWNLOAD // 1024 // 1024} MB, skipped")
    return buf.getvalue()


def iter_text_files(blob: bytes, filename: str):
    """Yield (path, text) for code files in a .tar.gz / .tgz / .zip / .whl, read in memory only."""
    total = 0
    if filename.endswith((".zip", ".whl", ".egg")):
        with zipfile.ZipFile(io.BytesIO(blob)) as z:
            for i, info in enumerate(z.infolist()):
                if i >= MAX_MEMBERS:
                    break
                if info.is_dir() or not info.filename.lower().endswith(CODE_EXT) or info.file_size > MAX_FILE:
                    continue
                total += info.file_size
                if total > MAX_TOTAL:
                    break
                with z.open(info) as f:
                    yield info.filename, f.read(MAX_FILE).decode("utf-8", "replace")
    else:
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:*") as t:
            for i, m in enumerate(t):
                if i >= MAX_MEMBERS:
                    break
                if not m.isfile() or not m.name.lower().endswith(CODE_EXT) or m.size > MAX_FILE:
                    continue
                total += m.size
                if total > MAX_TOTAL:
                    break
                f = t.extractfile(m)  # file object in memory; nothing is written to disk
                if f:
                    yield m.name, f.read(MAX_FILE).decode("utf-8", "replace")


def _line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def analyze_files(files) -> list[Finding]:
    findings: list[Finding] = []
    for path, text in files:
        base = path.rsplit("/", 1)[-1].lower()
        ext = "." + base.rsplit(".", 1)[-1] if "." in base else ""
        install_time = base in INSTALL_TIME_FILES
        if base.endswith(".pth") and PTH_IMPORT.search(text):
            findings.append(Finding("pth-autorun", 45, path, 1, ".pth file with import: runs on every Python start"))
        if base == "setup.py" and SETUP_CMDCLASS.search(text):
            m = SETUP_CMDCLASS.search(text)
            findings.append(Finding("custom-install-command", 15, path, _line_of(text, m.start()), "setup.py overrides install commands"))
        if base == "package.json":
            try:
                scripts = (json.loads(text).get("scripts") or {})
            except (ValueError, AttributeError):
                scripts = {}
            for hook in NPM_INSTALL_SCRIPTS:
                if hook in scripts:
                    findings.append(Finding("npm-install-script", 25, path, 1, f'"{hook}": {str(scripts[hook])[:100]}'))
        for rule, points, rx, only in RULES:
            if only and ext not in only:
                continue
            if rule == "long-obfuscated-line" and MINIFIED.search(path):
                continue  # minified bundles have long lines by design
            m = rx.search(text)
            if m:
                pts = int(points * 1.5) if install_time else points  # worse if it runs during install
                snippet = text[max(0, m.start() - 30): m.end() + 50].replace("\n", " ")[:140]
                findings.append(Finding(rule + ("@install" if install_time else ""), pts, path, _line_of(text, m.start()), snippet))
    return findings


def _metadata_findings(age_days: float | None, n_versions: int | None, has_repo: bool) -> list[Finding]:
    out = []
    if age_days is not None and age_days < 30:
        out.append(Finding("very-new-package", 10, "(metadata)", 0, f"first release {age_days:.0f} days ago"))
    if n_versions is not None and n_versions <= 1:
        out.append(Finding("single-version", 5, "(metadata)", 0, "only one version ever published"))
    if not has_repo:
        out.append(Finding("no-source-repo", 5, "(metadata)", 0, "no repository / homepage link"))
    return out


def _age_days(iso: str | None) -> float | None:
    if not iso:
        return None
    dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    return (datetime.now(timezone.utc) - dt).total_seconds() / 86400


def _pick_pypi_files(urls: list[dict]) -> list[dict]:
    """sdist first (its setup.py runs at install time), then one wheel."""
    sdists = [u for u in urls if u.get("packagetype") == "sdist"]
    wheels = [u for u in urls if u.get("packagetype") == "bdist_wheel"]
    return (sdists[:1] + wheels[:1]) or urls[:1]


def scan(client: httpx.Client, ecosystem: str, name: str) -> ScanResult:
    res = ScanResult(ecosystem, name)
    try:
        findings: list[Finding] = []
        hashes = []
        if ecosystem == "pypi":
            data = client.get(f"https://pypi.org/pypi/{quote(name)}/json")
            data.raise_for_status()
            j = data.json()
            info = j["info"]
            res.version = info.get("version")
            uploads = [f["upload_time_iso_8601"] for fs in j.get("releases", {}).values() for f in fs]
            has_repo = bool(info.get("project_urls") or info.get("home_page"))
            findings += _metadata_findings(_age_days(min(uploads)) if uploads else None, len(j.get("releases", {})), has_repo)
            for f in _pick_pypi_files(j.get("urls", [])):
                if f.get("size", 0) > MAX_DOWNLOAD:
                    continue
                blob = _download(client, f["url"])
                hashes.append(hashlib.sha256(blob).hexdigest())
                findings += analyze_files(iter_text_files(blob, f["filename"]))
        else:
            data = client.get(f"https://registry.npmjs.org/{quote(name, safe='@')}")
            data.raise_for_status()
            doc = data.json()
            res.version = (doc.get("dist-tags") or {}).get("latest")
            meta = (doc.get("versions") or {}).get(res.version or "", {})
            has_repo = bool(doc.get("repository") or doc.get("homepage"))
            findings += _metadata_findings(_age_days((doc.get("time") or {}).get("created")),
                                           len(doc.get("versions") or {}), has_repo)
            tarball = (meta.get("dist") or {}).get("tarball")
            if tarball:
                blob = _download(client, tarball)
                hashes.append(hashlib.sha256(blob).hexdigest())
                findings += analyze_files(iter_text_files(blob, "package.tgz"))
        # one finding per rule per file is enough
        seen, unique = set(), []
        for f in findings:
            if (f.rule, f.file) not in seen:
                seen.add((f.rule, f.file))
                unique.append(f)
        res.findings = unique
        res.sha256 = ",".join(hashes) or None
        res.score = score_findings(unique)
        res.level = _level(res.score)
    except Exception as e:  # report, don't crash the watch run
        res.level, res.error = "error", f"{type(e).__name__}: {str(e)[:200]}"
    return res


def save(conn, r: ScanResult) -> None:
    conn.executescript(SCHEMA)
    conn.execute(
        "INSERT INTO scans (ecosystem, name, version, sha256, score, level, findings, scanned_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (ecosystem, name, version) DO UPDATE SET "
        "sha256=excluded.sha256, score=excluded.score, level=excluded.level, findings=excluded.findings, "
        "scanned_at=excluded.scanned_at",
        (r.ecosystem, r.name, r.version, r.sha256, r.score, r.level,
         json.dumps([asdict(f) for f in r.findings] if not r.error else [{"error": r.error}]),
         datetime.now(timezone.utc).isoformat(timespec="seconds")),
    )
    conn.commit()


def new_client() -> httpx.Client:
    return httpx.Client(headers={"User-Agent": USER_AGENT}, timeout=60, follow_redirects=True)
