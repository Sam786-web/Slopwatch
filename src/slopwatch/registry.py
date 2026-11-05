"""Checks package names against the real registries (PyPI, npm) and records what exists.

Status of a name:
  established  exists, first release more than NEW_DAYS ago
  new          exists, first release within NEW_DAYS (possibly registered by a squatter)
  empty        name registered but has no released files (name reservation)
  missing      registry says 404 -> the model hallucinated it
  error        lookup failed (network, 5xx); retried next time

Every lookup is also appended to `checks`, so Phase 3 can detect names that flip
from missing to registered.
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from urllib.parse import quote

import httpx
from rich.console import Console

from .extract import normalize_pypi

console = Console()
NEW_DAYS = 90
USER_AGENT = "slopwatch-research/0.1 (academic study of AI package hallucination)"

SCHEMA = """
CREATE TABLE IF NOT EXISTS packages (
    ecosystem      TEXT NOT NULL,
    name           TEXT NOT NULL,
    status         TEXT NOT NULL,      -- established | new | empty | missing | error
    first_release  TEXT,               -- ISO timestamp of the first upload / creation
    last_release   TEXT,
    n_versions     INTEGER,
    summary        TEXT,
    checked_at     TEXT NOT NULL,
    first_missing_at TEXT,             -- when we first saw it missing (for flip monitoring)
    PRIMARY KEY (ecosystem, name)
);
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY,
    ecosystem   TEXT NOT NULL,
    name        TEXT NOT NULL,
    old_status  TEXT NOT NULL,
    new_status  TEXT NOT NULL,
    detected_at TEXT NOT NULL,
    details     TEXT
);
CREATE TABLE IF NOT EXISTS checks (
    id         INTEGER PRIMARY KEY,
    ecosystem  TEXT NOT NULL,
    name       TEXT NOT NULL,
    status     TEXT NOT NULL,
    checked_at TEXT NOT NULL
);
"""

# Python import name -> PyPI distribution name, for well-known mismatches.
IMPORT_TO_DIST = {
    "cv2": "opencv-python", "pil": "pillow", "sklearn": "scikit-learn", "skimage": "scikit-image",
    "yaml": "pyyaml", "bs4": "beautifulsoup4", "dateutil": "python-dateutil", "crypto": "pycryptodome",
    "cryptodome": "pycryptodomex", "jwt": "pyjwt", "dotenv": "python-dotenv", "docx": "python-docx",
    "pptx": "python-pptx", "serial": "pyserial", "usb": "pyusb", "fitz": "pymupdf", "pymupdf": "pymupdf",
    "snap7": "python-snap7", "attr": "attrs", "openssl": "pyopenssl", "nmap": "python-nmap",
    "whois": "python-whois", "telegram": "python-telegram-bot", "gi": "pygobject", "zmq": "pyzmq",
    "jose": "python-jose", "ldap": "python-ldap", "git": "gitpython", "magic": "python-magic",
    "win32api": "pywin32", "win32com": "pywin32", "win32con": "pywin32", "pythoncom": "pywin32",
    "dns": "dnspython", "evtx": "python-evtx", "Evtx": "python-evtx", "can": "python-can",
    "cantools": "cantools", "pydicom": "pydicom", "fitdecode": "fitdecode", "multipart": "python-multipart",
    "socketio": "python-socketio", "engineio": "python-engineio", "slugify": "python-slugify",
    "googleapiclient": "google-api-python-client", "google_auth_oauthlib": "google-auth-oauthlib",
    "faiss": "faiss-cpu", "llama_cpp": "llama-cpp-python", "sentence_transformers": "sentence-transformers",
    "huggingface_hub": "huggingface-hub", "mpl_toolkits": "matplotlib", "pkg_resources": "setuptools",
    "setuptools": "setuptools", "pymodbus": "pymodbus", "opcua": "opcua", "asyncua": "asyncua",
    "ifcopenshell": "ifcopenshell", "pygrib": "pygrib", "cfgrib": "cfgrib", "kubernetes": "kubernetes",
    "hvac": "hvac", "grpc": "grpcio", "grpc_tools": "grpcio-tools", "tesserocr": "tesserocr",
    "pytesseract": "pytesseract", "yara": "yara-python", "scapy": "scapy", "pyshark": "pyshark",
    "oletools": "oletools", "olefile": "olefile", "presidio_analyzer": "presidio-analyzer",
    "presidio_anonymizer": "presidio-anonymizer", "peft": "peft", "onnxruntime": "onnxruntime",
    "imagehash": "imagehash", "whisper": "openai-whisper", "faster_whisper": "faster-whisper",
    "pysrt": "pysrt", "boto3": "boto3", "botocore": "botocore", "nltk": "nltk", "spacy": "spacy",
}
# Namespace packages / ambiguous roots we can't map to a single distribution.
AMBIGUOUS_IMPORTS = {"google", "azure", "zope", "jaraco", "backports", "ruamel", "mpl_toolkits"}
# Names that are almost always the user's own local modules, not packages.
LOCAL_MODULE_NAMES = {"utils", "util", "config", "settings", "app", "main", "models", "helpers", "my_module",
                      "mymodule", "module", "lib", "core", "common", "constants", "db", "database", "api",
                      "routes", "views", "tests", "test", "src", "server", "client", "schemas", "tasks"}


def import_to_pypi(import_name: str) -> str | None:
    """Best-effort PyPI name for a Python import, or None if it can't be judged."""
    if import_name in AMBIGUOUS_IMPORTS or import_name.lower() in LOCAL_MODULE_NAMES:
        return None
    if import_name.endswith(("_pb2", "_pb2_grpc")):  # code generated locally by protoc / grpc_tools
        return None
    return IMPORT_TO_DIST.get(import_name) or IMPORT_TO_DIST.get(import_name.lower()) or normalize_pypi(import_name)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _classify(first_release: str | None, has_files: bool) -> str:
    if not has_files:
        return "empty"
    if first_release:
        first = datetime.fromisoformat(first_release.replace("Z", "+00:00"))
        if first.tzinfo is None:
            first = first.replace(tzinfo=timezone.utc)
        if (_now() - first).days < NEW_DAYS:
            return "new"
    return "established"


def check_pypi(client: httpx.Client, name: str) -> dict:
    r = client.get(f"https://pypi.org/pypi/{quote(name)}/json")
    if r.status_code == 404:
        return {"status": "missing"}
    r.raise_for_status()
    data = r.json()
    uploads = [f["upload_time_iso_8601"] for files in data.get("releases", {}).values() for f in files]
    first = min(uploads) if uploads else None
    last = max(uploads) if uploads else None
    return {
        "status": _classify(first, bool(uploads)),
        "first_release": first,
        "last_release": last,
        "n_versions": len(data.get("releases", {})),
        "summary": (data.get("info", {}).get("summary") or "")[:300],
    }


def check_npm(client: httpx.Client, name: str) -> dict:
    url = f"https://registry.npmjs.org/{quote(name, safe='@')}"
    # The abbreviated document is small even for huge packages; enough for existence + version count.
    r = client.get(url, headers={"Accept": "application/vnd.npm.install-v1+json"})
    if r.status_code == 404:
        return {"status": "missing"}
    r.raise_for_status()
    abbrev = r.json()
    n_versions = len(abbrev.get("versions", {}))
    if n_versions == 0:
        return {"status": "empty", "n_versions": 0}
    if n_versions >= 20:  # long history -> clearly not brand new; skip the heavy full document
        return {"status": "established", "n_versions": n_versions, "last_release": abbrev.get("modified")}
    full = client.get(url)
    full.raise_for_status()
    doc = full.json()
    times = doc.get("time", {})
    first = times.get("created")
    return {
        "status": _classify(first, True),
        "first_release": first,
        "last_release": times.get("modified"),
        "n_versions": n_versions,
        "summary": (doc.get("description") or "")[:300],
    }


def _lookup(client: httpx.Client, ecosystem: str, name: str) -> dict:
    for attempt in range(3):
        try:
            return (check_pypi if ecosystem == "pypi" else check_npm)(client, name)
        except (httpx.HTTPError, ValueError) as e:
            if attempt == 2:
                return {"status": "error", "summary": f"{type(e).__name__}: {str(e)[:200]}"}
            time.sleep(2 * (attempt + 1))
    raise AssertionError("unreachable")


def wanted_names(conn) -> set[tuple[str, str]]:
    """All registry names implied by current mentions (imports mapped to PyPI names)."""
    wanted: set[tuple[str, str]] = set()
    for r in conn.execute("SELECT DISTINCT ecosystem, name, kind FROM mentions"):
        if r["ecosystem"] == "pypi" and r["kind"] == "import":
            if (n := import_to_pypi(r["name"])):
                wanted.add(("pypi", n))
        else:
            wanted.add((r["ecosystem"], r["name"]))
    return wanted


def prune_stale(conn) -> int:
    """Drop packages no current mention refers to (e.g. noise removed by a better extractor).
    Names that already flipped are kept: they are research results."""
    wanted = wanted_names(conn)
    flipped = {(r["ecosystem"], r["name"]) for r in conn.execute("SELECT ecosystem, name FROM events")}
    stale = [(r["ecosystem"], r["name"]) for r in conn.execute("SELECT ecosystem, name FROM packages")
             if (r["ecosystem"], r["name"]) not in wanted | flipped]
    conn.executemany("DELETE FROM packages WHERE ecosystem = ? AND name = ?", stale)
    conn.commit()
    return len(stale)


def names_to_check(conn, recheck: str | None) -> list[tuple[str, str]]:
    wanted = wanted_names(conn)
    known = {(r["ecosystem"], r["name"]): r["status"] for r in conn.execute("SELECT ecosystem, name, status FROM packages")}
    todo = []
    for key in sorted(wanted):
        status = known.get(key)
        if status is None or status == "error" or recheck == "all" or (recheck == "missing" and status in ("missing", "empty")):
            todo.append(key)
    return todo


FLIP_FROM = ("missing", "empty")  # a name that had no code and now has some


def check_all(conn, recheck: str | None = None, workers: int = 8,
              only: list[tuple[str, str]] | None = None) -> tuple[dict[str, int], list[dict]]:
    """Look names up and store results. Returns (status counts, flips).

    A flip is a name that was missing/empty and now has released code: someone registered a
    name an AI model invented. Flips are stored in `events`.
    """
    conn.executescript(SCHEMA)
    if only is None and (n := prune_stale(conn)):
        console.print(f"Pruned {n} stale name(s) no longer produced by the extractor.")
    todo = only if only is not None else names_to_check(conn, recheck)
    prev = {(r["ecosystem"], r["name"]): r["status"] for r in conn.execute("SELECT ecosystem, name, status FROM packages")}
    console.print(f"Checking {len(todo)} names against PyPI / npm...")
    counts: dict[str, int] = {}
    flips: list[dict] = []
    with httpx.Client(headers={"User-Agent": USER_AGENT}, timeout=30, follow_redirects=True) as client:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            results = pool.map(lambda key: (key, _lookup(client, *key)), todo)
            for i, ((eco, name), res) in enumerate(results, 1):
                now = _now().isoformat(timespec="seconds")
                conn.execute(
                    """INSERT INTO packages (ecosystem, name, status, first_release, last_release, n_versions,
                                            summary, checked_at, first_missing_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, CASE WHEN ? = 'missing' THEN ? END)
                       ON CONFLICT (ecosystem, name) DO UPDATE SET
                         status=excluded.status, first_release=excluded.first_release,
                         last_release=excluded.last_release, n_versions=excluded.n_versions,
                         summary=excluded.summary, checked_at=excluded.checked_at,
                         first_missing_at=COALESCE(packages.first_missing_at, excluded.first_missing_at)""",
                    (eco, name, res["status"], res.get("first_release"), res.get("last_release"),
                     res.get("n_versions"), res.get("summary"), now, res["status"], now),
                )
                conn.execute("INSERT INTO checks (ecosystem, name, status, checked_at) VALUES (?, ?, ?, ?)",
                             (eco, name, res["status"], now))
                counts[res["status"]] = counts.get(res["status"], 0) + 1
                old = prev.get((eco, name))
                if old in FLIP_FROM and res["status"] in ("new", "established"):
                    flip = {"ecosystem": eco, "name": name, "old_status": old, "new_status": res["status"],
                            "first_release": res.get("first_release"), "detected_at": now}
                    flips.append(flip)
                    conn.execute(
                        "INSERT INTO events (ecosystem, name, old_status, new_status, detected_at, details) "
                        "VALUES (?, ?, ?, ?, ?, ?)",
                        (eco, name, old, res["status"], now, f"first release {res.get('first_release')}"),
                    )
                if i % 50 == 0:
                    conn.commit()
                    console.print(f"  {i}/{len(todo)}")
    conn.commit()
    return counts, flips
