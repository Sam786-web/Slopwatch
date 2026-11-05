"""Pulls package names out of model responses.

Two signals:
  - 'install': names in install commands (pip install X, npm i X, uv add X, ...). Strongest signal:
    this is literally what a developer would type.
  - 'import':  names in import/require statements inside code blocks. Python import names can
    differ from package names (cv2 -> opencv-python); Phase 2 resolves that.
"""

from __future__ import annotations

import re
import sys

# ---------- helpers ----------

CODE_BLOCK = re.compile(r"```[^\n]*\n(.*?)```", re.DOTALL)

PY_INSTALL = re.compile(
    r"(?:\bpip3?\s+install|\bpython3?\s+-m\s+pip\s+install|\bpy\s+-m\s+pip\s+install"
    r"|\buv\s+pip\s+install|\buv\s+add|\bpoetry\s+add|\bpipenv\s+install|\bconda\s+install)"
    r"[ \t]+([^\n`;&|#–—]+)",  # stop at dashes: "pip install x - then ..."
    re.IGNORECASE,
)
NPM_INSTALL = re.compile(
    r"(?:\bnpm\s+(?:install|i|add)|\byarn\s+(?:global\s+)?add|\bpnpm\s+(?:add|install|i)|\bbun\s+(?:add|install|i))"
    r"[ \t]+([^\n`;&|#–—]+)",
    re.IGNORECASE,
)

PY_IMPORT = re.compile(r"^[ \t]*import[ \t]+([\w.]+(?:[ \t]*,[ \t]*[\w.]+)*)", re.MULTILINE)
PY_FROM = re.compile(r"^[ \t]*from[ \t]+([\w.]+)[ \t]+import\b", re.MULTILINE)
JS_SPEC = re.compile(
    r"""(?:\brequire\(\s*|\bfrom\s+|^\s*import\s+|\bimport\(\s*)['"]([^'"\n]+)['"]""", re.MULTILINE
)

PY_STDLIB = set(sys.stdlib_module_names) | {"__future__"}
NODE_BUILTINS = {
    "assert", "async_hooks", "buffer", "child_process", "cluster", "console", "constants", "crypto",
    "dgram", "diagnostics_channel", "dns", "domain", "events", "fs", "http", "http2", "https",
    "inspector", "module", "net", "os", "path", "perf_hooks", "process", "punycode", "querystring",
    "readline", "repl", "stream", "string_decoder", "sys", "timers", "tls", "trace_events", "tty",
    "url", "util", "v8", "vm", "wasi", "worker_threads", "zlib", "test", "sqlite",
}

VALID_PYPI = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$")
VALID_NPM = re.compile(r"^(@[a-z0-9][\w.-]*/)?[a-z0-9]([\w.-]*[a-z0-9])?$")

# Words that show up after "pip install" in prose but are not packages.
NOT_PACKAGES = {"the", "a", "an", "it", "this", "that", "them", "package", "packages", "library",
                "libraries", "command", "following", "and", "or", "with", "using", "your", "any", "all",
                "pip", "npm", "install", "python", "node", "via", "first", "then", "dependencies",
                # placeholders models use in generic instructions
                "package-name", "package_name", "packagename", "your-package", "your_package", "yourpackage",
                "my-package", "my_package", "mypackage", "example", "name", "foo", "bar", "module",
                # words seen after "install" in code comments
                "requirement", "requirements", "needed", "required", "uses", "nothing", "anything", "these",
                "those", "everything", "extra", "is", "are", "not", "no"}

# "No pip install needed", "you don't need to npm install ..."
NEGATION = re.compile(r"\b(?:no|not|without|don't|doesn't|never)\b[^\n]{0,12}$", re.IGNORECASE)
# A line that starts with an install command is a command even outside code formatting.
CMD_LINE = re.compile(
    r"^[ \t]*((?:pip3?|python3?\s+-m\s+pip|py\s+-m\s+pip|uv|poetry|pipenv|conda|npm|yarn|pnpm|bun)\s.+)$",
    re.MULTILINE | re.IGNORECASE,
)


def normalize_pypi(name: str) -> str:
    """PEP 503 normalization: lowercase, runs of -_. become '-'."""
    return re.sub(r"[-_.]+", "-", name).lower()


INLINE_CODE = re.compile(r"`([^`\n]+)`")
SHELL_LINE = re.compile(r"^[ \t]*(?:\$|>|PS [^>]*>|C:\\[^>]*>)[ \t]*(.+)$", re.MULTILINE)


def code_or_all(text: str) -> str:
    blocks = CODE_BLOCK.findall(text)
    return "\n".join(blocks) if blocks else text


def code_segments(text: str) -> str:
    """Only the parts of a response that are code: fenced blocks, `inline code`, and shell-prompt lines.

    Install commands are only trusted here; prose like "pip install the needed packages" is ignored.
    """
    parts = CODE_BLOCK.findall(text)
    prose = CODE_BLOCK.sub("\n", text)
    parts += INLINE_CODE.findall(prose)
    parts += SHELL_LINE.findall(prose)
    parts += CMD_LINE.findall(prose)
    return "\n".join(parts)


def _negated(text: str, pos: int) -> bool:
    line_start = text.rfind("\n", 0, pos) + 1
    return bool(NEGATION.search(text[line_start:pos]))


# ---------- install commands ----------

def _install_tokens(arg_text: str) -> list[str]:
    toks = []
    skip_next = False
    for tok in arg_text.split():
        tok = tok.strip("'\"`,()")
        if skip_next:
            skip_next = False
            continue
        if tok in {"-r", "--requirement", "-c", "--constraint", "-e", "--editable", "-i", "--index-url",
                   "--extra-index-url", "-f", "--find-links", "--target", "-t", "--prefix", "-c"}:
            skip_next = True
            continue
        if not tok or tok.startswith("-") or tok.startswith("$") or tok.startswith("<"):
            continue
        toks.append(tok)
    return toks


def pypi_from_install(tok: str) -> str | None:
    if "/" in tok or "\\" in tok or tok.startswith(("git+", "http")) or tok.endswith((".txt", ".whl", ".tar.gz", ".py")):
        return None
    name = re.split(r"[\[<>=!~;@ ]", tok, maxsplit=1)[0]
    if not name or name.lower() in NOT_PACKAGES or not VALID_PYPI.match(name):
        return None
    return normalize_pypi(name)


def npm_from_install(tok: str) -> str | None:
    if tok.startswith(("git+", "http", "file:", ".", "/")):
        return None
    if tok.startswith("@"):
        scope, _, rest = tok[1:].partition("/")
        name = "@" + scope + "/" + rest.split("@", 1)[0] if rest else None
    else:
        name = tok.split("@", 1)[0]
    if not name:
        return None
    name = name.lower()
    if name in NOT_PACKAGES or not VALID_NPM.match(name):
        return None
    return name


# ---------- imports ----------

def python_imports(code: str) -> set[str]:
    names = set()
    for m in PY_IMPORT.finditer(code):
        for part in m.group(1).split(","):
            names.add(part.strip().split(".")[0])
    for m in PY_FROM.finditer(code):
        names.add(m.group(1).split(".")[0])
    return {n for n in names if n and n not in PY_STDLIB and not n.startswith("_")}


def js_imports(code: str) -> set[str]:
    names = set()
    for m in JS_SPEC.finditer(code):
        spec = m.group(1).strip()
        if spec.startswith((".", "/", "node:", "http:", "https:", "data:")) or spec.startswith("~"):
            continue
        parts = spec.split("/")
        name = "/".join(parts[:2]) if spec.startswith("@") else parts[0]
        name = name.lower()
        if name in NODE_BUILTINS or not VALID_NPM.match(name):
            continue
        names.add(name)
    return names


# ---------- main entry ----------

def extract(text: str, ecosystem: str) -> set[tuple[str, str, str]]:
    """Return {(ecosystem, name, kind)} found in one response."""
    found: set[tuple[str, str, str]] = set()
    code_text = code_segments(text)
    for m in PY_INSTALL.finditer(code_text):
        if _negated(code_text, m.start()):
            continue
        for tok in _install_tokens(m.group(1)):
            if (n := pypi_from_install(tok)):
                found.add(("pypi", n, "install"))
    for m in NPM_INSTALL.finditer(code_text):
        if _negated(code_text, m.start()):
            continue
        for tok in _install_tokens(m.group(1)):
            if (n := npm_from_install(tok)):
                found.add(("npm", n, "install"))
    code = code_or_all(text)
    if ecosystem == "pypi":
        found |= {("pypi", n, "import") for n in python_imports(code)}
    else:
        found |= {("npm", n, "import") for n in js_imports(code)}
    return found


def extract_pending(conn) -> tuple[int, int]:
    """Extract mentions from every response not yet processed. Returns (responses, mentions)."""
    rows = conn.execute(
        "SELECT r.id, r.content, p.ecosystem FROM responses r JOIN prompts p ON p.id = r.prompt_id "
        "WHERE r.extracted = 0 AND r.content IS NOT NULL"
    ).fetchall()
    n_mentions = 0
    for r in rows:
        items = extract(r["content"], r["ecosystem"])
        conn.executemany(
            "INSERT OR IGNORE INTO mentions (response_id, ecosystem, name, kind) VALUES (?, ?, ?, ?)",
            [(r["id"], eco, name, kind) for eco, name, kind in items],
        )
        conn.execute("UPDATE responses SET extracted = 1 WHERE id = ?", (r["id"],))
        n_mentions += len(items)
    conn.commit()
    return len(rows), n_mentions
