# Security policy and disclosure process

SlopWatch handles two kinds of sensitive material: **unregistered hallucinated package names** (useful to attackers) and **possibly malicious packages** (untrusted code). This document describes how both are handled.

## Reporting a problem with SlopWatch

If you find a vulnerability in this project, or a way it could leak protected names, please use GitHub's **private vulnerability reporting** (Security tab → "Report a vulnerability") instead of opening a public issue.

## How findings are handled

| Situation | What SlopWatch does |
|---|---|
| A model invents a package name that doesn't exist | The name is stored **encrypted** (`data/watchlist.json.enc`), masked on the dashboard, and blocked from commits by `slopwatch leakcheck`. It is re-checked daily. |
| Someone registers a tracked fake name | The watchtower records a *flip*, downloads the package **into memory only** and scans it statically. A GitHub issue with counts only (no names) is opened. |
| The scan scores **low** | Logged. The name is shown on the dashboard as "registered", which warns developers who meet it. |
| The scan scores **medium or high** | Manual review of the evidence. If malicious, it is reported to the registry first (below) and only discussed publicly after the registry has acted, or after 7 days without a response. |

SlopWatch **never installs, extracts to disk or executes** scanned packages, and **never registers** hallucinated names itself.

## Reporting a malicious package to a registry

**PyPI**
1. Open `https://pypi.org/project/<name>/` and use **"Report project as malware"**.
2. For anything urgent or wide-reaching, also email **security@pypi.org** with the evidence below.

**npm**
1. Open `https://www.npmjs.com/package/<name>` and use **"Report malware"**.
2. Or report through **https://www.npmjs.com/support** (category: security / malware).

**Include in the report:**
- package name, version and SHA-256 of the scanned archive (stored in the `scans` table);
- the findings, with file and line (`slopwatch scan <ecosystem> <name>`);
- the fact that the name was hallucinated by AI models, and the date it was first seen missing (`first_missing_at`);
- a note that the package was analysed statically and never executed.

Record the report date and registry response in the issue. Once the registry has removed the package, the finding can be published (dashboard, write-up), including the name.
