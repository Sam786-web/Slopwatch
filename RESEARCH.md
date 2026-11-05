# AI coding assistants invent packages: preliminary findings from SlopWatch

*Samiya Patel · November 2026 · preliminary report (first collection run, small sample)*

## TL;DR

- Across **451 package install recommendations** from 4 AI models, **4.0%** pointed to packages that **do not exist** (95% CI 2.5–6.2%).
- **npm answers were about 4x worse than PyPI answers**: 7.5% vs 1.8%, with non-overlapping confidence intervals.
- **Two different model families independently invented the same fake npm package name.** Hallucinated names are predictable, which is what lets attackers squat them.
- Hallucinations cluster where no well-known library fits: **12% for AI / modern-stack tasks** and **10% for niche tasks**, versus **0% for common tasks**.
- **7 of the 17 fake names were scoped npm packages** under well-known organisations' namespaces. They look official, which makes them more dangerous.
- None of the fake names has been registered yet. SlopWatch checks them every day.

Live data: https://sam786-web.github.io/Slopwatch/ · Code: https://github.com/Sam786-web/Slopwatch

## Why this matters

When an AI assistant tells a developer to run `npm install <name>` and `<name>` doesn't exist, the install fails harmlessly at first. But anyone can register that name on npm or PyPI. If an attacker publishes malware under it, every developer who later gets the same suggestion installs the attacker's code, often with install scripts that run immediately.

This attack is called **slopsquatting**. It only works if hallucinations repeat, because attackers need to predict the names. Earlier academic work measured this in one-off studies. SlopWatch measures it **continuously** and **watches the fake names** for the moment someone registers one.

## Method

| Step | Detail |
|---|---|
| Prompts | 94 developer tasks (common, security, AI / modern stack, niche data formats, infra, niche) in Python and Node.js, each asked two ways: *"Write a script that will…"* and *"What is the best library to…?"*, for 188 prompts. |
| Models | gpt-oss-120b and Qwen 3.8 27B (via Groq), Gemini 3.5 Flash (Google AI Studio), and OpenRouter's free model router. All free tiers; temperature 0.7. |
| Extraction | Package names are taken from install commands (`pip`, `uv`, `poetry`, `npm`, `yarn`, `pnpm`, …) **inside code only**. Prose ("pip install the needed packages"), negations ("no pip install needed") and placeholders are ignored. |
| Verification | Every name is looked up on the PyPI and npm registries and classified as established, new (< 90 days), empty (reserved, no code) or **missing**. |
| Metric | Hallucination rate = install recommendations naming a **missing** package ÷ all install recommendations. Imports are tracked separately, because import names often differ from package names (`cv2` comes from `opencv-python`). |

The run covers **223 answers to 103 distinct prompts**. Free-tier quotas stopped some models early, and collection continues daily.

## Results

### By model

| Model | Install recommendations | Fake | Rate |
|---|---|---|---|
| OpenRouter free router | 118 | 8 | 6.8% |
| Qwen 3.8 27B | 44 | 2 | 4.5% |
| gpt-oss-120b | 259 | 8 | 3.1% |
| Gemini 3.5 Flash | 30 | 0 | 0.0% |

Per-model samples are still small and the intervals overlap, so this is **not yet a ranking**. Gemini's 0% comes from only 30 recommendations.

### By ecosystem: the clearest result

| Ecosystem | Rate | 95% CI |
|---|---|---|
| npm (JavaScript) | **7.5%** (13 / 173) | 4.4% – 12.4% |
| PyPI (Python) | **1.8%** (5 / 278) | 0.8% – 4.1% |

A plausible explanation: npm's namespace is enormous and fragmented, with many tiny single-purpose packages and scoped packages under organisation names. That makes it easy for a model to "complete" a name that sounds right. 7 of the 13 fake npm names were **scoped** (`@org/something`) under real, well-known organisations' scopes.

### By task category

| Category | Rate |
|---|---|
| AI / modern stack (RAG, MCP servers, token counting, tracing) | 12.1% (8 / 66) |
| Niche hardware and protocols (BLE, NFC, DMX, OPC UA, …) | 9.8% (4 / 41) |
| Security tooling | 4.1% (4 / 98) |
| AI / data | 1.5% (1 / 66) |
| Niche data formats | 1.5% (1 / 68) |
| Infra / DevOps | 0.0% (0 / 30) |
| Common tasks (PDFs, email, CSV, …) | **0.0%** (0 / 82) |

The **fastest-moving ecosystems** (AI tooling) produce the most fake names, probably because the real package landscape changed after the models' training data was collected.

### By how the question is asked

| Phrasing | Rate |
|---|---|
| "What is the best library to…?" | 6.4% (95% CI 3.7–10.8%) |
| "Write a script that will…" | 2.3% (95% CI 1.0–4.9%) |

This is suggestive but not yet conclusive, since the intervals overlap slightly. Asking a model to *name* a library invites it to produce a plausible name. Asking it to *write code* anchors it to libraries it has actually seen used.

### Repeatability

One fake npm name was produced by **both gpt-oss-120b and Qwen**, two unrelated model families answering the same task. That is the property slopsquatting needs: an attacker who registers that name catches developers using either model. A dedicated repeatability study (each prompt asked several times) is the next step.

## Watchtower

All fake names are re-checked every day by a GitHub Action. If one gets registered, SlopWatch downloads it **into memory only** (never installed, never extracted, never executed) and scores it for install-time hooks, `exec` of decoded payloads, exfiltration endpoints and credential access, with Datadog's GuardDog as a second opinion. As of this report, **0 of the tracked names have been registered.**

## What developers can do

1. **Don't copy install commands blindly.** Check the package page: age, downloads, repository link, maintainers.
2. **Be most careful with npm, scoped packages and AI-tooling tasks.** That's where this data shows fake names concentrate.
3. **Prefer "write the code" prompts** over "which library should I use?" prompts.
4. **Use lockfiles, and disable install scripts where possible** (`npm config set ignore-scripts true`, enabling them per package as needed).
5. **Organisations:** route installs through a proxy or allowlist (an internal registry mirror) so a brand-new package can't be pulled in unnoticed.

## Responsible handling

- Unregistered fake names are **not published**. They are stored encrypted in the repository and masked on the dashboard, and a pre-commit check blocks commits that contain them.
- If a registered fake name turns out to be malicious, it is reported to the registry's security team **before** being discussed publicly.
- SlopWatch never registers hallucinated names itself.

## Limitations

- **Small sample:** 451 install recommendations and 18 hallucinations. Per-model differences are not yet statistically meaningful.
- **Free tiers only:** these are the models developers can use for free, not every popular assistant.
- **Snapshot of time:** "missing" means missing at check time. A name may also belong to a package that was deleted earlier.
- **Two phrasings and 94 tasks:** real developer questions are more varied.

## Next steps

- Keep collecting daily until every model has answered all prompts.
- Run a repeatability study (`--runs 3`) to rank fake names by how predictable they are.
- Add more models and real-world questions from public Q&A datasets.
- Publish an updated report with per-model confidence intervals.

*Methodology, code and tests are open source: https://github.com/Sam786-web/Slopwatch*
