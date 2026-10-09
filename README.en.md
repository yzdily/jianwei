# JianWei (鉴微) · AI Security Testing Platform

[简体中文](README.md) | **English**

> "See the subtle, perceive the risk in AI"

**An open-source AI security testing platform driven by the continuously maintained [XuanJian (玄鉴)](https://github.com/yzdily/xuanjian) engine**

<p>
  <a href="#quick-start">Quick Start</a> ·
  <a href="#architecture-6-layers">Architecture</a> ·
  <a href="#modules">Modules</a> ·
  <a href="#unified-console-webstatic">Unified Console</a>
</p>

---

## What It Is

JianWei is an **AI application security testing platform** covering the full loop **"asset discovery → attack/evaluation → guardrails → metrics → reporting"**, with targets spanning Web / API / RAG / Agent systems.

- **Not** just another web scanner
- **Not** just an evaluation dataset
- **Not** only a guardrail

It is a platform that **productizes red-team capability and makes AI risk quantifiable**.

## Core Flywheel

```
XuanJian engine (real attack execution) + JianWei platform layer (AI-native evaluation / guardrails / metrics)
    → evaluation data feeds back into SKILLs and rules → the more you test, the more accurate it becomes
```

**In one sentence**: JianWei upgrades "a XuanJian that can attack" into "an AI security testing platform that can evaluate, defend, and quantify".

## Architecture (6 Layers)

```
┌───────────────────────────────────────────────────────────────────────────────────────────┐
│  L5  Reporting / Compliance   Compliance · Remediation · Audit trail · MLPS               │
├───────────────────────────────────────────────────────────────────────────────────────────┤
│  L4  Metrics & Evaluation   ASR / Refusal / Leak / Block rate · Regression baseline       │
├───────────────────────────────────────────────────────────────────────────────────────────┤
│  L3  Guardrail sec_shield   Input validation → Policy engine → Output filter (pluggable)  │
├───────────────────────────────────────────────────────────────────────────────────────────┤
│  L2  Attack / Eval   Injection · Jailbreak · Poisoning · Over-retrieval · Excessive agency│
├───────────────────────────────────────────────────────────────────────────────────────────┤
│  L1  Asset / Interface   AI app asset discovery (Web / API / RAG / Agent tool surface)    │
├───────────────────────────────────────────────────────────────────────────────────────────┤
│  L0  Engine Base (XuanJian v2.0, actively maintained)                                     │
│      Crawling · Orchestration · Parallelism · Context · Harm validation                   │
└───────────────────────────────────────────────────────────────────────────────────────────┘
```

| Layer | Responsibility | Status |
|---|---|---|
| **L0 Engine Base** | Real attack execution, browser/proxy, orchestration, harm validation | XuanJian v2.0 (actively maintained) |
| **L1 Asset / Interface** | Identify the attack surface of the target AI app (passive probing) | ✅ Implemented (`_checks_web.asset_discovery`) |
| **L2 Attack / Evaluation** | Red-team case execution engine (LLM 13 checks + injection test set + RAG/Agent evaluation + skill supply chain) | ✅ Implemented |
| **L3 Guardrail sec_shield** | Input/output validation, sensitive-content blocking, pluggable policies | ✅ Implemented (`core/ai_sec/sec_shield`) |
| **L4 Metrics** | ASR / refusal rate / leak rate / shield block rate, regression baseline | ✅ Implemented (`core/ai_sec/metrics`) |
| **L5 Reporting / Compliance** | Auditable security reports, remediation list, MLPS alignment | ✅ Implemented (LLM Top10 section + ATLAS + SARIF + full compliance assembly; MLPS as reference alignment) |

## Modules

### L2 · Attack / Evaluation

| Module | Function | Directory | Status |
|------|------|------|------|
| **LLM Vulnerability Scanner** | OWASP LLM Top 10 + Agent/MCP automated detection (13 checks) | `core/ai_sec/llm_top10/` | ✅ Implemented |
| **Prompt Injection / Jailbreak Test Set** | Reusable injection/jailbreak probe library (direct/indirect/jailbreak/multimodal) | `core/ai_sec/prompt_injection/` | ✅ Implemented (22 built-in probes + adopts `skills_my/redteam/`) |
| **Agent Security Evaluation** | Tool-call privilege escalation / orchestration escape / memory poisoning | `core/ai_sec/agent_eval/` | ✅ Implemented (3 evaluators) |
| **RAG Security Detection** | Knowledge-base poisoning / unauthorized retrieval / provenance consistency | `core/ai_sec/rag_sec/` | ✅ Implemented (3 detectors) |

> All three **reuse engine-level primitives** (`core/llm_security/*`), providing only "adapter + case library + runner" without rewriting the detection logic.

### L3 · Guardrail

| Module | Function | Directory |
|------|------|------|
| **sec_shield** | Input validation → Policy engine → Output filtering, pluggable, self-attack/self-defense closed loop | `core/ai_sec/sec_shield/` |

### L4 · Metrics

| Module | Function | Directory |
|------|------|------|
| **Metrics** | ASR / refusal rate / leak rate / shield block rate / regression baseline (incl. `hook.py` flywheel hook + `baseline.py` regression comparison) | `core/ai_sec/metrics/` |

### Scanning Engine & Dual-Axis Model

| Module | Function | Directory |
|------|------|------|
| **Dual-axis scanning strategy** | `TargetType`(web/api/llm_app/agent/rag/skill) × `TestStrategy`(passive/standard/redteam/compliance) factory | `core/scan_strategies.py` |
| **FastScanner wiring layer** | Multiple-inheritance mixin + `getattr(_check_{rule})` dispatch, zero-intrusion integration | `core/fast_scanner/` |
| **Skill supply-chain scanning** | Static analysis (pattern/AST/OSV/semantic/YARA), never executes the scanned object, SARIF export | `core/llm_security/skill_scan/` |
| **3 new checks** | RAG poisoning / Agent escape / MCP abuse | `core/llm_security/{rag_poison,agent_eval,mcp_exploit}.py` |
| **AI risk matrix integration (E)** | `ai` domain sidecar attribution + `AIMatrixRunner` (attribution → execution → gate decision → matrix cell), wired into the engine testflow matrix (zero intrusion) | `core/ai_sec/ai_matrix/` |
| **Benchmark** | LLMVault-annotated range replay, producing detection rate / false-positive rate | `core/llm_security/benchmark.py` + `tests/golden/` |
| **Web API** | Skill upload scanning + dual-axis scan API + digpool SSE + SARIF | `web/api/` |
| **CLI** | `scan-skill` / `scan` command line | `core/cli.py` |

## Design Principles

- **Evidence over probability** (an extension of the XuanJian iron rule): every LLM/Agent risk must come with **reproducible evidence** (payload + response + verdict), never a probabilistic guess
- **sec_shield self-attack/self-defense closed loop**: the L3 guardrail also serves as the "target under test" for L2 evaluation — using JianWei's own red-team probes to test its own guardrail
- **Reuse the harm_validation verdict paradigm**: AI risk rating reuses the "harm validation + evidence" logic
- **Zero-intrusion extension**: the platform layer only consumes the engine's public contract (`getattr(_check_{rule})` to append rule names + mixin), never modifying the engine in reverse

## Quick Start

> **Requirements**: Python >= 3.10

```bash
# 1. Clone the repository
git clone https://github.com/yzdily/jianwei.git
cd jianwei

# 2. Install dependencies (including the XuanJian engine)
pip install -r requirements.txt
# Minimal dependencies (CLI + workbench only, no heavy deps):
pip install -r requirements-min.txt

# 3. Configure the LLM
cp .env.example .env

# 4. Launch (the console runs with zero keys)
python start.py            # print module list and platform status
python start.py --serve    # start Web API + unified console → http://127.0.0.1:8000/
```

## Quick Usage

```bash
# Statically scan a skill package / MCP server package (directory / zip / single file / URL / git)
python start.py scan-skill ./my-skill/ --strategy redteam --format sarif
python -m core.cli scan-skill ./my-skill/ --strategy standard

# Dual-axis scan target (Web / API / LLM app / Agent / RAG)
python -m core.cli scan https://llm.example.com/v1/chat --target-type llm_app --strategy standard

# Start the Web API + unified console (--host / --port / --reload optional)
python start.py --serve --port 8000
# equivalent to: uvicorn web.api:app --reload
```

### Unified Console (web/static)

Single-page console, zero-dependency vanilla JS, no external CDN (works offline / on intranet):

| No. | View | Backend endpoint |
|------|------|----------|
| 01 | Dual-axis Scan | `POST /api/scan/target` |
| 02 | Upload Skill | `POST /api/scan/skill/upload` + `GET /api/scan/skill/{id}` + `/sarif` |
| 03 | Agent Workbench | `POST /api/digpool/run` (SSE stream) + `/session/empty` |
| 04 | Report Center | `POST /api/ai-sec/report/scan` + `GET .../report/{id}` + `/sarif` |
| 05 | Benchmark | `GET /api/ai-sec/benchmark/summary` |
| 06 | L4 Metrics | `POST /api/ai-sec/metrics/summary` |
| 07 | System Health | `GET /health` + `GET /openapi.json` |
| 08 | System Settings | `GET /api/platform/info` (sanitized runtime) |
| 09 | RBAC | `GET/POST/DELETE /api/rbac/{overview,users,groups,roles}` |

> The console has a **login gate**: `POST /api/auth/login` first, then the session is injected via
> `Authorization: Bearer`. All product routes are checked by `Depends(require_auth)`; `/api/auth/*`
> (login/me/logout) are the only public endpoints. Multi-user + RBAC live in `web/api/auth.py` and
> `web/api/rbac_api.py` (in-memory storage), with per-role permission checks (`scan.run` / `skill.upload`
> / `digpool.run` / `report.read` / `rbac.manage`, etc.). When no key is configured, it degrades to
> local-dev allow-all.

Frontend layout (each file stays small and focused):

```
web/static/
├── index.html            # Shell: sidebar / topbar / user card / modal mount points
├── css/{tokens,shell,components}.css
└── js/
    ├── api.js            # fetch wrapper + SSE-over-fetch reader
    ├── ui.js             # DOM helpers / Toast / modal / Markdown / findings table
    ├── login.js          # Login gate (unauthenticated mask + session / logout)
    ├── views/*.js        # One module per view (9 total), registering into JW.viewList
    └── app.js            # Hash router + nav rendering + user menu
```

Other endpoints (for CLI / CI):

```
#  → POST /api/scan/skill/upload  (multipart: file + strategy)
#  → POST /api/scan/target         (JSON: url + target_type + strategy)
#  → POST /api/digpool/chat        (SSE conversational pentesting terminal)
#  → GET  /api/scan/skill/{scan_id}/sarif
```

Run tests:

```bash
# Unit / API / contract tests (default path, fast)
pytest                      # equivalent to pytest -m "not e2e"

# Browser end-to-end (Playwright: upload Skill / dual-axis scan / report / health / RBAC)
pip install -r requirements-dev.txt
pytest -m e2e               # uses local Chrome/Edge if present; otherwise playwright install chromium
```

> E2E and unit tests are **two separate runs**: Playwright's sync API occupies the event loop in-process,
> which conflicts with pytest-asyncio async cases in the same process, so `pytest.ini` defaults to
> `addopts = -m "not e2e"` and CI should run it as an independent step.

## Agentic Loop Workbench

> JianWei's agent workbench lives in `core/digpool/`: an Agentic Loop chaining "plan → tool execution → validate → report",
> and runs with zero dependencies (it automatically degrades to StubCore when the XuanJian engine is missing, no LLM key required).
> Its UI entry is console view **03 Agent Workbench**.

```bash
# End-to-end demo: skill-scan real detection + six-dimension governance approval gate + LOOP run
python -m core.digpool demo --target tests/fixtures/malicious_skill
python -m core.digpool demo --target tests/fixtures/clean_skill
python -m core.digpool tools          # list registered curated tools
python -m core.digpool plan  --goal "run one security test on the target" --target ./my-skill/  # goal → task DAG + budget
python -m core.digpool loop  --trigger sqli_possible                                            # run the LOOP once
python -m core.digpool solve --target ./my-skill/                                               # closed loop: plan→execute→verify→report→memory
```

## Relationship with XuanJian

| Dimension | XuanJian | JianWei |
|---|---|---|
| Role | Continuously maintained open-source engine / kernel | Open-source AI security testing platform built on top of it |
| Repository | `github.com/yzdily/xuanjian` (MIT, actively maintained) | `github.com/yzdily/jianwei` (Apache-2.0) |
| Audience | Security researchers, self-hosting enthusiasts | Enterprise AI teams, red teams, compliance |
| Boundary | Engine / rules / SKILL (upstream, continuously evolving) | Core platform (L1–L5 + test sets + dashboard), fully open source |

> **Dependency model**: The XuanJian engine is actively maintained (features are not frozen); JianWei follows the engine's evolution, and the platform layer only consumes the engine's public contract without modifying it in reverse.

## License

- JianWei platform layer: **Apache-2.0**
- XuanJian engine (dependency): **MIT**

> **Legal notice**: This tool is intended only for legally authorized security testing. Unauthorized use is illegal. See [DISCLAIMER.md](DISCLAIMER.md).
