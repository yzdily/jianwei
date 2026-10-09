# 鉴微 JianWei 开发总览

> 基于 `818/` 设计文档（AI安全测试平台_MASTER_PLAN、LLM漏洞扫描器设计方案、Skill供应链扫描设计方案、OWASP映射），
> 在鉴微（玄鉴 v2 持续维护引擎之上的平台层）落地核心能力。
> **最新事实源**：[`818/10月8号技术方案.md`](./818/10月8号技术方案.md)。本文为**开发总览**，随代码演进更新。

## 当前能力盘点（截至 2026-10-08）

| 能力 | 目录 | 状态 |
|---|---|---|
| 统一日志 | `core/log.py` | ✅ |
| 双轴扫描模型（6 目标类型 × 4 策略） | `core/scan_strategies.py` | ✅ |
| FastScanner 接线层（零侵入 mixin） | `core/fast_scanner/` | ✅ |
| LLM 漏洞扫描器（13 check） | `core/ai_sec/llm_top10/` | ✅ |
| Prompt 注入/越狱测试集（22 内置 + skills 收编） | `core/ai_sec/prompt_injection/` | ✅ |
| Agent 安全评测（工具越权/编排逃逸/记忆投毒） | `core/ai_sec/agent_eval/` | ✅ |
| RAG 安全检测（投毒/越权检索/溯源） | `core/ai_sec/rag_sec/` | ✅ |
| AI 风险矩阵接入（`ai` 域 sidecar + `AIMatrixRunner`） | `core/ai_sec/ai_matrix/` | ✅ E2/E3 |
| 技能供应链静态扫描（5 分析器 + SARIF） | `core/llm_security/skill_scan/` | ✅ |
| sec_shield 护栏 | `core/ai_sec/sec_shield/` | ✅ |
| 评测度量（ASR/拒答率/泄露率/拦截率 + 飞轮挂钩 + 基线回归） | `core/ai_sec/metrics/` | ✅ |
| L5 报告（LLM Top10 章节 + ATLAS + SARIF + **完整合规组装**） | `core/ai_sec/report/` | ✅ |
| AI 挖洞工作台（Agentic Loop，零依赖可跑） | `core/digpool/` | ✅ |
| Web API（技能上传/双轴扫描/digpool SSE） | `web/api/` | ✅ |
| CLI（`scan-skill` / `scan`） | `core/cli.py` | ✅ |
| 基准脚手架（LLMVault 标注回放，32 样本） | `core/llm_security/benchmark.py` + `tests/golden/` | ✅ |
| 技能市场（`skills_my/**/SKILL.md` 自动登记为 curated 工具） | `core/digpool/tools/builtins.register_skills` | ✅ F2 |

## 关键实现说明

### 1. 统一日志 `core/log.py`
`get_logger(name)` 轻量封装，统一各模块日志来源。

### 2. 双轴扫描模型 `core/scan_strategies.py`
- `TargetType`：web / api / llm_app / agent / rag / **skill**
- `TestStrategy`：passive / standard / redteam / compliance
- `get_scan_strategy(target_type, strategy)` → `ScanConfig.enabled_rules`

### 3. 扫描引擎接线层 `core/fast_scanner/`
- `_models.py`：`ScanTarget` / `VulnFinding`（统一 schema）
- `_checks_llm.py`：委派 `core.ai_sec.llm_top10.LLMScanner`（13 check）
- `_checks_skill.py`：委派 `core.llm_security.skill_scan`
- `_checks_web.py`：`security_headers` + 被动 `asset_discovery`
- `_engine.py`：`FastScanner(...)` 多重继承 + `getattr(_check_{rule})` 零侵入分发

### 4. 技能供应链静态扫描 `core/llm_security/skill_scan/`
- `ingest.py`：目录/单文件/zip/URL/git 摄入；**防 zip-bomb + 路径穿越防护 + 扫完即焚**
- `analyzers/`：pattern / ast_behavior / supply_chain（OSV.dev）/ semantic（LLM）/ yara_scan
- `scoring.py`：0–100 风险分 + 可执行脚本 ×1.3；`report.py`：SARIF 2.1.0 + 退出码门禁
- **信任边界**：绝不执行被扫对象

### 5. 三个新增 check + 平台三测试集
- 引擎级：`core/llm_security/{rag_poison,agent_eval,mcp_exploit}.py`（接入 `LLMScanner.scan()`，覆盖 13 check）
- 平台级（复用上述原语，只做适配+用例+运行器）：
  - `core/ai_sec/prompt_injection/`（22 内置探针 + `ProbeRegistry`/`ProbeRunner`）
  - `core/ai_sec/agent_eval/`（3 评估器）
  - `core/ai_sec/rag_sec/`（3 检测器）
- 全部支持离线 responder 回放，不依赖真实 LLM 端点。

### 6. AI 风险矩阵接入 `core/ai_sec/ai_matrix/`（E 阶段 1）
`AIEndpointTagger` 给 LLM/Agent/RAG 端点补打 `ai` 域（只追加不删改引擎 8 域），接入引擎 testflow 矩阵。

### 7. Web API `web/api/`
- `skill_scan_api.py`：`POST /api/scan/skill/upload` + `GET /api/scan/skill/{id}` + SARIF
- `scan_api.py`：`POST /api/scan/target`（双轴）
- `digpool_api.py`：`POST /api/digpool/chat`·`/run`（SSE）+ `/ingest`·`/ingest/proxy`·`/ingest/cert`
- `ai_sec_api.py`：报告 + 度量 + 基准
- `__init__.py`：`create_app()` 应用工厂

### 8. CLI `core/cli.py` + `start.py`
`scan-skill <path>` / `scan <target>`（双轴）

### 9. 工作台 `core/digpool/`
Agentic Loop：session/agent/core_link/scope/ingest/loops/governance/executor/tools；零依赖可跑。
闭环（M1/M3/M4）：`agents/planner.py`（目标→DAG+预算）、`agents/validator.py`（证据门+佐证门双重去误报）、
`agents/reporter.py`（报告落盘）、`memory/store.py`（项目级记忆）；`session.plan()/solve()` 贯通 `目标→DAG→执行→验证→报告→记忆`。

### 10. 基准
`core/llm_security/benchmark.py` + `tests/golden/llmvault_benchmark.jsonl`（32 条标注样本，含 15 负样本）；
Golden 回放 recall/precision/accuracy 均 100%（非 live 实测）。

## 验证要点
- `pytest tests/ -q` → **212 passed / 1 skipped**（新增工作台闭环 `tests/test_digpool_closure.py` 13 项）；`--cov=core` 行覆盖率 **74%**（2026-10-08）
- 零依赖门禁：`tests/test_digpool_zerodep.py`（子进程屏蔽 yaml/httpx 等，验证工作台仍可导入/可用）
- CI：`.github/workflows/ci.yml`（全量测试 × Py3.10–3.12 + 零依赖门禁 + 覆盖率）
- `python -m core.cli scan-skill <恶意skill目录>` → 命中硬编码密钥/os.system/指令覆盖，`safe_to_install=False`，exit=1
- `POST /api/scan/skill/upload`（zip）→ 202 + scan_id → SARIF 2.1.0

## 后续建议（未做/部分）
- L5 完整合规报告（覆盖矩阵 + PoC + 整改清单 + 等保对齐）——见《鉴微优化方案》§4。
- L4 度量飞轮挂钩（指标接进 Finding/报告）——见《鉴微优化方案》§3。
- ~~工作台 Planner/Validator/Reporter/Memory 闭环（M1/M3/M4）~~ —— ✅ 已落地：`core/digpool/agents/{planner,validator,reporter}.py` + `core/digpool/memory/store.py`，`session.solve()` 一键贯通。
- AI 风险矩阵：E3 AIMatrixRunner / E4 链扩展 / E5 报告 —— 见《AI风险接入testflow矩阵_设计稿》。
- `core/fast_scanner` 的 Web 规则目前仅 `security_headers`/`asset_discovery` 为平台层实现；玄鉴引擎的 Web 规则为上游来源（未复制入本仓）。
- ✅ 3 个既有 API 漂移已修复（skill_scan 补齐 `scan_skill`/`to_sarif`/`render_markdown`/`MAX_*`/`summarize`；`upload.py`/`mcp_tool.py` 修复；`test_skill_scan_m123.py` 改写为当前 API）。
