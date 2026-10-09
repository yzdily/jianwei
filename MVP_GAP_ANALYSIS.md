# 鉴微 JianWei · MVP 范围纠偏与「还有哪些要改」清单

> 整理日期：2026-09-12 ｜ **状态更新：2026-10-08**
> 对标依据：
> - `F:\xuanjian-main\hollowing-optimization-plan\plan\0912_DigPool_tech_analysis.md`（斗象蛙池AI / DigPool AI 竞品技术方案）
> - `F:\xuanjian-main\hollowing-optimization-plan\plan\0912_XuanJian_AI_Demo_TechPlan.md`（玄鉴 AI 挖洞工作台 Demo 技术方案）
> 关联代码：`core/digpool/`
> **最新待办与 DoD**：见 [`818/鉴微优化方案_2026-10-08.md`](./818/鉴微优化方案_2026-10-08.md)。

---

## 0. 纠偏结论（先说重点）

**之前那版 `mvp/`（纯静态扫描器）方向错了。** 它只覆盖了"Tool & Data 层"里的一个工具（skill_scan），不是 MVP 本身。

正确的 MVP 是 **`core/digpool/` —— 对标蛙池AI / 玄鉴 DEEP 档的「AI 挖洞工作台」**：
基模 + Multi-agent + Memory + 工具链 + 治理门控的 Agentic Loop 骨架。

> 已删除跑偏的 `mvp/` 目录，避免方向混淆。

---

## 1. MVP 已落地（零依赖可跑）

| 模块 | 文件 | 状态 | 说明 |
|---|---|---|---|
| 运行时后端 | `core/digpool/core_link.py` | ✅ | 引擎可用则链接，否则降级 `StubCore` |
| Agentic Loop 主循环 | `core/digpool/session.py` | ✅ | 会话/事件流/SSE、空跑通、LOOP 钩入、对话入口 |
| 多智能体 | `core/digpool/agent.py` | ✅ | `DeterministicAgent`（零依赖）+ `LLMAgent`（真实驱动） |
| 动态 Scope / 流量语料 | `core/digpool/scope.py` + `ingest.py` | ✅ | 代理/合规证书抓包 → 运行时扩界 |
| LOOP 引擎 | `core/digpool/loops/` | ✅ | loop_controller / gates / vuln_chain / 11 trigger |
| Tool & Data 工具层 | `core/digpool/tools/` | ✅ | `Tool/ToolCall/risk_level` 协议 + 注册表 + 4 curated 工具 |
| 六维治理 · 审批/熔断 | `core/digpool/governance.py` | ✅ | 低风险自动 / 高风险人工审批单；预算/重复熔断 |
| 工具执行器 | `core/digpool/executor.py` | ✅ | 治理裁决后派发工具，结果转 LOOP `Finding` |
| CLI 演示入口 | `core/digpool/__main__.py` | ✅ | `python -m core.digpool demo/tools/loop/plan/solve` |
| **Web SSE 入口** | `web/api/digpool_api.py` | ✅ 2026-10 | `/chat`·`/run`(SSE) + ingest 三通道 |
| **真实 LLM 接 Agent** | `core/digpool/agent.py` | ✅ 2026-10 | `LLMAgent` 经 `DIGPOOL_LLM_API_KEY` |
| **M1 Planner** | `core/digpool/agents/planner.py` | ✅ 2026-10 晚 | 目标→`RECON→…→REPORT` DAG + 预算；Deterministic/LLM 双实现 |
| **M3 Validator** | `core/digpool/agents/validator.py` | ✅ 2026-10 晚 | 证据门 + 佐证门双重去误报；引擎缺失降级 `StubValidator` |
| **M4 Reporter + 记忆** | `core/digpool/agents/reporter.py` + `memory/store.py` | ✅ 2026-10 晚 | 报告落盘（覆盖矩阵/详情/证据）+ 项目级记忆 `recall()` |
| **闭环编排** | `core/digpool/session.py` `plan()`/`solve()` | ✅ 2026-10 晚 | plan→execute→verify→report→memory 贯通 |

---

## 2. 已修的真实阻塞 bug

| # | 问题 | 根因 | 修复 |
|---|---|---|---|
| B1 | `import core.digpool` 直接失败 | `loops/loop_controller.py` 顶层 `import yaml` | yaml 可选，缺失回退内嵌矩阵 |
| B2 | `skill_scan` 导不进 | 父包顶层 `from .attacks import`（attacks 顶层 `import httpx`） | 父包 PEP 562 懒加载；httpx 移入函数内 |
| B3 | `supply_chain.py` 顶层 `import httpx` 离线崩溃 | 重依赖耦合 | 改为函数内懒加载 |

---

## 3. 「还有哪些要改」——按优先级（状态更新 2026-10-08）

### P0 · 可运行性 / 检测信任

- [x] **B1/B2/B3 解耦重依赖** —— 已完成，零依赖可跑。
- [x] **clean_skill 否定句误报** —— 已修：`core/llm_security/skill_scan/analyzers/pattern.py` 新增否定窗口
      （`_NEGATION_WINDOW=30` + `_match_without_negation`）。
- [x] **依赖分层** —— 已加 `requirements-min.txt`（MVP 工作台零依赖子集）。

### P1 · 架构完整性（对齐 TechPlan 的 M0–M4）

| TechPlan 里程碑 | 目标 | 现状（2026-10-08 晚） | 待改 |
|---|---|---|---|
| M1 Planner | 自然语言 → 任务 DAG + 预算估算 | ✅ 已实现 `agents/planner.py`（目标→DAG+预算，Deterministic/LLM） | LLM 计划路径可再补端到端用例 |
| M2 Recon + Runtime | 浏览器代理执行 + 流量监听 | Scope/ingest ✅；Runtime 依赖引擎 | 明确标注「依赖引擎」或 vendored 最小运行时 |
| M3 Validator 去误报 | 双重去误报（harm_validation） | ✅ 已实现 `agents/validator.py`（证据门+佐证门；接引擎 harm_validation，缺失降级 Stub） | 引擎在线时校验 harm_validation 契约 |
| M4 Reporter + 记忆 | 报告 + 项目记忆沉淀 | ✅ 已实现 `agents/reporter.py` + `memory/store.py`（报告落盘 + 项目级记忆 recall） | — |
| 治理-预算/验收 | 预算计量 + 证据驱动验收 | 审批/熔断 ✅；`solve()` 按计划预算计量；验收接 Validator ✅ | 接真实 token 计数（细粒度） |

### P2 · 平台层补全（与 L0–L5 对齐）

- [x] **Web SSE 入口** —— 已完成：`web/api/digpool_api.py`（`/chat`·`/run` SSE + ingest 三通道）。
- [x] **真实 LLM 接 Agent** —— 已完成：`LLMAgent` + `get_agent()`（读 `DIGPOOL_LLM_API_KEY`）。
- [x] **三个平台测试集补实（A1/A2/A3）** —— 已完成：
      `core/ai_sec/prompt_injection/`（22 内置探针 + 收编 skills）、
      `core/ai_sec/agent_eval/`（3 评估器）、`core/ai_sec/rag_sec/`（3 检测器）；
      均复用引擎级 `core/llm_security/*` 原语，含离线测试。
- [x] **AI 风险矩阵接入 sidecar（E2）** —— 已完成：`core/ai_sec/ai_matrix/AIEndpointTagger`。
- [x] **L4 度量挂钩**：`metrics/hook.py`（MetricsHook + render_metrics_section）+ `baseline.py`（Golden 回归对比），已接入 L5 报告。
- [x] **L5 报告模板**：`report/compliance_report.py::build_full_report` 组装覆盖矩阵 + 详情 + PoC + 整改清单 + 等保参考对齐。
- [x] **Skill/MCP 市场形态**：`builtins.register_skills` 扫描 `skills_my/**/SKILL.md` 自动登记为 `source="skill"` curated 工具。

### P3 · 文档 / 测试一致性

- [x] **架构口径统一** —— README/ARCHITECTURE 已改：去掉「封板」、L0–L5 状态与三测试集状态如实；
      平台层 L1–L5 与 `core/digpool` 工作台层关系已讲清。
- [x] **零依赖测试路径**：`tests/test_digpool_zerodep.py`（子进程屏蔽第三方依赖，验证工作台导入/降级/技能市场/内嵌矩阵）。
- [x] **补齐被引用文档**：`docs/digpool_workbench_roadmap.md` 已建。
- [x] **清理既有 API 漂移**：`skill_scan` 补齐 `scan_skill`/`to_sarif`/`render_markdown`/`MAX_*`/`summarize`；`upload.py`/`mcp_tool.py` 修复；`test_skill_scan_m123.py` 改写为当前 API。
- [x] **CI / 覆盖率**：`.github/workflows/ci.yml`（全量测试 × Py3.10–3.12 + 零依赖门禁 + 覆盖率）；`--cov=core` 行覆盖率 **74%**。

---

## 4. 建议的下一步

1. ~~**补 M1 Planner + M4 Reporter/Memory**~~ —— ✅ 已完成（`agents/planner.py` + `agents/reporter.py` + `memory/store.py`），工作台已从"骨架"变为"可演示闭环"。
2. ~~**D 工作台闭环**（Planner/Validator/Reporter/Memory）~~ —— ✅ 已完成，`python -m core.digpool solve --target X` 一键贯通。
3. **M2 Recon + Runtime**：浏览器代理执行 + 流量监听（依赖引擎，或 vendored 最小运行时）。
4. **引擎在线校验**：`HarmValidator` 对 `harm_validation` 公开契约的实测对接；L4 细粒度 token 计量。

> 一句话：**MVP 方向已纠正为 `core/digpool` 工作台，已零依赖跑通；三测试集 + Web SSE + 真实 LLM + AI 矩阵 sidecar + 工作台闭环（Planner/Validator/Reporter/Memory）均已落地；剩余主要是依赖引擎的 M2 Runtime 与引擎在线契约校验。**
