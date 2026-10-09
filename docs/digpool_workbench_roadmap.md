# DigPool 工作台里程碑（MVP 验收对照）

> 对齐 `0912_XuanJian_AI_Demo_TechPlan.md` 的 M0–M4 里程碑。本文件为 jianwei `core/digpool/` 的验收判据索引。
> **状态更新：2026-10-08 晚**（Web SSE / 真实 LLM Agent 已落地；**工作台闭环 Planner/Validator/Reporter/Memory 已补全**）。
> **本目录（docs/）为历史镜像**；权威设计文档集见 [`../818/`](../818/)（索引 `818/INDEX.md`）。

## 里程碑状态（截至 2026-10-08 晚）

| 里程碑 | 内容 | 状态 | 证据 |
|---|---|---|---|
| **M0** | 脚手架：会话 + SSE 事件流 + 空跑通（StubCore 降级） | ✅ 完成 | `session.py` `run_empty` / `core_link.py` `StubCore` |
| **M1** | Planner + 状态机 + 项目记忆读写 | ✅ 完成 | `agents/planner.py`（`DeterministicPlanner`/`LLMPlanner`，目标→DAG+预算）；`memory/store.py`（项目级记忆落盘）；`session.plan()` |
| **M2** | Recon/Scope + 工具链 + curated skill | 🟡 部分 | `scope.py`+`ingest.py` ✅；`tools/` ✅（4 curated + 技能市场）；Recon 智能体/浏览器 Runtime 依赖引擎 |
| **M3** | 治理门控（审批/熔断）+ Validator 去误报 | ✅ 完成 | `governance.py` 审批/熔断 ✅；`agents/validator.py` 双重去误报（证据门+佐证门，引擎缺失降级 `StubValidator`） |
| **M4** | Reporter + 记忆沉淀 + Web SSE + demo | ✅ 完成 | Web SSE ✅（`web/api/digpool_api.py`）；真实 LLM Agent ✅（`LLMAgent`）；`agents/reporter.py` 报告落盘；`memory/store.py` 记忆沉淀；`session.solve()` 闭环 |

## 验收清单（取自 TechPlan §10.1，逐项勾选）

- [x] 打开工作台，进入"AI 挖洞对话"终端（CLI `python -m core.digpool demo` + Web `/api/digpool/chat` SSE）
- [x] 输入目标 → 工具链真实执行（skill-scan 命中 malicious_skill，exit=1）
- [x] 高风险工具触发人工审批门（llm-top10 → ApprovalTicket pending）
- [x] LOOP 引擎跑出 depth_chain + termination
- [x] Web SSE 对话终端（`POST /api/digpool/chat`·`/run`）+ 真实 LLM Agent（`DIGPOOL_LLM_API_KEY`）
- [x] Planner 输出可视化任务 DAG + 预算估算（`python -m core.digpool plan --target X`）
- [ ] Recon 拉起浏览器、监听流量、识别资产（依赖引擎 Runtime）
- [x] SCOPE 基于流量动态修正边界（不越权）—— `session.ingest_traffic` + `Scope.expand`（M2）
- [x] VERIFY 双重去误报，仅确定性漏洞进入报告 —— `agents/validator.py`（证据门 + 佐证门）
- [x] REPORT 输出覆盖矩阵 + 漏洞详情 + 证据（PoC 以证据字段呈现）—— `agents/reporter.py`
- [x] ACCEPT 结果沉淀为项目记忆，可驱动下一次任务 —— `memory/store.py` `recall()`
- [x] 预算超额 / 重复执行时自动熔断 —— `governance.py` `charge`/`check_repeat`；`solve()` 按计划预算计量

## 关联文档

- 上游：`F:\xuanjian-main\hollowing-optimization-plan\plan\0912_DigPool_tech_analysis.md`
- 方案：`F:\xuanjian-main\hollowing-optimization-plan\plan\0912_XuanJian_AI_Demo_TechPlan.md`
- 待改清单：`F:\jianwei-main\MVP_GAP_ANALYSIS.md`、[`../818/鉴微优化方案_2026-10-08.md`](../818/鉴微优化方案_2026-10-08.md)
