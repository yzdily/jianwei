# 鉴微 JianWei 架构文档

> 鉴微是在玄鉴 XuanJian v2.0 持续维护的引擎之上构建的 AI 安全测试平台。
> 本文档描述平台层（L1-L5）的架构设计，引擎层（L0）详见 [玄鉴 ARCHITECTURE.md](https://github.com/yzdily/xuanjian/blob/main/ARCHITECTURE.md)。
> 最新事实源见 [`818/10月8号技术方案.md`](./818/10月8号技术方案.md)。

---

## MVP 工作台：core/digpool（对齐蛙池AI / 玄鉴 DEEP 档）

鉴微的 MVP 不是单个扫描器，而是**对标斗象蛙池AI / 玄鉴 DEEP 档的「AI 挖洞工作台」**——
基模 + Multi-agent + Memory + 工具链 + 治理门控的 Agentic Loop 骨架，落在 `core/digpool/`。

- **零依赖可跑**：玄鉴引擎（L0）未安装时自动降级 `StubCore`；`yaml`/`httpx` 缺失也有兜底。
  无需 LLM 密钥即可跑通 `DeterministicAgent` 闭环。
- **六层对齐**：Runtime(`core_link`) / Orchestration(`session`) / State&Memory(`scope`+`VulnChainMemory`) /
  Tool&Data(`tools/`) / Communication(`agent`) / Observability&Governance(`governance`+`loops/gates`)。
- **Tool & Data 层**：把平台层真实检测能力（如 `skill_scan` 供应链扫描）桥接为带 `risk_level` 的 curated 工具，
  高风险工具受六维治理审批门约束（低自动 / 高人工）。
- **Web SSE + 真实 Agent**：`web/api/digpool_api.py`（`/chat`·`/run` SSE + ingest）；`core/digpool/agent.py`
  的 `LLMAgent` 经 `DIGPOOL_LLM_API_KEY` 真实驱动（缺省走 `DeterministicAgent`）。
- **运行**：`python -m core.digpool demo --target tests/fixtures/malicious_skill`
- 详细待改清单见 [`MVP_GAP_ANALYSIS.md`](./MVP_GAP_ANALYSIS.md)；里程碑见 [`docs/digpool_workbench_roadmap.md`](./docs/digpool_workbench_roadmap.md)。

> 注意：本文件 L0–L5 描述的是**平台层能力目标**；`core/digpool` 是在其之上新增的**工作台层**，
> 两者不冲突——工作台调度平台层与引擎层的检测能力。

---

## 平台分层架构

| 层 | 职责 | 状态 |
|---|---|---|
| **L0 引擎基座** | 真实攻击执行、浏览器/代理、编排、危害验证 | 玄鉴 v2.0（持续维护） |
| **L1 资产/接口层** | 识别被测 AI 应用攻击面 | ✅ 已实现（`_checks_web.asset_discovery`） |
| **L2 攻击/评测层** | 红队用例执行引擎 | ✅ 已实现（llm_top10 + prompt_injection + agent_eval + rag_sec + skill_scan） |
| **L3 护栏层 sec_shield** | 输入/输出校验、敏感拦截、可插拔策略 | ✅ 已实现（契约冻结） |
| **L4 评测度量层** | ASR/拒答率/泄露率/护栏拦截率、回归基线 | ✅ 已实现（飞轮挂钩 + 基线回归对比） |
| **L5 报告/合规层** | 可审计安全报告、整改清单、等保对齐 | ✅ 已实现（章节 + ATLAS + SARIF + 完整合规组装） |

## 依赖方向

**单向依赖**：L5 -> L4 -> L3 -> L2 -> L1 -> L0

上层可依赖下层，下层**不可**反向依赖上层。

## L0 引擎基座（玄鉴 XuanJian v2.0，持续维护）

依赖方式：`xuanjian @ git+https://github.com/yzdily/xuanjian@v2.0`（**引擎持续维护，建议跟随 `main` 版本化 pin**，见《10月8号技术方案》§2.2）

复用能力：爬虫(crawler)、编排(session)、并行(parallel)、快速扫描(fast_scanner)、危害验证(harm_validation)、XSS专项(xss)、Fuzz引擎(fuzz)、LLM客户端(llm)、**矩阵编排(core/testflow)、攻击链引擎(chain_engine)**

## L2 攻击/评测层

### LLM 漏洞扫描器 (`core/ai_sec/llm_top10/`)
覆盖 OWASP LLM Top 10 + Agent/MCP 新威胁面（13 check）。✅ 已实现。

### Prompt 注入测试集 (`core/ai_sec/prompt_injection/`)
直接注入、间接注入、越狱、多模态 四类探针库（内置 22 条 + 收编 `skills_my/redteam/`），
`ProbeRunner` 复用引擎级 `fire_attack`/`judge_response`。✅ 已实现。

### Agent 安全评测 (`core/ai_sec/agent_eval/`)
工具调用越权、编排逃逸/目标劫持、记忆投毒（3 评估器，复用 `core/llm_security/{agent_eval,mcp_exploit}`）。✅ 已实现。

### RAG 安全检测 (`core/ai_sec/rag_sec/`)
知识库投毒、向量越权检索、溯源一致性（3 检测器，复用 `core/llm_security/rag_poison`）。✅ 已实现。

### AI 风险矩阵接入 (`core/ai_sec/ai_matrix/`) — E 阶段 1（sidecar）
`AIEndpointTagger`（E2 归属）+ `AIMatrixRunner`（E3：归属→执行 playbook→GATE-TRI 裁决→矩阵格）接入引擎 `core/testflow` 稀疏矩阵；门优先复用引擎 `gates`/`verdict`，零依赖时本地等价降级。
设计见 [`818/AI风险接入testflow矩阵_设计稿_2026-10-08.md`](./818/AI风险接入testflow矩阵_设计稿_2026-10-08.md)。

## L3 护栏层 sec_shield

输入校验 -> 策略引擎 -> 输出过滤（可插拔）
自攻自防闭环：L3 护栏同时作为 L2 评测的被测对象

## L4 评测度量层

ASR（攻击成功率）、拒答率、泄露率、护栏拦截率、回归基线。
`hook.py`（飞轮挂钩：扫描产物→指标→报告）、`baseline.py`（Golden 基线回归对比）。

## L5 报告/合规层

AI 风险报告、整改清单、等保对齐、审计日志。
`compliance_report.build_full_report`：覆盖矩阵 + 详情 + PoC + 整改清单（+ 等保参考对齐 + 指标 + ATLAS）。

## 扫描模式（双轴重设计）

目标类型 TargetType: web / api / llm_app / agent / rag / **skill**
测试策略 TestStrategy: passive / standard / redteam / compliance

`get_scan_strategy(target_type, strategy)` 返回 `ScanConfig.enabled_rules`：
- `web/api` → 传统 Web 规则（玄鉴引擎提供）
- `llm_app/agent/rag` → Web 规则 + `llm_vuln`（OWASP LLM Top 10 专项，13 check）
- `skill` → `skill_scan`（静态供应链分析，与运行时端点扫描互斥）
- `passive` → `asset_discovery`（仅资产识别，不发射攻击）
- `redteam` → 追加多轮驱动器 + 工具滥用模拟 + LLM-judge

### 扫描引擎接线（core/fast_scanner/）

`FastScanner(_ChecksWeb, _ChecksLLM, _ChecksSkill)` 通过多重继承组合检测能力，
沿用 `getattr(self, f"_check_{rule}")` 动态分发（零侵入）。各 mixin：
- `_checks_llm` → 委派 `core.ai_sec.llm_top10.LLMScanner`（含 RAG/Agent/MCP 三个新增 check）
- `_checks_skill` → 委派 `core.llm_security.skill_scan.scan_package`
- `_checks_web` → 平台层 `security_headers` + `asset_discovery`（被动资产识别）

### 技能供应链扫描（core/llm_security/skill_scan/）

借鉴 NVIDIA SkillSpector 的静态分析管道，与黑盒 LLM 红队形成"动静互补"。
分析器注册表：pattern（正则）/ ast_behavior（Python AST）/ supply_chain（OSV.dev CVE）/
semantic（LLM 语义，redteam 启用）/ yara_scan（恶意载荷特征）。
**信任边界**：绝不执行被扫对象，摄入只读解析，扫完即焚。评分 0-100 + 可执行脚本 ×1.3，
退出码作 CI 门禁，支持 SARIF 2.1.0 导出。
