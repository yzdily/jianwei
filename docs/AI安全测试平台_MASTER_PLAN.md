# 鉴微 JianWei · AI 安全测试平台 — Master Plan（合成升级总纲 v1.2）

> ⚠️ **口径修正（2026-10-08 重审）**：本文为**历史规划存档**。文中所有「xuanjian 持续维护 / 冻结 / 持续维护」表述经核实为**不实信息**——玄鉴引擎**持续维护中**（HEAD=`37b0956`，未冻结）。最新唯一事实源见 [`../818/10月8号技术方案.md`](../818/10月8号技术方案.md)（v2.1）。下文「持续维护」相关表述请一律按「持续维护的引擎」口径阅读。

> **合成来源**（本文为唯一事实源）：
> 1. `2026-ai安全专家.docx` 第四部分《玄鉴升级路线图 —— 从渗透 Agent 到 AI 安全测试平台》（定位 / 架构 / 增量 / 商业化）
> 2. `XUANJIAN_MASTER_PLAN.md`（v1.6 · 全量源码实读校准版）—— 玄鉴引擎当前工程状态、优先级、产品策略、角色行动清单
> 3. `xuanjian-main/` 源码实读 —— 验证引擎已具备 / 缺失的能力，确保升级路线不虚构
>
> **定位**：本文把"玄鉴渗透 Agent"合成为"覆盖 扫描—评测—护栏—报告 的 AI 安全测试平台"，给出**平台命名决策 + 架构分层 + 关键增量 + 角色行动清单 + 路线图 + 商业化 + 里程碑**。本文只出方案，不改源码；凡与 `XUANJIAN_MASTER_PLAN.md` 冲突的引擎层论断，以该文（v1.6 实测）为准。

---

## 0. 命名决策（选名）

### 0.1 推荐名：**鉴微（JiànWēi）**

| 项 | 内容 |
|---|---|
| **中文名** | 鉴微 |
| **英文名** | JianWei AI Security Testing Platform（缩写 **JW-AISTP**） |
| **内核** | 玄鉴 XuanJian v2（**开源引擎**，持续维护，作为稳定基座） |
| **完整称呼** | 鉴微 · AI 安全测试平台（由玄鉴引擎驱动） |
| **Slogan** | 「见微知著，洞见 AI 之险」 |

**命名释义**
- **鉴**：审视 / 校验 / 守护 —— 与「玄鉴」同源（**品牌延续**，不另起炉灶）。
- **微**：幽微 / 隐蔽 —— 特指 AI 系统中传统扫描器**看不见的隐性风险**：提示注入、越狱、记忆投毒、过度代理（Excessive Agency）、向量库越权检索。
- 整词义：「从细微处鉴察」，正是平台核心价值 —— 把 OWASP LLM Top 10、Agent 威胁、RAG 投毒这些"软风险"变成可扫描、可量化、可回归的硬指标。

### 0.2 与「玄鉴」的品牌关系（解决 docx §4.4 与引擎现状的张力）

docx §4.4 写道「沉淀个人技术品牌 玄鉴 = AI 安全测试平台」。但 `XUANJIAN_MASTER_PLAN.md` 产品策略（P1/P2）明确要**区分社区版与商业版 fork**。两者统一方案：

| 维度 | 玄鉴 XuanJian | 鉴微 JianWei |
|---|---|---|
| 角色 | **开源引擎 / 内核**（持续维护） | **在其上构建的开源 AI 安全测试平台** |
| 仓库 | `github.com/yzdily/xuanjian`（MIT，持续维护） | 开源平台层（独立仓库 / mono-repo 子模块，建在 xuanjian 之上） |
| 受众 | 安全研究员、自托管玩家、社区贡献者 | 企业 AI 团队、红队、合规方、社区贡献者 |
| 边界 | 引擎 / 规则 / SKILL 留社区（上游持续演进） | 核心平台（L1–L5 + 测试集 + 看板）全开源；Cloud 托管 / 等保合规 / 计量仅作可选增值层（后置） |

> **结论（按 2026-10-08 修正口径）**：保留"玄鉴 = AI 安全测试平台"的品牌意志，把**平台产品名落地为「鉴微」**。依赖模式为 **xuanjian 持续维护（开源引擎，不冻结）+ 鉴微同步开源（建在其上）**——两者同源开源、命名隔离清晰（玄鉴=引擎，鉴微=开源平台），避免混淆。对外话术：「**玄鉴，自主可控的持续维护渗透引擎；鉴微，由玄鉴驱动的开源 AI 安全测试平台**」。

### 0.3 备选名对比（供拍板）

| 名称 | 含义 | 优点 | 顾虑 |
|---|---|---|---|
| **鉴微**（推荐） | 鉴察幽微 | 与玄鉴同源、精准命中"隐性 AI 风险" | 无显著短板 |
| 玄镜 XuanJing | 玄妙之镜 | 与玄鉴强关联，镜像意象统一 | 与玄鉴易混淆，区分度低 |
| 烛龙 Zhulong | 神话照见幽冥之龙 | 红队"照见 AI 裂隙"意象极强 | 怪兽感偏攻击性，合规语境略 aggressive |
| 洞微 DongWei | 洞见幽微 | 近义、更"洞察" | 与"懂微"谐音，口语易混 |

---

## 1. 一页纸定位

- **是什么**：一个覆盖「资产发现 → 攻击/评测 → 护栏 → 度量 → 报告」的 **AI 应用安全测试平台**，被测对象包括 Web / API / RAG / Agent 系统。
- **不是什么**：不是又一个 Web 漏扫；不是纯评测集；不是只做护栏。它是**把红队能力产品化、把 AI 风险可量化**的平台。
- **核心飞轮**：玄鉴引擎（真实攻击执行力）+ 鉴微平台层（AI-native 评测/护栏/度量）→ 评测数据反哺 SKILL 与规则 → 越测越准。
- **一句话**：**鉴微把"会攻的玄鉴"升级为"会评、会防、会量化的 AI 安全测试平台"。**
- **本轮重设计重点（2026-08 源码实读后）**：鉴微已从"玄鉴渗透 Agent"明确为**独立 AI 测试平台**，因此本轮对两处做结构性重设计 —— ① **扫描模式双轴重设计**（目标类型 × 测试策略，取代仅深度的单维），见 §12；② **平台 UI 重设计**（对话/红队模块从底部折叠终端升级为主工作区、左侧功能栏重构、扫描发起改为双轴向导），见 §13。所有改动均固化于 §14《改动设计记录》。

---

## 2. 现状基础盘点（玄鉴引擎已具备，可直接复用为平台底座）

> 以下能力均经 `xuanjian-main/` 源码实读确认（路径来自 `XUANJIAN_MASTER_PLAN.md` v1.6 实测）。**关键结论：引擎是"Web/App 渗透 Agent"，尚无任何 AI-native 安全模块（grep `sec_shield|guardrail|护栏|Agent 安全` 结果为 0）** —— 这正是平台化要补的增量。

| 模块（源码真实路径） | 现状能力 | 平台化复用方式 |
|---|---|---|
| `core/crawler/crawler_core.py`（AutoCrawler, 3547 行） | 自动爬虫、页面/SPA 探索 | 升级为「AI 应用资产发现 / 接口识别」（含 RAG 暴露面、Agent 工具面） |
| `core/session/chat_loop.py`（ChatLoopMixin, 2222 行） | 对话式任务编排、多 phase | 改造为「红队对话引擎」与多轮越狱编排 |
| `core/parallel/orchestrator.py`（1499 行） | 并行任务调度 | 复用为评测任务并发执行器 |
| `core/context.py` + `core/session/` | 上下文 / 记忆管理 | **加记忆完整性校验**，防上下文/记忆投毒 |
| `core/fast_scanner/`（含 `_engine.py` 超时熔断/心跳） | 快速扫描引擎 | 扩展 LLM/RAG/Agent 专项扫描插件 |
| `core/harm_validation/`（validator/context/exploit） | 危害验证，**证据优于概率**铁律 | 复用于 AI 风险「证据化」定级 |
| `core/fuzz/`（sqli / race_condition / waf_bypass） | 注入 / 竞态 / WAF 绕过 | 复用为 Payload 生成底座 |
| `core/xss/`（13-step 引擎 + `llm_judge.py`） | XSS 13 步专项 + LLM 判定 | 复用 LLM 判定范式做越狱/注入判定 |
| `core/reconcile.py` + `core/false_positive_manager.py` | 对账 / 去误报 | 复用为评测结果去噪、ASR 计算基线 |
| `rules/*.yaml`（5 条）+ `skill_registry`/`skill_router` | 规则 + SKILL 方法论 | 新增 LLM/Agent/RAG 规则与红队 SKILL |
| `web/api/`（18 个 router） | Web UI / API | 扩展为平台看板与评测 API |
| `mcp_servers/` | 工具扩展（浏览器/代理 MCP） | Agent 工具滥用测试的工具面 |
| `pentest/pentest_xuanjian.py`（XJ-01/02/03/05） | 自带安全自检 | 平台自身合规自检基线 |

**当前能力边界（必须正视）**：仅覆盖传统 Web/App 攻防；**OWASP LLM Top 10、Agent 威胁建模、RAG 安全、Prompt 注入、护栏（sec_shield）、评测度量（ASR/拒答率/泄露率）全部缺失** —— 这些是鉴微平台层的 100% 净增量。

**前端交互边界（源码实读 `web/index.html` 4436 行单体 SPA，原生 JS + 内联 CSS，无框架）**：对话模块为底部 220px、**默认折叠 44px** 的等宽终端条（无气泡、过小）；左侧功能栏 240px，AI/LLM 能力被降级塞进「🧰 高级工具」折叠区；扫描发起仅「深度」一维（快速/标准/深度），**无目标类型维度**。`core/llm_security/`、`core/ai_sec/` 均未落地。以上缺口即 §12（扫描模式）、§13（UI）重设计对象。

---

## 3. 平台化架构（能力分层，6 层）

```
┌─────────────────────────────────────────────────────────────┐
│  L5  报告 / 合规层   合规报告 · 整改清单 · 可审计溯源 · 等保对齐   │
├─────────────────────────────────────────────────────────────┤
│  L4  评测度量层   ASR / 拒答率 / 泄露率 / 护栏拦截率 · 回归基线    │
├─────────────────────────────────────────────────────────────┤
│  L3  护栏层 sec_shield   输入校验→策略引擎→输出过滤（可插拔）     │
├─────────────────────────────────────────────────────────────┤
│  L2  攻击 / 评测层   注入·越狱·投毒·越权检索·过度代理 红队用例引擎 │
├─────────────────────────────────────────────────────────────┤
│  L1  资产 / 接口层   AI 应用资产发现（Web/API/RAG/Agent 工具面） │
├─────────────────────────────────────────────────────────────┤
│  L0  引擎基座（玄鉴 XuanJian v2）  爬虫·编排·并行·上下文·危害验证  │
└─────────────────────────────────────────────────────────────┘
```

| 层 | 职责 | 复用（玄鉴） | 净新增（鉴微） |
|---|---|---|---|
| **L0 引擎基座** | 真实攻击执行、浏览器/代理、编排、危害验证 | 全部现有模块 | 无 |
| **L1 资产/接口层** | 识别被测 AI 应用攻击面 | `core/crawler`、`core/js_analyzer` | RAG 数据源发现、Agent 工具清单抓取、系统提示暴露面探测 |
| **L2 攻击/评测层** | 红队用例执行引擎 | `core/fuzz`、`core/xss`、`harm_validation` | LLM Top10 插件、Agent 安全评测、Prompt 注入探针集 |
| **L3 护栏层 sec_shield** | 输入/输出校验、敏感拦截、可插拔策略 | `harm_validation` 判定范式 | **全新**：策略引擎 + 企业自定义策略 + 与评测闭环 |
| **L4 评测度量层** | ASR/拒答率/泄露率/护栏拦截率、回归基线 | `reconcile`/`false_positive_manager` | **全新**：指标聚合、Golden Report 比对、靶场基准 |
| **L5 报告/合规层** | 可审计安全报告、整改清单、等保对齐 | `compliance_report.py`、`report_templates.py` | AI 风险专项报告模板、授权证明 + 审计日志 |

---

## 4. 关键功能增量（2026 落地，映射源码）

> 优先级沿用 docx §4.3；"复用/新增"列经源码实读校准，确保不虚构。

| 增量模块 | 功能 | 复用（玄鉴） | 新增模块（鉴微） | 优先级 | 验收基线 |
|---|---|---|---|---|---|
| **LLM 漏洞扫描器** | OWASP LLM Top 10 + Agent/MCP 自动化检测插件（13 check） | `core/fast_scanner`、`rules/*.yaml`、`skill_*` | **MVP（引擎层）**：`core/llm_security/`（13 个 check + `_checks_llm.py` mixin，零侵入接入 `FastScanner`）；**远期（平台层）**：`core/ai_sec/llm_top10/`（10+ 类规则+探针）。详细模块路径 / check 命名 / 多靶场映射见 `hollowing-optimization-plan/818/LLM漏洞扫描器设计方案.md` §1.5–§1.7 与 `OWASP_LLM_Top10_攻击研究与映射.md` §13–§15 | **P0** | 10 类风险 + Agent/MCP 新面均有可执行用例 + 证据化报告 |
| **Agent 安全评测** | 工具调用越权 / 编排逃逸 / 记忆投毒测试 | `core/context`、`mcp_servers`、`harm_validation` | `core/ai_sec/agent_eval/`（目标劫持/工具滥用/记忆投毒用例） | **P0** | 覆盖 LLM06 过度代理 + 记忆投毒可复现 |
| **Prompt 注入测试集** | 可复用注入/越狱探针库 | `core/xss/llm_judge.py` 判定范式、`skill_registry` | `skills_my/redteam/`（直接/间接注入、多模态、越狱集） | **P0** | 探针集开源 + 自动评测脚本可回归 |
| **RAG 安全检测** | 知识库投毒扫描 / 越权检索 / 溯源校验 | `core/crawler`、`reconcile` | `core/ai_sec/rag_sec/`（来源审计、向量鉴权、溯源一致性） | **P1** | 投毒检测 + 越权检索检出可演示 |
| **护栏策略引擎 sec_shield** | 输入校验→策略引擎→输出过滤，可插拔 | `harm_validation` 校验范式 | `core/ai_sec/sec_shield/`（策略注册、PII/越狱/敏感词验证器、企业策略） | **P1** | 策略可自定义 + 与 L2 评测闭环（自攻自防） |
| **评测看板** | 指标可视化、回归基线、报告导出 | `web/api/`（19 Router）、`dashboard_api.py` | `web/api/metrics_api.py` + L4 指标聚合（`core/metrics.py` 已存在，扩展） | **P2** | ASR/拒答率/泄露率/护栏拦截率实时可见 |
| **扫描模式双轴重设计** | 目标类型(Web/API/LLM应用/Agent/RAG) × 测试策略(被动/标准/红队/合规) | `core/scan_strategies.py`、`web/server.py:/api/chat` | `scan_strategies.py` 增 `TargetType` 枚举 + `get_scan_strategy(target_type,strategy)` 工厂；Web 发起改双轴选择器 | **P0** | 5×4=20 组合规则组装单测通过；llm 类型默认启用 llm_vuln |
| **平台 UI 重设计** | 对话/红队模块升级为主工作区 + 左侧功能栏重构 + 扫描发起向导 | `web/index.html`（内联 CSS/JS 单体 SPA） | 新建 redteamWorkspace 气泡对话（复用 marked+DOMPurify）、侧边栏增 🤖对话·红队/📈评测度量、新建测试双轴向导 | **P0/P1** | 对话默认展开可多轮渲染；导航含新入口；发起可双轴选择 |

**关键设计原则**
- **证据优于概率**（玄鉴铁律）延伸至 AI 风险：每个 LLM/Agent 风险必须给出**可复现证据**（payload + 响应 + 判定），不靠概率妄断。
- **sec_shield 自攻自防闭环**：L3 护栏同时作为 L2 评测的"被测对象"——用鉴微自己的红队探针测自己的护栏，形成"攻防度量"双环。
- **复用 harm_validation 判定范式**：AI 风险定级复用"危害验证 + 证据"逻辑，避免另起一套判定体系。

---

## 5. 角色行动清单（平台合成 · 各角色该做什么）

> 引擎层的开发/产品/测试/前端/架构师/运维/运营动作见 `XUANJIAN_MASTER_PLAN.md` §3（专注玄鉴引擎治理），**本文只列平台合成（鉴微）增量对应的角色动作**。平台动作以"在玄鉴引擎之上建设 L1–L5"为边界，不重复引擎治理项。
> 优先级：P0 = Q3 启动即做；P1 = Q4；P2 = Q1 2027。

### 5.1 开发（Platform Dev）— 把增量变成代码

| # | 动作 | 平台层 | 优先级 | 具体方案（映射源码） |
|---|---|---|---|---|
| **PD1** | LLM 漏洞扫描器 | L2 | P0 | 新建 `core/ai_sec/llm_top10/`（10 类规则+探针），新增 `rules/llm_*.yaml`；复用 `core/fast_scanner` 调度 + `harm_validation` 证据范式 |
| **PD2** | Agent 安全评测 | L2 | P0 | 新建 `core/ai_sec/agent_eval/`（目标劫持/工具滥用/记忆投毒用例），复用 `core/context` + `mcp_servers` 工具面 |
| **PD3** | Prompt 注入测试集 | L2 | P0 | `skills_my/redteam/`（直接/间接注入、多模态、越狱集），复用 `core/xss/llm_judge.py` 判定范式 |
| **PD4** | RAG 安全检测 | L1/L2 | P1 | 新建 `core/ai_sec/rag_sec/`（来源审计、向量鉴权、溯源一致性），复用 `core/crawler` + `reconcile` |
| **PD5** | 护栏引擎 sec_shield | L3 | P1 | 新建 `core/ai_sec/sec_shield/`（策略注册、PII/越狱/敏感词验证器、企业自定义策略），复用 `harm_validation` 校验范式 |
| **PD6** | 评测度量层 | L4 | P2 | 扩展 `core/metrics.py` + 新建 `core/ai_sec/metrics/`（ASR/拒答率/泄露率/护栏拦截率聚合） |
| **PD7** | 平台 API | L4/L5 | P2 | 新建 `web/api/ai_sec_api.py`（评测任务、指标、报告导出），复用 `web/api/` 既有 19 Router 模式 |
| **PD8** | 资产层 AI 暴露面扩展 | L1 | P1 | 扩展 `core/crawler/crawler_core.py` 识别 RAG 数据源、Agent 工具清单、系统提示暴露面 |
| **PD9** | AI 风险统一数据模型 | L2–L5 | P1 | 在 `harm_validation` 之上统一 AI 风险 schema（vuln_type/evidence/severity），供 L3–L5 共用 |

### 5.2 测试（Platform Test）— 把红队经验变成可回归资产

| # | 动作 | 优先级 | 具体方案 |
|---|---|---|---|
| **PT1** | LLM Top10 用例执行 + 证据断言 | P0 | 为 PD1 每类风险写"先红后绿"测试，断言产出证据化报告（复用 `tests/` 体系） |
| **PT2** | 红队测试集可回归 | P0 | `skills_my/redteam/` 配自动评测脚本，支持 CI 回归（ASR 可复算） |
| **PT3** | ASR/拒答率/泄露率 度量 | P1 | 对着 PD6 写指标计算单测 + 靶场 Golden 基线 |
| **PT4** | sec_shield 自攻自防闭环 | P1 | 用 PT2 探针测 PD5 护栏，断言拦截率可度量、漏拦有告警 |
| **PT5** | 靶场 e2e（Juice Shop/DVWA + LLM 靶场） | P1 | 检出率 ≥ 基线、已知干净目标零严重误报（延续引擎 T5） |
| **PT6** | 平台层回归接入 CI | P2 | 平台增量测试纳入 `tests.yml` 分层门禁（与引擎 T3 协同） |

### 5.3 产品（Product）— 把平台变成可卖的产品

| # | 动作 | 优先级 | 具体方案 |
|---|---|---|---|
| **PP1** | 拍板命名（鉴微） | P0 | 以本文 §0 推荐为准，对外话术"鉴微，由玄鉴引擎驱动" |
| **PP2** | 平台定位话术 | P0 | 锁定"扫描—评测—护栏—报告"四维 + "证据优于概率"差异化 |
| **PP3** | 社区/商业边界 | P0 | 沿用引擎产品 P1/P2：引擎全开源，Cloud/合规/计量仅商业 |
| **PP4** | Cloud 单位经济测算 | P1 | 用 DEEP 扫描 token 样本估边际成本 → 定 ¥99–299/月(个人)、¥999–4999/月(团队)、¥5w–50w/年(企业) |
| **PP5** | 等保合规门禁 | P1 | 授权证明上传 + 企业 KYC + 审计日志 + 目标白名单（复用引擎产品 P5） |

### 5.4 架构师（Architect）— 冻结平台分层与契约

| # | 动作 | 优先级 | 具体方案（参照引擎 Master Plan） |
|---|---|---|---|
| **PA1** | 平台分层与依赖方向 | P0 | 确立 L0(玄鉴内核)→L5(报告) 单向依赖，加 layer-lint 防反向依赖（接引擎 A1） |
| **PA2** | sec_shield 接口契约 | P1 | 冻结策略注册/验证器接口签名，抽出 `sec_shield/_contracts.py`，契约测试 |
| **PA3** | AI 风险统一数据模型 | P1 | 冻结 PD9 schema，L3–L5 共用，避免各自造对象 |
| **PA4** | 与引擎 DI 收敛协同 | P1 | 平台层全局态复用 `core/di.py` resetter 模式（接引擎 A4/D7） |

### 5.5 前端（Frontend）— 平台看板与编排 UI

| # | 动作 | 优先级 | 具体方案 |
|---|---|---|---|
| **PF1** | 评测度量看板 | P2 | 可视化 ASR/拒答率/泄露率/护栏拦截率（接 PD6/PD7） |
| **PF2** | 红队对话/编排 UI | P1 | 基于 `core/session/chat_loop.py` 暴露多轮越狱编排界面 |
| **PF3** | 报告/合规导出 UI | P1 | 复用 `report_templates.py` 加 AI 风险专项模板导出 |
| **PF4** | 对话/红队工作区升级 | P0 | 把 `index.html:1613` 底部折叠终端条升级为主工作区气泡对话（§13.1），复用 marked+DOMPurify，多轮+证据锚点 |
| **PF5** | 左侧功能栏重构 | P1 | 重排分组，新增 🤖对话·红队 / 📈评测度量 一级入口，AI 能力不再藏于折叠区（§13.2） |
| **PF6** | 扫描发起双轴向导 | P0 | 「新建测试」向导：目标类型 → 测试策略 → 范围授权，实时提示将启用哪些 check（§13.3 / §12） |

### 5.6 运维（Ops）— 平台可托管可合规

| # | 动作 | 优先级 | 具体方案 |
|---|---|---|---|
| **PO1** | Cloud 托管部署 | P1 | 容器化鉴微平台层，复用引擎 `Dockerfile`/`docker-compose.yml` 加固（接引擎 O3/O4） |
| **PO2** | 多租户/计量/审计 | P1 | 租户隔离 + `llm_usage.jsonl` 计费 API 化（接引擎产品 P2/P15） |
| **PO3** | 合规门禁落地 | P0 | 授权证明/KYC 校验服务，生产强制 HTTPS（接引擎 O1/O2） |
| **PO4** | 可观测性 | P1 | `/metrics` 暴露平台指标，接 Prometheus/Grafana（接引擎 O6/A8） |

### 5.7 运营（Community/Ops）— 开源飞轮

| # | 动作 | 优先级 | 具体方案 |
|---|---|---|---|
| **PG1** | 开源红队测试集发布 | P0 | `skills_my/redteam/` 开源 + README 引导（接引擎 G3/G6） |
| **PG2** | SKILL 市场（红队方法论） | P1 | `marketplace.json` 加红队分类，创作者 7:3 分成 |
| **PG3** | 文档站 + 社区 | P1 | `docs/` 加平台专页，Issue/PR 模板（接引擎 G1/G2） |
| **PG4** | 靶场基准榜 | P2 | 公开 LLM 靶场基准数据，对外"证据优于概率"话术 |

### 5.8 各角色 Q3 启动期「本周 3 件事」

| 角色 | 本周 3 件事（Q3 启动） |
|---|---|
| **开发** | ① PD1 LLM 扫描器骨架 ② PD3 注入测试集初版 ③ PD9 AI 风险 schema |
| **测试** | ① PT1 LLM Top10 证据断言 ② PT2 测试集可回归脚本 ③ PT3 指标计算单测 |
| **产品** | ① PP1 拍板命名 ② PP2 定位话术 ③ PP3 社区/商业边界 |
| **架构师** | ① PA1 平台分层 lint ② PA3 AI 风险 schema 冻结 ③ PA2 sec_shield 契约草案 |
| **前端** | ① PF3 报告导出 UI 原型 ② PF2 红队编排 UI 设计 |
| **运维** | ① PO3 合规门禁 ② PO1 平台容器化评估 |
| **运营** | ① PG1 测试集开源准备 ② PG3 文档站平台页 |

> **协同原则**：引擎层 7 角色（§3 引擎 Master Plan）负责"玄鉴可信"；本 §5 平台层 7 角色负责"鉴微能用"。两者通过 PA1/PA4（分层契约 + DI 收敛）与 PD9/PA3（统一 AI 风险 schema）对齐接口，避免平台层与引擎层脱钩。

---

## 6. 开源与商业化路径（docx §4.4 × 引擎产品策略 — 修订版：持续维护 + 同步开源）

> **本次拍板（对齐"先准备跳槽"诉求）**：原方案将鉴微定为"私有/商业 fork"。现调整为三件事 —— ① **xuanjian 持续维护**（稳定为开源引擎基座）；② **鉴微在持续维护 xuanjian 之上同步开源**（平台层）；③ **二者同源开源、对外一组作品**，商业化仅作可选后置增值层。核心动机：把"持续维护可信引擎 + 可演示 AI 安全平台"做成最强跳槽作品集，而非先创业。

### 6.0 战略变更摘要

| 维度 | 原方案 | 本次修订 |
|---|---|---|
| 玄鉴 xuanjian | 开源引擎，持续演进 | **持续维护**：持续演进，作可信基座 |
| 鉴微 JianWei | 私有 / 商业 fork | **同步开源**：建在持续维护 xuanjian 之上的开源平台 |
| 商业化 | Cloud/合规/计量仅商业 | **后置**：核心全开源，可选 Cloud/合规增值 |
| 首要目标 | 产品化 / 商业飞轮 | **跳槽作品集**（Q2 2027 求职冲刺） |

### 6.1 xuanjian 持续维护策略（稳定为可信基座）

"持续维护"= 引擎持续演进，公开契约与基线保持稳定可依赖：

- **稳定版本**：`xuanjian v2.0 "稳定版"` —— 以 `XUANJIAN_MASTER_PLAN.md` S1–S2 止血完成态为基线，打 `release/v2.0` tag；`main` 主线持续演进，`maintain` 分支持续接纳 bugfix / 安全补丁。
- **既有能力范围**：Web/App 渗透 Agent 全能力、19 Router Web API、`crawler/orchestrator/harm_validation` 等已实测模块；`DISCLAIMER.md` 合规免责。
- **平台层另建（引擎侧不再加 AI 模块）**：**不新增 LLM/Agent/RAG 等 AI-native 安全模块** —— 这些全部归鉴微平台层，避免引擎/平台职责混淆（对准 §3 分层单向依赖 + §5.4 PA1）。
- **稳定即作品化**：补 `README.md`（架构图 + 快速上手 + Demo GIF）、`ARCHITECTURE.md`、`CHANGELOG.md`；覆盖率守住（§7 基线达标），保证"可信、可演示"。
- **维护模式**：仅 bugfix / 安全补丁，社区 PR 欢迎；不再加 feature，保持引擎稳定可依赖。

### 6.2 鉴微同步开源策略（建在持续维护 xuanjian 之上）

- **依赖方式**：鉴微以 `xuanjian` 为 `pip` 依赖（或 git submodule 锁定 `release/v2.0`），**平台层只读引擎契约**（§5.4 PA1/PA2/PA3），不反向修改引擎。
- **仓库结构（推荐 mono-repo）**：
  - 方案 A（双仓）：`github.com/yzdily/xuanjian`（持续维护，MIT）+ `github.com/yzdily/jianwei`（平台，Apache-2.0）；平台 README 首行写明"由玄鉴引擎驱动"。
  - 方案 B（mono-repo，推荐）：`yzdily/ai-sec-platform` 内含 `engines/xuanjian`（子树锁定稳定版）+ `platform/jianwei`，一处可见"从引擎到平台"全貌 —— **对跳槽展示更直观**。
- **开源内容边界（open-core）**：

  | 开源（MIT / Apache-2.0） | 可选商业增值（后置，不与求职冲突） |
  |---|---|
  | 玄鉴引擎（持续维护稳定版） | 云托管 / SaaS 部署 |
  | 鉴微 L1–L5 平台核心 + 评测看板 | 企业等保合规打包 + KYC |
  | 红队测试集 / Prompt 注入靶场 | 多租户计量 / 私有化交付 |
  | sec_shield 基础策略 | 企业自定义策略实验室 |
- **许可证建议**：引擎 **MIT**（最友好，鼓励复用）；平台 **Apache-2.0**（含专利授权，便于企业评估采用）。二者均允许作为个人简历作品展示。

### 6.3 双仓开源飞轮（玄鉴引擎 × 鉴微平台 一组作品）

把两个仓库作为**连贯的开源叙事**对外，强化"从会攻的引擎到会评会防的平台"故事：

- **统一品牌话术**：「**玄鉴 —— 自主可控的渗透 Agent 引擎（持续维护稳定版）；鉴微 —— 在其之上构建的开源 AI 安全测试平台。二者同源开源。**」
- **贡献飞轮**：红队测试集开源 → 社区补用例 → 反哺鉴微评测度量 → 靶场基准榜公开 → 吸引 Star / Contributor。
- **SKILL 市场 / 基准榜**：`skills_my/redteam/` 与鉴微评测集同源发布；公开 LLM 靶场基准数据，对外强化"证据优于概率"。

### 6.4 商业化路径（后置、可选，不与跳槽冲突）

- 核心平台全开源，**商业化仅作为持续维护后的可选增值层**，不阻塞求职：Cloud 托管、企业合规打包、私有化交付。
- 单位经济测算（§5.3 PP4）保留但**后置到 Q1 2027 之后** —— 求职期间精力集中在作品集与面试，而非营收。
- 若求职顺利，平台开源作品本身即"技术影响力资产"，可带入下一份工作的 AI 安全体系建设。

### 6.5 跳槽备战对齐（时间线收口）

> 持续维护 + 同步开源的核心目的：**在 Q2 2027 前，手里有一组拿得出手的开源作品**。

| 时间 | 跳槽作品集资产 | 对应动作 |
|---|---|---|
| Q3 2026 | 持续维护 xuanjian（稳定引擎）+ 鉴微设计/原型 | §8 Q3：xuanjian 持续维护 tag + M1/M2 + §0 命名落地 |
| Q4 2026 | 鉴微评测版 + 开源红队测试集 | §8 Q4：P0 三件套开源 + PG1 测试集发布 |
| Q1 2027 | 鉴微平台 Demo（L1–L5 贯通）+ 技术博客 | §8 Q1：M4 + FreeBuf/阿里云博客系列 |
| Q2 2027 | 精准简历 + GitHub 双仓 Star + 面试战报 | §8 Q2：求职冲刺，M5 Offer |

**简历叙事**：以"独立开发并开源 玄鉴（持续维护渗透引擎）+ 鉴微（AI 安全测试平台）"为主线，用 §9 DoD 的可量化证据（覆盖率、ASR、拦截率、靶场基准）对冲非科班质疑。

---

## 7. 工程成熟度前置条件（先固本，再扩界）

> ⚠️ **合成升级的硬约束**：鉴微平台层必须建在一个**可信引擎**之上。玄鉴引擎当前仍有工程债（v1.6 实测），在以下基线达标前，**平台增量只做设计与接口契约，不急于大规模堆代码**：

| 前置基线（来自引擎 Master Plan v1.6） | 当前实测 | 平台化门槛 |
|---|---|---|
| 测试覆盖率 | 29.06% 行 / 19.04% 分支 | 先补回归测试锁死（`tests/` 9 项已建），防"加 AI 层后旧引擎退化" |
| 全局可变态 | 54 处 `global` | 收敛 <10（DI `register_resetter` 已 29 处），解锁并行评测单测 |
| 孤儿死代码 | `dir_scanner.py`(1343) 仍滞留 | 删除 + 确认 `FEATURES_PER_WORKER=3` 生效 |
| 活巨文件 | crawler_core(3547)/chat_loop(2222)/orchestrator(1499) | 拆 ≤800 行、冻结公开 API，平台层依赖稳定契约 |
| Web 安全 | S1–S5 已落地，回归测试缺 | 补 `test_web_security.py`，平台 API 才敢暴露 |
| 自带自检 | XJ-01/02/03/05 已落地 | 接入 CI 作为平台自身合规门槛 |

**节奏**：S1–S2（引擎止血+可部署）并行启动 L1/L2 设计；S3 起平台增量进入实质编码；S4 生态飞轮。

---

## 8. 路线图（docx 季度 × 引擎 Sprint 对齐）

| 阶段 | 时间 | 重点（平台层） | 引擎层协同（Master Plan） | 交付工件 |
|---|---|---|---|---|
| **Q3 2026** | 7–9 月 | OWASP LLM Top 10 通读 + L1/L2 设计 + sec_shield 原型 | S1–S2 引擎止血、CI 门禁、孤儿清理 + **xuanjian v2.0 稳定 tag** | 持续维护 xuanjian + 《Agent 安全威胁建模清单 v1》+ 鉴微 sec_shield 原型（覆盖 LLM01/06/07） |
| **Q4 2026** | 10–12 月 | LLM 漏洞扫描器 + Agent 安全评测 + Prompt 注入测试集（P0 三件套） | S3 提稳健 + 可观测 | 鉴微 AI 安全评测版（开源）+ 注入/越狱测试集开源 |
| **Q1 2027** | 1–3 月 | RAG 安全检测 + sec_shield 企业策略 + 评测看板（P1/P2） | S4 全局态收敛 + 生态 | 平台 Demo + 技术博客系列（FreeBuf/阿里云） |
| **Q2 2027** | 4–6 月 | 求职冲刺：平台 Demo 现场演示 + 商业版 fork 定型 | 维护态 | 精准简历 + 面试战报 + offer 谈判 |

**周节奏**（沿用 docx）：70% 动手 / 20% 输入 / 10% 输出。

---

## 9. 里程碑与验收标准（DoD）

| 里程碑 | 验收标准 | 时间 |
|---|---|---|
| **M1 理论地基** | OWASP LLM Top 10 可逐条讲解 + 内部培训 1 次 | 2026 Q3 |
| **M2 平台原型** | 鉴微 sec_shield 跑通，覆盖 LLM01/06/07 | 2026 Q3 |
| **M3 评测资产** | 开源注入/越狱测试集 + 自动评测脚本（可回归） | 2026 Q4 |
| **M4 平台成形** | 鉴微 AI 安全测试平台可对外 Demo（L1–L5 贯通） | 2027 Q1 |
| **M5 Offer** | 拿到 1+ 进阶档（40w+）offer | 2027 Q2 |

**平台级 DoD（合成验收）**
- [ ] 引擎覆盖率达标且平台增量有回归测试，不退化旧能力
- [ ] L1–L5 五层贯通：AI 应用资产可发现 → 红队用例可执行 → sec_shield 可拦截 → ASR/拒答率/泄露率可量化 → 报告可审计
- [ ] LLM Top 10 十类风险均有可执行用例 + 证据化报告
- [ ] 开源测试集 + 自动评测脚本可回归（对接 `tests/` 体系）
- [ ] sec_shield 自攻自防闭环：用鉴微探针测鉴微护栏，拦截率可度量
- [ ] 社区版（玄鉴 MIT）与平台版（鉴微）命名/仓库隔离清晰，合规可见

---

## 10. 风险与应对（docx §八 沿用 + 合成新增）

| 风险 | 应对 |
|---|---|
| 非科班学历被质疑 | 用鉴微平台 + 开源测试集 + 演讲对冲，强调查工程与实战结果 |
| AI 安全理论深度不足 | 系统补 OWASP / 论文 / 护栏工程，输出学习笔记反哺影响力 |
| 引擎工程债拖垮平台 | 严守 §7 前置基线，先固本再扩界 |
| 同质化「AI 概念」选手 | 靠真平台（L1–L5 贯通）、真评测集、真红队经验建壁垒 |
| 社区/商业命名混淆 | §0.2 品牌隔离：玄鉴=引擎，鉴微=平台 |
| 时间投入不足 | 固定周节奏 + 季度工件验收，避免只学不产 |

---

## 12. 扫描模式重设计（AI 测试平台视角）

> **源码实读依据**：`core/scan_strategies.py`（`ScanMode.FAST/STANDARD/DEEP/SMART` + 编排 `batch/realtime/packet`）、`web/index.html:1538` 设置页卡片单选（⚡快速/🔍标准/🧬深度）、`index.html:1655` 添加目标弹窗下拉（quick/standard/deep）；`FastScanner.scan_target` 经 `getattr(f"_check_{rule}")` 分发 15 条现有规则（sql_injection…jwt），**生产代码无 `llm_vuln`**。
> **现状问题**：当前扫描模式只有「深度」一维，**没有「目标类型」维度**——所有目标都用同一套 Web 规则打，无法区分 Web/API/LLM 应用/Agent/RAG，更无法触发 LLM 专项 13 check（详见 818 设计文档 §1.7）。

### 12.1 双轴扫描模式模型

鉴微作为 AI 测试平台，把扫描模式从「单深度滑块」重构为 **两正交轴**：

| 轴 | 取值 | 含义 |
|----|------|------|
| **目标类型 TargetType** | `web` / `api` / `llm_app` / `agent` / `rag` | 被测对象是什么，决定启用哪套规则与攻击库 |
| **测试策略 TestStrategy** | `passive`(被动探测) / `standard`(标准全量) / `redteam`(主动红队) / `compliance`(合规对照) | 打多狠、是否主动发射对抗 payload |

组合示例：`llm_app + redteam` = 对 LLM 应用发起 OWASP LLM Top10 主动红队；`agent + passive` = 只识别 Agent 工具面/暴露 schema 不主动打；`web + standard` = 传统全量（沿用现有规则）。

### 12.2 与现有引擎的衔接（零侵入改造点）

- `core/scan_strategies.py` 新增 `TargetType` 枚举 + `get_scan_strategy(target_type, strategy)` 工厂，返回 `ScanConfig`（含 `enabled_rules`）。
- `enabled_rules` 组装逻辑：
  - `web` / `api` → 现有 15 规则（sql_injection…jwt）。
  - `llm_app` / `agent` / `rag` → 追加 `"llm_vuln"`（触发 `_ChecksLLM` 13 check，见 818 设计文档 §1.7）。
  - `passive` → 仅资产发现 + 特征识别（不发射攻击 payload）。
  - `redteam` → 启用多轮驱动器 + 工具滥用模拟 + LLM-judge。
- `FastScanner.scan_target` 现有 `getattr(f"_check_{rule}")` 分发**不动**；新模式只改变 `enabled_rules` 与传入的 `target.extra["llm"]` 上下文（与 818 `_checks_llm_skeleton.py` 一致）。
- `web/server.py:/api/chat` 请求体增加 `target_type` 字段，与现有 `scan_mode`(深度) 合并为新双轴；前端 `scanModeMap` 同步扩展（见 §13.3）。

### 12.3 四种测试策略语义

| 策略 | 行为 | 触发 check | 风险/成本 |
|------|------|-----------|-----------|
| `passive` 被动探测 | 只识别 AI 应用特征（暴露工具 schema、系统提示回声、RAG 线索），不发攻击 | 资产发现类（info） | 零风险，可默认对未授权资产跑 |
| `standard` 标准 | 已知规则全量 + 确定性判定 | 全部对应 check | 中 |
| `redteam` 主动红队 | 主动发射对抗 prompt、多轮越狱、工具滥用模拟、LLM-judge 二次确认 | 全 + 主动类 | 需明确授权 |
| `compliance` 合规对照 | 按等保/OWASP/ATLAS 对照产出差距清单 | 全 + 映射 | 报告导向 |

### 12.4 验收
- [ ] `core/scan_strategies.py` 增加 `TargetType` + `get_scan_strategy(target_type, strategy)`；单测覆盖 5×4=20 组合的规则组装。
- [ ] `llm_app/agent/rag` 类型默认启用 `llm_vuln`，`web/api` 不启用。
- [ ] Web 发起扫描可同时选「目标类型 + 策略」，后端正确映射到 `enabled_rules`。

---

## 13. 平台 UI 重设计（对话显示 + 左侧功能栏 + 扫描发起）

> **源码实读依据**：`web/index.html`（4436 行单体 SPA，原生 JS + 内联 CSS，无框架；静态资源仅 `vendor/marked.min.js` + `dompurify.min.js`）。关键发现：
> - **对话模块过小**：`index.html:1613` 「💬 智能助手终端」是主区底部一条 `220px` 高、**默认 `collapsed`(44px)** 的横向终端条；消息为等宽 12px 单行 flex（无气泡、无 `max-width`），视觉上像日志不像对话（`index.html:536/560`）。
> - **侧边栏分组不合理**：`index.html:1160` `<aside class="sidebar">` 固定 240px，主导航仅 🎯目标/🔍扫描/🛡️漏洞/📊报告/⚙️设置；LLM 监控、决策回放、方法论等 AI 能力被降级塞进「🧰 高级工具」折叠区，**无 AI/对话专项入口**。
> - **扫描发起仅深度**：`index.html:1538/1655` 只有快速/标准/深度，无目标类型。

### 13.1 对话/红队显示模块升级（从"底部终端条"→"主工作区对话"）

鉴微是 AI 测试平台，**与 LLM 目标的对话/红队过程是第一公民**，必须把对话从"附属终端"提升为"主工作区"。

| 维度 | 现状 | 目标 |
|------|------|------|
| 位置 | 主区底部 220px 折叠条 | **独立主工作区**（右侧分栏或独立「对话/红队」视图），默认展开 |
| 形态 | 等宽日志行 | **气泡式对话**（user/assistant 气泡、`max-width` 约束、markdown 渲染，复用已引入的 `marked`+`DOMPurify`） |
| 字号 | 12px 等宽 | 14px 无衬线，代码块等宽 |
| 交互 | 单行 textarea + 发送 | 多行输入、历史会话列表、回合折叠、证据锚点（点击 finding 跳到对应对话回合） |
| 宽度 | 受限（≤50vh 高） | 可拖拽分隔条调宽，最小 360px |

实现要点：
- 新建 `index.html` 内 `<section id="redteamWorkspace">`（或独立 `redteam.html`），与原终端面板解耦。
- 复用 `vendor/marked.min.js` + `dompurify.min.js` 渲染助手/目标回复的 markdown。
- 接入 `core/session/chat_loop` 的多轮驱动器：红队对话 = 向 `target LLMClient` 发消息，回复实时渲染为气泡；judge 判定结果以徽标（✅中招/❌未中/⚠️可疑）贴在气泡旁。
- 证据可溯：每条 finding 的 `trace_id` 链接回触发它的对话回合（呼应 L0「证据优于概率」铁律）。

### 13.2 左侧功能栏重构

新增 **AI/对话/评测** 一级入口，重排分组，让平台定位（扫描—评测—护栏—报告）在导航上一目了然：

| 旧（index.html:1166） | 新侧边栏（建议） |
|----------------------|------------------|
| 🎯 目标 / 🔍 扫描 / 🛡️ 漏洞 / 📊 报告 / ⚙️ 设置 | 🎯 目标资产 / 🔍 扫描测试 / 🤖 对话·红队 / 🛡️ 漏洞发现 / 📈 评测度量 / 📊 报告合规 / ⚙️ 设置 |

- **🤖 对话·红队（新增一级）**：直达红队工作区（§13.1），承载与目标 LLM 的对抗对话。
- **📈 评测度量（新增一级）**：ASR/拒答率/泄露率/护栏拦截率看板（对应 L4）。
- 「🧰 高级工具」保留但精简：仪表盘、流量、决策回放、方法论、记忆管理、站点地图、加密模板、LLM 监控归入其下或各自一级。
- 侧边栏默认 **展开（240px）**，可折叠为图标（64px）；图标 + 文字常显，避免 AI 能力被藏进折叠区。

### 13.3 扫描发起 UX 重设计（双轴选择器）

把 `index.html:1655` 的单一下拉改为 **「新建测试」向导 / 双轴选择器**：

- **Step1 目标类型**：卡片选择 Web / API / LLM 应用 / Agent·MCP / RAG（对应 §12.1 `TargetType`）。
- **Step2 测试策略**：被动探测 / 标准 / 主动红队 / 合规对照（对应 §12.1 `TestStrategy`）。
- **Step3 范围与授权**：目标 URL + 鉴权 + 授权确认（合规门禁，复用引擎 O3/O1）。
- 选型实时提示将启用哪些 check（如选 LLM 应用 + 红队 → 提示"将运行 OWASP LLM Top10 13 项检查"）。

### 13.4 验收
- [ ] 对话模块默认展开为主工作区气泡式，手测可发多轮红队对话并渲染 markdown。
- [ ] 侧边栏含「对话·红队」「评测度量」一级入口，AI 能力不再藏于折叠区。
- [ ] 新建测试可同时选目标类型 + 策略，提示启用 check 清单。

---

## 14. 改动设计记录（Change Design Log / 设计决策台账）

> 本表把所有"相对当前源码的改动"固化为设计决策，便于评审、回溯与开发拆卡。每条含：现状(源码证据) → 目标 → 方案要点 → 验收 → 优先级 → 关联章节。

| 编号 | 模块 | 现状（源码证据） | 目标 | 方案要点 | 验收 | 优先级 | 关联 |
|------|------|------------------|------|----------|------|--------|------|
| **C1** | 扫描模式 | `scan_strategies.py` 仅深度维度(FAST/STANDARD/DEEP/SMART)；UI 只选深度 | 双轴（目标类型×策略） | 新增 `TargetType` 枚举 + `get_scan_strategy(target_type,strategy)`；UI 双轴选择器 | 20 组合规则组装单测通过；llm 类型默认启用 llm_vuln | P0 | §12 |
| **C2** | LLM 专项扫描 | `core/fast_scanner` 无 llm_vuln；`core/llm_security` 不存在 | 13 check 接入 | 新增 `_checks_llm.py` mixin + `core/llm_security/`（attacks/judge/conversation/tool_abuse/extraction/mcp_exploit/agent_eval/rag_poison）+ `rules/llm_vuln.yaml` | 10 类 + Agent/MCP 新面均有可执行用例 | P0 | 818 设计文档 §1.7 |
| **C3** | 对话显示 | `index.html:1613` 底部 220px 折叠终端条，12px 等宽无气泡 | 主工作区气泡对话 | 新建 redteamWorkspace，复用 marked+DOMPurify，多轮+证据锚点 | 默认展开、气泡渲染、点击 finding 跳回合 | P0 | §13.1 |
| **C4** | 左侧功能栏 | `index.html:1160` 240px，AI 能力藏「高级工具」 | 增 AI/对话/评测一级入口 | 重排分组，新增 🤖对话·红队 / 📈评测度量 | 导航含新入口，默认展开 | P1 | §13.2 |
| **C5** | 扫描发起 UX | `index.html:1655` 单一下拉(深度) | 双轴向导 | 新建测试向导：目标类型→策略→范围授权 | 可同时选两类并提示 check 清单 | P0 | §13.3 / §12 |
| **C6** | 评测度量看板 | 仅 `llm_monitor.html` 用量监控 | ASR/拒答率/泄露率/拦截率看板 | 扩展 `core/metrics.py` + `metrics_api.py`，新增 📈评测度量视图 | 指标实时可见、可回归 | P2 | §4 PD6 / §5.5 PF1 |
| **C7** | 护栏 sec_shield | 无（grep 0） | 输入校验→策略→输出过滤 | 新建 `core/ai_sec/sec_shield/`，自攻自防闭环 | 策略可自定义、拦截率可度量 | P1 | §4 PD5 |

---

## 15. 附录：参考与事实源

- `2026-ai安全专家.docx` §四 玄鉴升级路线图（定位 / 4.1 现状 / 4.2 架构 / 4.3 增量 / 4.4 商业化）
- `XUANJIAN_MASTER_PLAN.md`（v1.6）— 引擎工程状态、优先级、产品策略、7 角色行动清单、DoD
- `xuanjian-main/` 源码实读 — 模块路径、能力边界（确认无 AI-native 安全模块）
- 外部基准：OWASP LLM Top 10 (2025)、OWASP Agentic AI Threats、MITRE ATLAS、NVIDIA NeMo Guardrails、Guardrails AI、PyRIT、Garak
- 其他故意漏洞靶场（多靶场标注集，100% 本地可自托管）：[LLMVault](https://github.com/CyberSunil/LLMVault)（OWASP LLM Top10 CTF，25+3 实验）、[AIGoat](https://github.com/AISecurityConsortium/AIGoat)（真实模型+攻防分级+可投毒RAG）、[DVLAA](https://github.com/Tcotl/DVLAA)（LLM+Agent 双维度）、[DVAP](https://github.com/sonuoffsec/DVAP)（15 舱+Benchmark+MITRE ATLAS+MCP 利用）
- 智能体安全基准（带标注数据集，提供真实 ASR 数字）：AgentDojo(NeurIPS24)、InjecAgent(ACL24)、Agent Security Bench(ICLR25)、CyberSecEval2(Meta)、MCPTox、BIPIA(KDD25)
- `hollowing-optimization-plan/818/` 三件套（详细设计事实源）：`LLM漏洞扫描器设计方案.md`（总体设计 + 其他靶场/基准研究 §1.5–§1.7）、`OWASP_LLM_Top10_攻击研究与映射.md`（LLMVault + AIGoat/DVLAA/DVAP/Gandalf + AgentDojo/InjecAgent/ASB/CyberSecEval/MCPTox/BIPIA 攻击映射 §13–§15）、`benchmark_plan.md`（标注靶场评测细则）

> **行动建议（下一步）**：① 命名已锁定**鉴微 JianWei**，开源策略已拍板 —— **xuanjian 持续维护 + 鉴微同步开源（见 §6）**；② 本文件作为"平台化"唯一事实源，引擎层改动仍回流引擎 Master Plan；③ Q3 立即启动 xuanjian 持续维护 + M1/M2 与引擎 S1–S2 并行，按 §5.8 各角色"本周 3 件事"拆卡。
