# 鉴微 JianWei · AI 安全测试平台

**简体中文** | [English](README.en.md)

> 「见微知著，洞见 AI 之险」

**由 [玄鉴 XuanJian](https://github.com/yzdily/xuanjian) 持续维护的引擎驱动的开源 AI 安全测试平台**

<p>
  <a href="#快速开始">快速开始</a> ·
  <a href="#架构">架构</a> ·
  <a href="#功能模块">功能模块</a> ·
  <a href="#贡献">贡献</a>
</p>

---

## 是什么

鉴微是一个覆盖「**资产发现 → 攻击/评测 → 护栏 → 度量 → 报告**」的 **AI 应用安全测试平台**，被测对象包括 Web / API / RAG / Agent 系统。

- **不是**又一个 Web 漏扫
- **不是**纯评测集
- **不是**只做护栏

它是**把红队能力产品化、把 AI 风险可量化**的平台。

## 核心飞轮

```
玄鉴引擎（真实攻击执行力）+ 鉴微平台层（AI-native 评测/护栏/度量）
    → 评测数据反哺 SKILL 与规则 → 越测越准
```

**一句话**：鉴微把"会攻的玄鉴"升级为"会评、会防、会量化的 AI 安全测试平台"。

## 架构（6 层）

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
│  L0  引擎基座（玄鉴 XuanJian v2.0 持续维护）                     │
│      爬虫·编排·并行·上下文·危害验证                              │
└─────────────────────────────────────────────────────────────┘
```

| 层 | 职责 | 状态 |
|---|---|---|
| **L0 引擎基座** | 真实攻击执行、浏览器/代理、编排、危害验证 | 玄鉴 v2.0（持续维护） |
| **L1 资产/接口层** | 识别被测 AI 应用攻击面（被动探测） | ✅ 已实现（`_checks_web.asset_discovery`） |
| **L2 攻击/评测层** | 红队用例执行引擎（LLM 13 check + 注入测试集 + RAG/Agent 评测 + 技能供应链） | ✅ 已实现 |
| **L3 护栏层 sec_shield** | 输入/输出校验、敏感拦截、可插拔策略 | ✅ 已实现（`core/ai_sec/sec_shield`） |
| **L4 评测度量层** | ASR/拒答率/泄露率/护栏拦截率、回归基线 | ✅ 已实现（`core/ai_sec/metrics`） |
| **L5 报告/合规层** | 可审计安全报告、整改清单、等保对齐 | ✅ 已实现（LLM Top10 章节 + ATLAS + SARIF + 完整合规组装；等保为参考对齐） |

## 功能模块

### L2 · 攻击/评测层

| 模块 | 功能 | 目录 | 状态 |
|------|------|------|------|
| **LLM 漏洞扫描器** | OWASP LLM Top 10 + Agent/MCP 自动化检测（13 check） | `core/ai_sec/llm_top10/` | ✅ 已实现 |
| **Prompt 注入 / 越狱测试集** | 可复用注入/越狱探针库（direct/indirect/jailbreak/multimodal） | `core/ai_sec/prompt_injection/` | ✅ 已实现（内置 22 探针 + 收编 `skills_my/redteam/`） |
| **Agent 安全评测** | 工具调用越权 / 编排逃逸 / 记忆投毒 | `core/ai_sec/agent_eval/` | ✅ 已实现（3 评估器） |
| **RAG 安全检测** | 知识库投毒 / 越权检索 / 溯源一致性 | `core/ai_sec/rag_sec/` | ✅ 已实现（3 检测器） |

> 三者均**复用引擎级原语**（`core/llm_security/*`），只做「适配 + 用例库 + 运行器」，不重写检测逻辑。

### L3 · 护栏层

| 模块 | 功能 | 目录 |
|------|------|------|
| **sec_shield** | 输入校验→策略引擎→输出过滤，可插拔，自攻自防闭环 | `core/ai_sec/sec_shield/` |

### L4 · 评测度量层

| 模块 | 功能 | 目录 |
|------|------|------|
| **评测度量** | ASR / 拒答率 / 泄露率 / 护栏拦截率 / 回归基线（含 `hook.py` 飞轮挂钩 + `baseline.py` 回归对比） | `core/ai_sec/metrics/` |

### 扫描引擎与双轴模型

| 模块 | 功能 | 目录 |
|------|------|------|
| **双轴扫描策略** | `TargetType`(web/api/llm_app/agent/rag/skill) × `TestStrategy`(passive/standard/redteam/compliance) 工厂 | `core/scan_strategies.py` |
| **FastScanner 接线层** | 多重继承 mixin + `getattr(_check_{rule})` 分发，零侵入接入 | `core/fast_scanner/` |
| **技能供应链扫描** | 静态分析（pattern/AST/OSV/语义/YARA），绝不执行被扫对象，SARIF 导出 | `core/llm_security/skill_scan/` |
| **3 个新增 check** | RAG 投毒 / Agent 逃逸 / MCP 滥用 | `core/llm_security/{rag_poison,agent_eval,mcp_exploit}.py` |
| **AI 风险矩阵接入（E）** | `ai` 域 sidecar 归属 + `AIMatrixRunner`（归属→执行→门裁决→矩阵格），接入引擎 testflow 矩阵（零侵入） | `core/ai_sec/ai_matrix/` |
| **基准测试** | LLMVault 标注靶场回放，产出检测率/误报率 | `core/llm_security/benchmark.py` + `tests/golden/` |
| **Web API** | 技能上传扫描 + 双轴扫描接口 + digpool SSE + SARIF | `web/api/` |
| **CLI** | `scan-skill` / `scan` 命令行 | `core/cli.py` |

## 设计原则

- **证据优于概率**（玄鉴铁律延伸）：每个 LLM/Agent 风险必须给出**可复现证据**（payload + 响应 + 判定），不靠概率妄断
- **sec_shield 自攻自防闭环**：L3 护栏同时作为 L2 评测的"被测对象"——用鉴微自己的红队探针测自己的护栏
- **复用 harm_validation 判定范式**：AI 风险定级复用"危害验证 + 证据"逻辑
- **零侵入扩展**：平台层只消费引擎公开契约（`getattr(_check_{rule})` 追加规则名 + mixin），不反向修改引擎

## 快速开始

> **环境要求**：Python >= 3.10

```bash
# 1. 克隆仓库
git clone https://github.com/yzdily/jianwei.git
cd jianwei

# 2. 安装依赖（含玄鉴引擎）
pip install -r requirements.txt
# 最小依赖（仅 CLI + 工作台，零重依赖）：
pip install -r requirements-min.txt

# 3. 配置 LLM
cp .env.example .env

# 4. 启动
python start.py
```

## 快速使用

```bash
# 静态扫描一个技能包 / MCP server 包（目录 / zip / 单文件 / URL / git）
python start.py scan-skill ./my-skill/ --strategy redteam --format sarif
python -m core.cli scan-skill ./my-skill/ --strategy standard

# 双轴扫描目标（Web / API / LLM 应用 / Agent / RAG）
python -m core.cli scan https://llm.example.com/v1/chat --target-type llm_app --strategy standard

# 启动 Web API（上传技能包 / 发起扫描 / digpool 对话 / 导出 SARIF）
uvicorn web.api:app --reload
#  → POST /api/scan/skill/upload  (multipart: file + strategy)
#  → POST /api/scan/target         (JSON: url + target_type + strategy)
#  → POST /api/digpool/chat        (SSE 对话式挖洞终端)
#  → GET  /api/scan/skill/{scan_id}/sarif
```

运行测试（含标注靶场基准）：

```bash
pytest tests/ -q
```

## MVP 工作台（AI 挖洞闭环）

> 鉴微 MVP 是对标蛙池AI / 玄鉴 DEEP 档的 Agentic Loop 工作台（非单个扫描器），位于 `core/digpool/`，
> 零依赖可跑（玄鉴引擎缺失时自动降级 StubCore，无需 LLM 密钥）。

```bash
# 端到端演示：skill-scan 真实检测 + 六维治理审批门 + LOOP 引擎骨架
python -m core.digpool demo --target tests/fixtures/malicious_skill
python -m core.digpool demo --target tests/fixtures/clean_skill
python -m core.digpool tools          # 列出已注册 curated 工具
python -m core.digpool loop --trigger sqli_possible   # 跑一次 LOOP 骨架
```

待改清单与里程碑见 [`MVP_GAP_ANALYSIS.md`](./MVP_GAP_ANALYSIS.md)。

## 与玄鉴的关系

| 维度 | 玄鉴 XuanJian | 鉴微 JianWei |
|---|---|---|
| 角色 | 持续维护的开源引擎 / 内核 | 在其上构建的开源 AI 安全测试平台 |
| 仓库 | `github.com/yzdily/xuanjian`（MIT，持续维护） | `github.com/yzdily/jianwei`（Apache-2.0） |
| 受众 | 安全研究员、自托管玩家 | 企业 AI 团队、红队、合规方 |
| 边界 | 引擎 / 规则 / SKILL（上游持续演进） | 核心平台（L1-L5 + 测试集 + 看板）全开源 |

> **依赖模式**：玄鉴引擎持续维护中（不冻结功能），鉴微跟随引擎演进；平台层只消费引擎公开契约，不反向修改。

## 许可证

- 鉴微平台层：**Apache-2.0**
- 玄鉴引擎（依赖）：**MIT**

> **法律声明**：本工具仅供获得合法授权的安全测试使用。未经授权使用属于违法行为。详见 [DISCLAIMER.md](DISCLAIMER.md)
