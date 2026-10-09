# 玄鉴 XuanJian · 新增「Skill 源码 / 供应链扫描」设计方案

> 研究触发：用户提议借鉴 [NVIDIA/SkillSpector](https://github.com/NVIDIA/SkillSpector)（agent skill 安装前安全扫描器），
> 并追问「扫描设计要不要做上传接口」。本文给出结论与落地设计。
> 配套文档：`LLM漏洞扫描器设计方案.md`（黑盒红队模式）、`AI安全测试平台_MASTER_PLAN.md`（§12 双轴扫描模型）。
> 输出目录：`D:\jianwei-main\818\`

---

## 0. 问题与原型结论（先给答案）

用户两个问题，先给结论，后给理由：

| 提问 | 结论 |
|------|------|
| ① 扫描模式及 agent 能否借鉴 SkillSpector？ | **能，且建议借鉴**，但借鉴的是它的「**静态/供应链**扫描管道」与「**不执行**信任边界」两件事；不是把它整体搬来替代现有 LLM 红队扫描。它补的是现有方案**缺失的一类面**——对「agent 技能包 / MCP server 包」源码本身的安全审计。 |
| ② 扫描设计要不要做「上传接口」？ | **要做，但作为多种摄入通道（ingestion）之一，而非唯一入口**。上传 = 把「本地目录 / zip / 单文件 SKILL.md」变成 Web 拖拽入口；底层仍走与 `path` / `git` / `url` 相同的引擎。并配齐护栏（不执行、体积上限、防 zip-bomb、YARA 预扫、扫完即焚）。 |

> **一句话定位**：在玄鉴「双轴扫描模型」里新增 `TargetType = skill`，用 SkillSpector 式的**静态分析管道**扫描一个*源码包*（而非一个*运行中的端点*），与现有 `llm_app` 黑盒红队形成「动静互补」。

---

## 1. SkillSpector 核心机制（已实读）

| 维度 | 做法 |
|------|------|
| 定位 | AI agent skills 的**安装前**安全扫描器（NVIDIA Verified Skills pipeline 一环） |
| 管道 | LangGraph 扫描图 + 分析器注册表 + CLI/MCP/Python 三种接口 |
| 分析器 | ① MCP 分析（最小权限 / 工具投毒 / rug-pull）② 静态模式（提示注入 / 数据外泄 / 过度代理 / 提权）③ 语义（LLM 评估开发者意图）④ 行为（AST + 污点追踪）⑤ 供应链（OSV.dev 实时 CVE 查询） |
| **信任边界** | **永不执行被扫描技能**；只做静态 + 可选 LLM 内容评估 |
| 输入 | Git URL / 单文件 / 本地目录 / Zip 压缩包 / 远程 URL |
| 输出 | 终端报告 / JSON / Markdown / **SARIF 2.1.0**；风险 0–100，严重级 LOW–CRITICAL；可执行脚本 ×1.3 倍率；退出码作安装门禁 |
| 接口 | CLI `skillspector scan <target>`；MCP Server 暴露单工具 `scan_skill(target, use_llm, output_format)`；Python API `graph.invoke(...)` |

**可借鉴的 4 个点**：
1. **不执行被扫对象** —— 把「审源码」和「跑代码」彻底隔离，安全且可离线。
2. **两阶段管道** —— 静态高召回（正则/AST/YARA/OSV）打底，LLM 语义二次降误报。
3. **多格式输出 + 退出码门禁** —— 能直接塞进 CI / 安装前卡点。
4. **多入口** —— CLI / Python API / MCP 工具，让 agent 自己能调用它来「自审」。

**不必照搬的 2 个点**：
- SkillSpector 强绑定 NVIDIA 自家的「Verified Skills 签名体系（OMS）」与模型注册表，玄鉴不需要。
- 它的「上传」概念很弱（CLI 传 path/url），是因为它定位为本地工具；玄鉴是**带 Web UI 的产品**，所以需要显式设计上传通道。

---

## 2. 与现有 LLM 扫描器的关系：动静互补，不冲突

现有 818 设计文档的 LLM 扫描器是**黑盒、动态、运行时**：

```
现有（动态红队）：构造对抗 prompt → 发往目标 LLM 端点 → 解析响应 → 判定是否中招
                    （core/llm.LLMClient 当"攻击发射器" + judge 当"裁判"）
```

SkillSpector 式扫描是**白盒、静态、源码期**：

```
新增（静态供应链）：摄入 skill 包 → 读 SKILL.md/脚本/依赖 → 静态+语义分析 → 产出风险发现
                     （绝不执行包内任何代码）
```

两者面对的攻击面不同、生命周期不同，建议**并行管道、统一回流**：

| 面 | 动态红队（已有） | 静态供应链（新增） |
|----|------------------|---------------------|
| 被测对象 | 运行中的 LLM 应用 / Agent 端点 | agent 技能包 / MCP server 包 / 依赖目录 |
| 触发时机 | 授权后主动打 | 安装前 / 采纳前 / CI 门禁 / 红队前 reconnaissance |
| 核心风险 | 提示注入、过度代理、RAG 越权 | 技能内含恶意指令、工具投毒、rug-pull、依赖 CVE、数据外泄脚本 |
| 能否互相替代 | 否 | 否 |

> 关键价值：红队前先「审源码」能**提前暴露目标的攻击面**（例如一个会自动外发对话记录的 skill），让动态红队更有针对性；反过来动态红队验证静态发现是否「真能触发」。

---

## 3. 新增扫描模式设计

### 3.1 双轴模型扩展（对齐 MASTER_PLAN §12）

在 `core/scan_strategies.py` 的 `TargetType` 枚举**新增 `skill`**（可选再细分 `mcp_server`）：

| 轴 | 取值（新增项加粗） |
|----|-------------------|
| **目标类型 TargetType** | `web` / `api` / `llm_app` / `agent` / `rag` / **`skill`** |
| **测试策略 TestStrategy** | `passive` / `standard` / `redteam` / `compliance` |

对于 `skill` 目标，「红队/被动」语义不再适用，策略轴改写为**三层静态分析开关**（仍复用 `TestStrategy` 枚举，仅解释不同）：

| skill 策略 | 行为 |
|-----------|------|
| `passive` | 仅做文件清单 + 元数据 + 依赖清单（info 级） |
| `standard` | 静态正则 + AST + OSV 供应链（默认） |
| `redteam` | 在 standard 基础上**再加 LLM 语义分析**（降误报、出可读解释） |
| `compliance` | 对照 OWASP LLM Top 10 / MITRE ATLAS 出差距清单 |

`enabled_rules` 组装：当 `target_type == skill` 时，追加 `"skill_scan"`（触发新增的 `_ChecksSkill` mixin），**不**触发 `llm_vuln`（那是打运行中的端点）。

### 3.2 静态分析管道（分析器注册表）

仿 SkillSpector 注册表模式，在 `core/llm_security/skill_scan/` 落地：

```
core/llm_security/skill_scan/
  __init__.py
  ingest.py        # 摄入：目录/zip/git/url/单文件 → 规范化文件树（含防 zip-bomb）
  registry.py      # 分析器注册表（analyzer 插件机制）
  analyzers/
    pattern.py     # 静态正则：提示注入 sink、外发 URL/Webhook、硬编码密钥
    ast_behavior.py# Python AST：exec/eval/subprocess/os.system/socket/动态 import
    supply_chain.py# 解析依赖清单 → OSV.dev 查 CVE（无 key，离线回退）
    yara_scan.py   # 可选：已知 malware/webshell/挖矿签名（初始可留空规则）
    semantic.py    # 可选 LLM：开发者意图 + 风险语义（带反越狱保护）
  scoring.py       # 0–100 评分 + 严重级 + 可执行脚本 ×1.3
  report.py        # VulnFinding 回流 + SARIF 导出
```

**各分析器映射到的 OWASP / 威胁**（适配玄鉴已有的 LLM Top10 + Agent 威胁模型）：

| 分析器 | 检测的 skill 风险 | 映射 |
|--------|------------------|------|
| pattern | SKILL.md 内指令覆盖短语、诱导外发数据、读取本地文件的提示 | LLM01 提示注入 / LLM02 敏感泄露 |
| ast_behavior | 脚本里 `subprocess`/`os.system`/`eval`/`socket` 调用、硬编码密钥、动态导入 | LLM06 过度代理 / LLM03 供应链 |
| supply_chain | 依赖清单命中已知 CVE（OSV） | LLM03 供应链 |
| semantic | 开发者意图是否含隐蔽外泄 / 权限提升 / rug-pull（版本更新后行为突变） | LLM06 / 工具投毒 / rug-pull |
| yara_scan | 已知恶意载荷（webshell、挖矿） | 通用恶意代码 |

### 3.3 信任边界（铁律，沿用 SkillSpector）

- **绝不执行**被扫 skill 包内任何脚本 / 二进制 / 安装钩子。
- 摄入后仅做**只读解析**；若包内含可执行文件，只做 YARA/哈希特征比对，不运行。
- LLM 语义分析时，把文件内容发往**玄鉴自有** judge 模型（复用 `core/llm.LLMClient`），不外泄到第三方；judge prompt 带反越狱保护。
- 供应链查询只把**依赖坐标**（包名+版本）发往 OSV.dev，不发源码。

### 3.4 判定与评分

- 复用 `core/false_positive_manager` 做误报过滤。
- 评分沿用 SkillSpector 思路但落到玄鉴 schema：
  - `risk_score` 0–100；严重级 `critical/high/medium/low`。
  - 含可执行脚本的 skill **×1.3 倍率**（可执行 = 风险放大器）。
  - 每条发现写入 `VulnFinding`：`file_path` + `line` + `owasp` + `recommendation` + `safe_to_install`（bool）。
- 退出码可作门禁：`<=50` 通过(0) / `>50` 阻断(1) / 错误(2)。

---

## 4. 上传接口设计（用户核心提问，给出方案）

### 4.1 结论

**做上传接口，但定位为「多种摄入通道之一」**：

```
摄入通道（统一进 ingest.py）
  ├─ (A) 本地路径 path        ← CLI / 服务端调用（本地优先，零网络风险）
  ├─ (B) Git URL              ← 服务端 clone 到沙箱
  ├─ (C) 远程 URL             ← 下载到沙箱（限大小、限域名可选）
  ├─ (D) Zip / tarball        ← 上传接口主载体
  └─ (E) 单文件 SKILL.md      ← 上传接口轻量载体（拖一个文件即扫）
```

上传接口 = 把 (D)(E) 做成 **Web 拖拽 / 文件选择**，落到 `web/api` 的新 router（如 `/api/scan/skill/upload`），后台转交同一 `ingest.py`，**与 (A)(B)(C) 共用分析管道**。

### 4.2 上传接口护栏（必须，否则上传比 path 更危险）

| 护栏 | 做法 |
|------|------|
| 体积上限 | 单文件 ≤ 1 MiB（参考 SkillSpector `MAX_FILE_BYTES`）；压缩包 ≤ 100 MiB、成员 ≤ 10,000（防 zip-bomb） |
| 不执行 | 上传内容只进分析器，**绝不 chmod/运行**；临时落盘到 `tmp/skill_scan_<uuid>/`，扫完即删 |
| 二进制预筛 | 解包后先用 YARA/扩展名黑名单识别可执行文件，仅做特征比对，不运行 |
| 路径穿越 | 解包时规范化路径，拒绝 `../` 与绝对路径写入沙箱外 |
| 内容治理 | 若上传内容本身含违规载荷，经 `core/harm_validation` 把关，不外显可利用细节 |
| 认证 | 上传接口挂现有会话鉴权（玄鉴 web/api 已有）；生产环境建议默认仅内网/授权用户可上传 |
| 速率 | 限制并发上传扫描数，避免资源耗尽 |

### 4.3 接口契约（建议）

```
POST /api/scan/skill/upload
  multipart/form-data: file=(zip|md|目录打包) , strategy=(passive|standard|redteam|compliance)
  → 202 { scan_id, status:"ingesting" }
GET  /api/scan/skill/{scan_id}
  → { risk_score, severity, safe_to_install, findings:[VulnFinding...], sarif_url? }
```

同时保留 **CLI**（本地优先，呼应 SkillSpector 习惯）：

```bash
xuanjian scan-skill ./my-skill/ --strategy redteam --format sarif
xuanjian scan-skill https://github.com/foo/bar-skill --format json
```

---

## 5. Agent 集成：让玄鉴自己能「自审」skill

借鉴 SkillSpector 把扫描暴露成 **MCP 工具**的做法，给玄鉴 agent 一个 `scan_skill` 能力：

- **MCP 工具（可选）**：`scan_skill(target, use_llm=true, output_format="json")` —— 让玄鉴 agent（或任意兼容 MCP 的 agent）在**安装/调用第三方 skill 之前先自审**，闭合「供应链安全」回路。
- **Agent 内工具调用**：在 `core/tool_router` 注册 `scan_skill`，红队编排（`core/session/chat_loop`）可在 reconnaissance 阶段先扫目标所用 skill 的源码，再把发现喂给后续动态红队。
- **复用现有 judge**：语义分析直接复用 `core/llm_security.judge`，不另起炉灶。

---

## 6. 与现有引擎接入点（零侵入优先）

| 改动点 | 内容 |
|--------|------|
| `core/scan_strategies.py` | `TargetType` 加 `skill`；`get_scan_strategy` 对 `skill` 返回 `enabled_rules=["skill_scan"]` + 静态策略映射 |
| `core/fast_scanner/_engine.py` | `FastScanner` 基类加 `_ChecksSkill` mixin；`all_rules` 追加 `"skill_scan"` |
| `core/fast_scanner/_checks_skill.py`（新增） | 仿 `_checks_llm_skeleton.py` 的 mixin：`_check_skill_scan(target)` → 调 `core/llm_security/skill_scan` |
| `core/llm_security/skill_scan/`（新增包） | 见 §3.2 |
| `web/api/`（新增 router） | `/api/scan/skill/upload` + 查询接口（见 §4.3） |
| 前端「新建测试」向导 | `TargetType` 卡片加「技能包 / Skill」；选 skill 后策略轴改为 passive/standard/redteam/compliance |
| 报告 | `compliance_report` 增加「技能供应链安全」章节；支持 SARIF 导出 |

> 接入方式与 818 `_checks_llm_skeleton.py` 同构：`getattr(self, f"_check_{rule}")` 分发机制**不动**，只需加一个 `skill_scan` 规则名与对应 mixin。

---

## 7. 输出格式

- **主回流**：沿用 `VulnFinding`（自动获得 `trace_id` / `evidence_quality`），新增字段 `file_path` / `line` / `safe_to_install`。
- **可选 SARIF 2.1.0**：供 CI / IDE（与 SkillSpector 对齐，便于企业接入现有 DevSecOps）。
- **风险评分**：0–100 + 严重级 + 可执行脚本 ×1.3；退出码作门禁。

---

## 8. 实施路线图

| 阶段 | 内容 | 交付 |
|------|------|------|
| **M0（P0）** | `skill_scan/ingest.py` + `pattern` + `ast_behavior` 两个分析器；CLI `xuanjian scan-skill <path>` 跑通；`_ChecksSkill` mixin 接入 | 能扫本地 skill 目录，产出基础发现 |
| **M1** | `supply_chain`（OSV）+ `scoring` + VulnFinding 回流 + 报告章节 | 含 CVE 与评分 |
| **M2** | **上传接口**（`/api/scan/skill/upload` + 护栏）+ 前端向导卡片 | Web 拖拽扫描 |
| **M3** | `semantic`（LLM 降误报）+ `yara_scan` + SARIF 导出 + MCP `scan_skill` 工具 | 动静互补闭环 + agent 自审 |

---

## 9. 结论（回应两个提问）

1. **能否借鉴 SkillSpector？** 能。借鉴其「**静态/供应链分析管道**」与「**绝不执行被扫对象**」两条核心原则，作为玄鉴**新增的 `skill` 目标类型**扫描，与现有黑盒 LLM 红队形成动静互补。**不**整体替换现有方案，**不**绑定 NVIDIA 私有签名体系。
2. **要不要做上传接口？** 要做，作为多种摄入通道之一（目录/zip/单文件/拖拽），底层与 path/git/url 共用引擎，并配齐「不执行 + 体积上限 + 防 zip-bomb + YARA 预筛 + 扫完即焚 + 会话鉴权」护栏。同时保留 CLI 与（可选）MCP `scan_skill` 工具，让玄鉴 agent 能自审第三方技能。

---

## 10. 交付物（本目录）

| 文件 | 说明 |
|------|------|
| `Skill供应链扫描_设计方案.md` | 本文：SkillSpector 借鉴分析 + skill 静态扫描模式设计 + 上传接口决策 |
| `LLM漏洞扫描器设计方案.md` | 现有黑盒 LLM 红队扫描（动态模式，本文的补充面） |
| `AI安全测试平台_MASTER_PLAN.md` | 平台总纲，§12 双轴扫描模型（本文 `skill` 目标类型在此扩展） |
