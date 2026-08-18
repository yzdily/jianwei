# 鉴微 JianWei 架构文档

> 鉴微是在玄鉴 XuanJian v2.0 封板引擎之上构建的 AI 安全测试平台。
> 本文档描述平台层（L1-L5）的架构设计，引擎层（L0）详见 [玄鉴 ARCHITECTURE.md](https://github.com/yzdily/xuanjian/blob/main/ARCHITECTURE.md)。

---

## 平台分层架构

| 层 | 职责 | 状态 |
|---|---|---|
| **L0 引擎基座** | 真实攻击执行、浏览器/代理、编排、危害验证 | 玄鉴 v2.0 封板版（稳定） |
| **L1 资产/接口层** | 识别被测 AI 应用攻击面 | 规划中 |
| **L2 攻击/评测层** | 红队用例执行引擎 | 规划中 |
| **L3 护栏层 sec_shield** | 输入/输出校验、敏感拦截、可插拔策略 | 规划中 |
| **L4 评测度量层** | ASR/拒答率/泄露率/护栏拦截率、回归基线 | 规划中 |
| **L5 报告/合规层** | 可审计安全报告、整改清单、等保对齐 | 规划中 |

## 依赖方向

**单向依赖**：L5 -> L4 -> L3 -> L2 -> L1 -> L0

上层可依赖下层，下层**不可**反向依赖上层。

## L0 引擎基座（玄鉴 XuanJian v2.0 封板版）

依赖方式：pip install xuanjian@git+https://github.com/yzdily/xuanjian@v2.0

复用能力：爬虫(crawler)、编排(session)、并行(parallel)、快速扫描(fast_scanner)、危害验证(harm_validation)、XSS专项(xss)、Fuzz引擎(fuzz)、LLM客户端(llm)

## L2 攻击/评测层

### LLM 漏洞扫描器 (core/ai_sec/llm_top10/)
覆盖 OWASP LLM Top 10 + Agent/MCP 新威胁面（13 check）

### Agent 安全评测 (core/ai_sec/agent_eval/)
目标劫持、工具滥用、记忆投毒、编排逃逸

### Prompt 注入测试集 (core/ai_sec/prompt_injection/ + skills_my/redteam/)
直接注入、间接注入、多模态注入、越狱集

### RAG 安全检测 (core/ai_sec/rag_sec/)
来源审计、向量鉴权、溯源一致性、投毒检测

## L3 护栏层 sec_shield

输入校验 -> 策略引擎 -> 输出过滤（可插拔）
自攻自防闭环：L3 护栏同时作为 L2 评测的被测对象

## L4 评测度量层

ASR（攻击成功率）、拒答率、泄露率、护栏拦截率、回归基线

## L5 报告/合规层

AI 风险报告、整改清单、等保对齐、审计日志

## 扫描模式（双轴重设计）

目标类型 TargetType: web / api / llm_app / agent / rag
测试策略 TestStrategy: passive / standard / redteam / compliance