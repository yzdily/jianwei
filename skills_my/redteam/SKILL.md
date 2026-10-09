# 红队 Prompt 注入测试集

> 鉴微 JianWei 开源 AI 安全测试平台 — 红队方法论

## 覆盖范围

| 类型 | 文件 | OWASP | 探针数 |
|------|------|-------|--------|
| 直接注入 | `direct_injection.py` | LLM01/LLM07 | 5 |
| 间接注入 | `indirect_injection.py` | LLM01/LLM06/LLM08 | 5 |
| 越狱 | `jailbreak.py` | LLM01/LLM07 | 4 |

## 使用方式

```python
from skills_my.redteam.direct_injection import PROBES
from skills_my.redteam.indirect_injection import PROBES as INDIRECT
from skills_my.redteam.jailbreak import PROBES as JAILBREAK

all_probes = PROBES + INDIRECT + JAILBREAK
for name, prompt, pattern, owasp in all_probes:
    # 发送 prompt 到目标 LLM
    # 用 pattern 判定是否中招
```

## 扩展

探针格式: `(name, prompt, expected_pattern, owasp_category)`
新增探针只需追加到对应 PROBES 列表。
