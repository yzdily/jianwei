"""`ai` 域接入 testflow 矩阵（E · 平台 sidecar，零侵入）。

见《AI风险接入testflow矩阵_设计稿_2026-10-08.md》。
- E2 端点归属：`AIEndpointTagger`
- E3 矩阵执行：`AIMatrixRunner` + `adapter.to_matrix_finding` + `_gates`（引擎优先，本地降级）
"""
from __future__ import annotations

from core.ai_sec.ai_matrix.adapter import to_matrix_finding
from core.ai_sec.ai_matrix.runner import AIMatrixResult, AIMatrixRunner, load_playbook
from core.ai_sec.ai_matrix.tagger import AI_DOMAIN, AIEndpointTagger

__all__ = [
    "AI_DOMAIN",
    "AIEndpointTagger",
    "AIMatrixRunner",
    "AIMatrixResult",
    "load_playbook",
    "to_matrix_finding",
]
