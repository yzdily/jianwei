# VENDORED MIRROR — 玄鉴 XuanJian v2.0 core/loops/loop_controller.py
#
# 本文件为上游引擎 v2.0 的逐字镜像（仅 import 路径改为 core.digpool.loops.vuln_chain）。
# 鉴微 M3 通过 core_link.get_loop_controller() 优先调用真实 xuanjian 同名公开类；
# 仅在 xuanjian 未 pip 安装时退回本镜像，用于开发/测试。逻辑禁止修改，上游发版须同步。
#
# 来源：F:\xuanjian-main\core\loops\loop_controller.py (F4.3 LOOP 引擎)
from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

try:
    import yaml  # 第三方；离线/未安装环境降级为内嵌矩阵
except Exception:  # pragma: no cover - 仅离线环境触发
    yaml = None  # type: ignore[assignment]

from core.digpool.loops.vuln_chain import VulnChainMemory

_LOOP_MATRIX_PATH = Path(__file__).parent / "loop_matrix.yaml"
_MAX_DEPTH = 3

# 内嵌兜底矩阵：与 loop_matrix.yaml 逐字对应（v2.0 mirror）。
# 仅当 PyYAML 缺失时使用，保证 digpool 在无第三方依赖环境也能跑通 LOOP 引擎；
# 若 PyYAML 可用，仍以 loop_matrix.yaml 文件为权威来源。
_EMBEDDED_MATRIX: dict[str, Any] = {
    "loops": [
        {
            "trigger": "actuator_exposure",
            "description": "/actuator/* 端点暴露",
            "spawn_pattern": "validation_agent",
            "depth_chain": [
                {"step": "scan_all_actuator_endpoints"},
                {"step": "extract_creds_from_env"},
                {"step": "heapdump_download_extract"},
            ],
            "termination": ["heapdump_unreachable", "cipherKey_failed", "rce_confirmed"],
        },
        {
            "trigger": "shiro_remmeberme_active",
            "description": "Shiro rememberMe Cookie 检测 deleteMe 标志",
            "spawn_pattern": "validation_agent",
            "depth_chain": [
                {"step": "detect_rememberme_active"},
                {"step": "extract_cipher_key"},
                {"step": "construct_deserialization_payload"},
                {"step": "validate_rce"},
            ],
            "termination": ["key_unobtainable", "payload_failed", "rce_confirmed"],
        },
        {
            "trigger": "heapdump_leak",
            "description": "/actuator/heapdump 200 且大小 > 1MB",
            "spawn_pattern": "validation_agent",
            "depth_chain": [
                {"step": "download_heapdump"},
                {"step": "string_scan_secrets"},
                {"step": "cross_ref_with_findings"},
            ],
            "termination": ["download_failed", "scan_complete"],
        },
        {
            "trigger": "actuator_env_leak",
            "description": "/actuator/env 含敏感字段",
            "spawn_pattern": "validation_agent",
            "depth_chain": [
                {"step": "extract_all_secrets"},
                {"step": "test_cred_usability"},
                {"step": "report_internal_services"},
            ],
            "termination": ["all_fields_extracted", "encrypted_uncrackable"],
        },
        {
            "trigger": "param_config_leak",
            "description": "一次性返回大量参数的接口",
            "spawn_pattern": "validation_agent",
            "depth_chain": [
                {"step": "list_all_params"},
                {"step": "filter_sensitive"},
                {"step": "classify_severity"},
            ],
            "termination": ["all_params_scanned"],
        },
        {
            "trigger": "unauthenticated_read",
            "description": "未授权可读 API",
            "spawn_pattern": "validation_agent",
            "depth_chain": [
                {"step": "try_write_operations"},
                {"step": "try_admin_endpoints"},
                {"step": "try_sensitive_resources"},
            ],
            "termination": ["write_blocked", "write_succeeded"],
        },
        {
            "trigger": "path_normalization_bypass",
            "description": "../ 或 URL 编码绕过",
            "spawn_pattern": "validation_agent",
            "depth_chain": [
                {"step": "enumerate_all_variants"},
                {"step": "compare_status_codes"},
                {"step": "report_variants_work"},
            ],
            "termination": ["variants_exhausted"],
        },
        {
            "trigger": "vertical_privilege_escalation",
            "description": "403→200 + 返回敏感数据",
            "spawn_pattern": "validation_agent",
            "depth_chain": [
                {"step": "enumerate_all_user_ids"},
                {"step": "cross_user_read_write"},
                {"step": "try_admin_only_endpoints"},
            ],
            "termination": ["all_ids_tested", "blocked"],
        },
        {
            "trigger": "sqli_possible",
            "description": "注入试探 500 错误",
            "spawn_pattern": "validation_agent",
            "depth_chain": [
                {"step": "distinguish_injection_vs_error"},
                {"step": "try_waf_bypass_primitives"},
                {"step": "confirm_with_blind"},
            ],
            "termination": ["waf_bypassed", "confirmed", "ruled_out"],
        },
        {
            "trigger": "ssrf_possible",
            "description": "SSRF 可疑",
            "spawn_pattern": "validation_agent",
            "depth_chain": [
                {"step": "try_internal_targets"},
                {"step": "try_protocol_smuggling"},
                {"step": "try_aws_metadata_endpoints"},
            ],
            "termination": ["internal_blocked", "aws_blocked", "confirmed"],
        },
        {
            "trigger": "xss_possible",
            "description": "XSS 可疑",
            "spawn_pattern": "validation_agent",
            "depth_chain": [
                {"step": "exclude_500_error_echo"},
                {"step": "exclude_error_message_field"},
                {"step": "confirm_in_data_field"},
            ],
            "termination": ["confirmed", "ruled_out"],
        },
    ]
}


@dataclass
class Finding:
    id: str
    vuln_type: str
    severity: str = "Medium"
    url: str = ""
    detail: dict[str, Any] = field(default_factory=dict)
    extracted_artifacts: dict[str, Any] = field(default_factory=dict)


class LoopController:
    """LOOP 引擎：加载矩阵 → 按 trigger 执行 depth_chain。"""

    def __init__(
        self,
        matrix_path: Path | None = None,
        vuln_chain: VulnChainMemory | None = None,
    ):
        path = matrix_path or _LOOP_MATRIX_PATH
        if yaml is not None and path.exists():
            with open(path, encoding="utf-8") as f:
                raw = yaml.safe_load(f) or {}
        else:
            # 零依赖兜底：PyYAML 缺失或矩阵文件不存在时使用内嵌镜像
            raw = _EMBEDDED_MATRIX
        self.matrix: dict[str, dict] = {}
        for entry in raw.get("loops", []):
            self.matrix[entry["trigger"]] = entry
        self.chain = vuln_chain or VulnChainMemory()

    def get_trigger(self, trigger: str) -> dict | None:
        return self.matrix.get(trigger)

    def has_trigger(self, trigger: str) -> bool:
        return trigger in self.matrix

    async def execute(
        self,
        trigger: str,
        context: dict[str, Any],
        step_handler: Callable[[dict, dict], Any] | None = None,
    ) -> list[Finding]:
        """触发 LOOP：执行 depth_chain 每一步，返回所有子发现。

        step_handler: 可选的回调，签名为 (step_def, context) -> Finding|None。
        若不提供则仅记录链路径。
        """
        trigger_def = self.matrix.get(trigger)
        if not trigger_def:
            return []

        depth_chain = trigger_def.get("depth_chain", [])
        findings: list[Finding] = []
        max_depth = min(len(depth_chain), _MAX_DEPTH)

        for i in range(max_depth):
            step = depth_chain[i]

            if self._is_terminated(trigger, context):
                break

            if step_handler is None:
                self.chain.append(trigger, step.get("step", f"step_{i}"), context)
                continue

            step_name = step.get("step", f"step_{i}")
            try:
                step_finding = await step_handler(step, context) if _is_coro(step_handler) else step_handler(step, context)
            except Exception:
                step_finding = None

            if step_finding:
                findings.append(step_finding)
                context.update(step_finding.extracted_artifacts)
                self.chain.append(
                    trigger, step_name,
                    {"finding_id": step_finding.id, **step_finding.detail},
                )
            else:
                self.chain.append(trigger, step_name, {"status": "no_finding"})

        return findings

    def _is_terminated(self, trigger: str, context: dict[str, Any]) -> bool:
        terms = self.matrix.get(trigger, {}).get("termination", [])
        for t in terms:
            if context.get(t):
                return True
        return False


def _is_coro(fn: Callable) -> bool:
    import asyncio
    return asyncio.iscoroutinefunction(fn)


__all__ = ["LoopController", "Finding"]
