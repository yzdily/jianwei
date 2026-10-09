"""流量语料摄入源：代理抓包 / 合规证书抓包 → TrafficCorpus（M2b 闭环）。

真实可运行：
- ProxyTrafficSource：解析 mitmproxy 流导出（JSON Lines，每行为 flow 记录，含
  request.host / request.url / request.method / request.path）或通用代理访问日志，
  产出 TrafficCorpus(source="proxy")。
- ComplianceCertSource：解析 TLS 证书元数据（openssl x509 -text 文本 或 JSON 数组/对象），
  提取 subjectAltName / CN 域名，产出 TrafficCorpus(source="compliance-cert")。

两者均离线可用（无需真实代理/证书服务），并自带 fixtures 供测试。
不依赖玄鉴内部类。
"""
from __future__ import annotations

import json
import re
from typing import Any

from core.digpool.scope import TrafficCorpus, _extract_host
from core.log import get_logger

log = get_logger("core.digpool.ingest")

# SAN 条目形如 DNS:api.example.com 或 DNS:*.example.com（通配符降级为父域）
_SAN_RE = re.compile(r"DNS:\s*(?:[*]\.)?([\w.-]+\.[a-z]{2,})", re.I)
_CN_RE = re.compile(r"CN\s*=\s*([\w.-]+\.[a-z]{2,})", re.I)
_HOST_IN_URL_RE = re.compile(r"https?://([\w.-]+\.[a-z]{2,})(?::\d+)?", re.I)


class ProxyTrafficSource:
    """代理抓包语料源（mitmproxy / 通用访问日志）。"""

    @staticmethod
    def from_mitmproxy_dump(path: str) -> TrafficCorpus:
        """解析 mitmproxy 流导出（JSON Lines）。

        每行一个 flow 对象；支持 request 嵌套（mitmproxy export）或顶层字段两种形态。
        """
        records: list[dict] = []
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    # 非 JSON 行按访问日志处理
                    m = _HOST_IN_URL_RE.search(line)
                    if m:
                        records.append({"url": m.group(0)})
                    continue
                req = obj.get("request", obj)
                host = req.get("host") or _extract_host(req.get("url", ""))
                rec = {
                    "host": host,
                    "url": req.get("url"),
                    "method": req.get("method"),
                    "path": req.get("path"),
                }
                if host or req.get("url"):
                    records.append({k: v for k, v in rec.items() if v})
        return TrafficCorpus.from_records("proxy", records)

    @staticmethod
    def from_access_log(path: str) -> TrafficCorpus:
        """解析 NCSA 风格访问日志，提取其中的 URL 作为语料。"""
        records: list[dict] = []
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                m = _HOST_IN_URL_RE.search(line)
                if m:
                    records.append({"url": m.group(0)})
        return TrafficCorpus.from_records("proxy", records)


class ComplianceCertSource:
    """合规证书抓包语料源：从证书元数据提取域名。"""

    @staticmethod
    def from_cert_text(text: str) -> TrafficCorpus:
        """解析 openssl x509 -text 风格文本，提取 SAN / CN 域名。"""
        domains: list[str] = []
        for m in _SAN_RE.finditer(text):
            d = m.group(1).lower()
            if d not in domains:
                domains.append(d)
        for m in _CN_RE.finditer(text):
            d = m.group(1).lower()
            if d not in domains:
                domains.append(d)
        return TrafficCorpus(source="compliance-cert", domains=domains, records=[{"cert_domains": domains}])

    @staticmethod
    def from_cert_dump(path: str) -> TrafficCorpus:
        """解析证书元数据文件：优先按 JSON（数组或对象列表），否则按文本解析。"""
        with open(path, "r", encoding="utf-8") as f:
            text = f.read()
        try:
            obj = json.loads(text)
        except Exception:
            return ComplianceCertSource.from_cert_text(text)
        domains: list[str] = []
        items = obj if isinstance(obj, list) else [obj]
        for item in items:
            if isinstance(item, str):
                domains.append(item.lower())
            elif isinstance(item, dict):
                for k in ("domain", "sand", "san", "cn", "host"):
                    val = item.get(k)
                    if val:
                        domains.append(str(val).lower())
        seen: set[str] = set()
        uniq: list[str] = []
        for d in domains:
            if d not in seen:
                seen.add(d)
                uniq.append(d)
        return TrafficCorpus(source="compliance-cert", domains=uniq, records=[{"cert_domains": uniq}])


__all__ = ["ProxyTrafficSource", "ComplianceCertSource"]
