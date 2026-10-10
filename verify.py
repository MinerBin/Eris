#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
edgetunnel 重部署后的验证脚本
=============================
在绑定好 discordia.terminator-sky.net 之后跑这个脚本，逐项确认是否恢复。

用法:
    python verify.py                 # 用默认值
    python verify.py --domain 你的域名   # 换域名
    python verify.py --uuid 你的UUID     # 指定期望的 UUID

依赖: 只用标准库, 不需要 pip install。
"""

import argparse
import json
import re
import socket
import ssl
import sys
import urllib.error
import urllib.request

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

DEFAULT_DOMAIN = "discordia.terminator-sky.net"
DEFAULT_SUB_URL = "https://minerbin.github.io/Eris/sub.txt"
DOH_URL = "https://doh.pub/dns-query?name={}&type=A"
UA = "Mozilla/5.0 (verify.py)"

PASS, FAIL, WARN, INFO = "[PASS]", "[FAIL]", "[WARN]", "[INFO]"
results = []


def record(ok, title, detail=""):
    tag = PASS if ok is True else (FAIL if ok is False else WARN)
    results.append((tag, title, detail))
    print("  %s %s" % (tag, title))
    if detail:
        for line in str(detail).splitlines():
            print("         " + line)


def http(url, timeout=20, method="GET"):
    """返回 (status, body_bytes, headers_dict)；失败返回 (None, 错误说明, {})。"""
    req = urllib.request.Request(url, method=method, headers={"User-Agent": UA})
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, r.read(200000), dict(r.headers)
    except urllib.error.HTTPError as e:
        try:
            body = e.read(200000)
        except Exception:
            body = b""
        return e.code, body, dict(e.headers)
    except Exception as e:
        return None, "%s: %s" % (type(e).__name__, e), {}


def check_dns(domain):
    """先用 DoH 查（绕开本机 DNS），再退回系统解析。"""
    url = DOH_URL.format(domain)
    st, body, _ = http(url, timeout=15)
    if st == 200 and isinstance(body, bytes):
        try:
            d = json.loads(body.decode("utf-8", "replace"))
            status = d.get("Status")
            answers = [a.get("data") for a in (d.get("Answer") or [])]
            if status == 3:
                record(False, "DNS 解析 %s" % domain,
                       "DoH 返回 NXDOMAIN(Status=3) —— 域名还没有 DNS 记录")
                return False
            if status == 0 and answers:
                record(True, "DNS 解析 %s" % domain, "DoH: " + ", ".join(answers[:4]))
                return True
            record(None, "DNS 解析 %s" % domain, "DoH Status=%s answers=%s" % (status, answers))
            return None
        except Exception as e:
            record(None, "DNS 解析 %s" % domain, "DoH 响应解析失败: %s" % e)
    else:
        record(None, "DNS 解析 %s" % domain, "DoH 不可达(HTTP %s)，改用系统解析" % st)

    try:
        infos = socket.getaddrinfo(domain, 443, proto=socket.IPPROTO_TCP)
        ips = sorted({i[4][0] for i in infos})
        record(True, "DNS 解析 %s (系统)" % domain, ", ".join(ips[:4]))
        return True
    except Exception as e:
        record(False, "DNS 解析 %s (系统)" % domain, str(e))
        return False


def check_https(domain):
    """核心检查：不再返回 530 / 1016。"""
    for path, label in (("/", "根路径"), ("/admin", "管理后台")):
        url = "https://%s%s" % (domain, path)
        st, body, _ = http(url, timeout=25)
        if st is None:
            record(False, "HTTPS %s (%s)" % (url, label), body)
            continue
        text = body.decode("utf-8", "replace") if isinstance(body, bytes) else str(body)
        if st == 530 or "error code: 1016" in text:
            record(False, "HTTPS %s (%s)" % (url, label),
                   "仍然返回 530 / error code: 1016 —— 回源 DNS 还是找不到。\n"
                   "检查: Worker → 设置 → 域和路由 → 自定义域 里有没有绑上 %s" % domain)
            continue
        if st in (200, 302, 401, 403):
            title = ""
            m = re.search(r"<title>([^<]{0,60})</title>", text, re.I)
            if m:
                title = " <title>%s</title>" % m.group(1)
            record(True, "HTTPS %s (%s)" % (url, label),
                   "HTTP %s, %d B%s" % (st, len(text.encode("utf-8")), title))
        else:
            record(None, "HTTPS %s (%s)" % (url, label), "HTTP %s, %d B" % (st, len(text)))


def check_sub(sub_url, domain, expect_uuid):
    """检查线上 sub.txt 与 Worker 的域名/UUID 是否一致。"""
    st, body, _ = http(sub_url, timeout=25)
    if st != 200 or not isinstance(body, bytes):
        record(None, "线上 sub.txt", "拉取失败: HTTP %s" % st)
        return
    text = body.decode("utf-8", "replace")
    links = re.findall(r"vless://([0-9a-fA-F-]+)@([^:]+):(\d+)\?", text)
    if not links:
        record(False, "线上 sub.txt", "没解析到 vless:// 链接")
        return
    uuids = sorted({u.lower() for u, _, _ in links})
    hosts = sorted({h for _, h, _ in links})
    record(True, "线上 sub.txt", "%d 条链接" % len(links))

    if hosts == [domain]:
        record(True, "sub.txt 里的域名", "全部指向 %s" % domain)
    else:
        record(False, "sub.txt 里的域名", "实际是: %s\n期望: %s" % (", ".join(hosts), domain))

    if expect_uuid:
        if uuids == [expect_uuid.lower()]:
            record(True, "sub.txt 里的 UUID", expect_uuid)
        else:
            record(False, "sub.txt 里的 UUID",
                   "实际是 %s\n期望 %s\n→ 要么改 Worker 的 UUID 变量, "
                   "要么设仓库 Secret EDT_UUID 并取消 check.yml 里那行注释" % (", ".join(uuids), expect_uuid))
    else:
        record(None, "sub.txt 里的 UUID", ", ".join(uuids) + "（未指定期望值，请自行核对 Worker 的 UUID 变量）")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--domain", default=DEFAULT_DOMAIN)
    ap.add_argument("--sub", default=DEFAULT_SUB_URL)
    ap.add_argument("--uuid", default="", help="期望的 UUID；不填则只打印实际值")
    args = ap.parse_args()

    print("=" * 74)
    print(" edgetunnel 重部署验证")
    print(" 域名: %s" % args.domain)
    print("=" * 74)
    print()

    print("[1/3] DNS")
    check_dns(args.domain)
    print()
    print("[2/3] HTTPS 可达性")
    check_https(args.domain)
    print()
    print("[3/3] 线上 sub.txt 一致性")
    check_sub(args.sub, args.domain, args.uuid)
    print()

    print("=" * 74)
    n_pass = sum(1 for t, _, _ in results if t == PASS)
    n_fail = sum(1 for t, _, _ in results if t == FAIL)
    n_warn = sum(1 for t, _, _ in results if t == WARN)
    print(" 汇总: %d 通过 / %d 失败 / %d 待确认" % (n_pass, n_fail, n_warn))
    if n_fail:
        print()
        print(" 需要处理的项:")
        for tag, title, _ in results:
            if tag == FAIL:
                print("   - " + title)
    else:
        print(" 没有发现硬性失败项。")
    print("=" * 74)
    return 1 if n_fail else 0


if __name__ == "__main__":
    sys.exit(main())
