#!/usr/bin/env python3
"""盾山 · 访问日志分诊（只用标准库，Python 3.8+）。

自动识别两种格式：IIS W3C 日志（带 #Fields 头，时间是 UTC）、nginx / Apache combined 日志。
回答被攻击后最先要回答的几个问题：谁在打、打哪里、打了多少、用什么工具、什么时候开始；
以及定限速阈值前必须先看的：按某个阈值拦，会误伤多少正常来源。

用法（日志是不可信数据，用隔离模式跑）：
  python -I -X utf8 log_triage.py <日志文件或通配符> [...] [选项]

选项：
  --attack 1.2.3.4,5.6.7.8   已知攻击 IP：单列明细，并从误伤统计里排除
  --office 9.9.9.9           自己人的出口 IP（办公室等）：单独报高峰，判断阈值会不会拦到自己
  --top 15                   各榜单显示条数
  --detail 3                 没给 --attack 时，自动展开明细的可疑 IP 个数
  --simulate 300/10,100/10   模拟"N 次 / M 秒"限速（被拒的请求不计数，与 IIS 动态 IP 限制实测语义一致）
  --tz 8                     显示用时区（小时）。IIS 日志原始是 UTC，默认按北京时间显示
"""
import argparse
import collections
import datetime as dt
import glob
import re
import sys

SENSITIVE = re.compile(
    r"(\.git/|\.svn/|\.env\b|\.ds_store|web\.config|appsettings|\.bak$|\.old$|\.sql$|\.zip$|\.tar|\.rar$|"
    r"phpmyadmin|/wp-|xmlrpc\.php|/admin\.php|elmah\.axd|trace\.axd|/actuator|/server-status|"
    r"\.map$|/bin/|app_data|/swagger|/console|/manager/html|/etc/passwd|\.\./|%2e%2e|/cgi-bin/|\.php$|\.jsp$|~1)",
    re.I)
TOOL_UA = re.compile(
    r"(curl|wget|python-requests|python-urllib|aiohttp|httpx|go-http-client|java/|okhttp|libwww|"
    r"sqlmap|nikto|nuclei|masscan|zgrab|nmap|dirbuster|gobuster|feroxbuster|ffuf|fuzz faster u fool|wfuzz|"
    r"whatweb|wpscan|commix|hydra|recon|probe|scanner)",
    re.I)
# 带外回连域名：参数里出现说明对方在测 SSRF、命令注入、盲 XSS（nuclei 默认的 interactsh 服务器等）
OAST = re.compile(r"(oast\.(pro|live|site|online|fun|me)|interact\.sh|dnslog|burpcollaborator|ceye\.io|requestbin|pipedream\.net)", re.I)
AUTH_PATH = re.compile(r"(login|logon|signin|register|signup|password|passwd|forgot|reset|sms|captcha|verify|otp|token)", re.I)
COMBINED = re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+)[^"]*" (\d{3}) \S+(?: "[^"]*" "([^"]*)")?')
WINDOWS = (1, 10, 60)


class IpStat:
    __slots__ = ("total", "first", "last", "secs", "paths", "uas", "sensitive", "tool", "auth", "oast", "notfound", "hours")

    def __init__(self):
        self.total = 0
        self.first = None
        self.last = None
        self.secs = collections.Counter()
        self.paths = collections.defaultdict(collections.Counter)
        self.uas = collections.Counter()
        self.sensitive = 0
        self.tool = 0
        self.auth = 0
        self.oast = 0
        self.notfound = 0
        self.hours = collections.Counter()


def parse_w3c(path):
    idx = None
    day_epoch = {}
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            if line.startswith("#"):
                if line.startswith("#Fields:"):
                    idx = {n: i for i, n in enumerate(line.split()[1:])}
                continue
            if idx is None:
                continue
            p = line.rstrip("\n").split(" ")
            if len(p) < len(idx):
                continue
            try:
                d = p[idx["date"]]
                if d not in day_epoch:
                    day_epoch[d] = int(dt.datetime.strptime(d, "%Y-%m-%d").replace(tzinfo=dt.timezone.utc).timestamp())
                h, m, s = p[idx["time"]].split(":")
                ts = day_epoch[d] + int(h) * 3600 + int(m) * 60 + int(s)
            except (KeyError, ValueError):
                continue
            status = p[idx["sc-status"]] if "sc-status" in idx else "-"
            sub = p[idx["sc-substatus"]] if "sc-substatus" in idx else "0"
            if sub not in ("0", "-"):
                status += "." + sub
            method = p[idx["cs-method"]] if "cs-method" in idx else "-"
            ua = p[idx["cs(User-Agent)"]] if "cs(User-Agent)" in idx else "-"
            query = p[idx["cs-uri-query"]] if "cs-uri-query" in idx else ""
            yield ts, p[idx["c-ip"]], method, p[idx["cs-uri-stem"]], query, status, ua.replace("+", " ")


def parse_combined(path):
    cache = {}
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            mt = COMBINED.match(line)
            if not mt:
                continue
            raw = mt.group(2)
            ts = cache.get(raw)
            if ts is None:
                try:
                    ts = int(dt.datetime.strptime(raw, "%d/%b/%Y:%H:%M:%S %z").timestamp())
                except ValueError:
                    continue
                if len(cache) > 200000:
                    cache.clear()
                cache[raw] = ts
            uri, _, query = mt.group(4).partition("?")
            yield ts, mt.group(1), mt.group(3), uri, query, mt.group(5), mt.group(6) or "-"


def detect(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        for _ in range(20):
            line = f.readline()
            if not line:
                break
            if line.startswith("#Software") or line.startswith("#Fields"):
                return parse_w3c
            if COMBINED.match(line):
                return parse_combined
    return None


def peaks(sec_counts):
    secs = sorted(sec_counts)
    out = {}
    for w in WINDOWS:
        best = total = lo = 0
        for s in secs:
            total += sec_counts[s]
            while secs[lo] <= s - w:
                total -= sec_counts[secs[lo]]
                lo += 1
            best = max(best, total)
        out[w] = best
    return out


def simulate(sec_counts, limit, window):
    allowed_q = collections.deque()
    allowed = blocked = 0
    for s in sorted(sec_counts):
        for _ in range(sec_counts[s]):
            while allowed_q and allowed_q[0] <= s - window:
                allowed_q.popleft()
            if len(allowed_q) < limit:
                allowed_q.append(s)
                allowed += 1
            else:
                blocked += 1
    return allowed, blocked


def main():
    ap = argparse.ArgumentParser(add_help=True)
    ap.add_argument("logs", nargs="+")
    ap.add_argument("--attack", default="")
    ap.add_argument("--office", default="")
    ap.add_argument("--top", type=int, default=15)
    ap.add_argument("--detail", type=int, default=3)
    ap.add_argument("--simulate", default="300/10,100/10")
    ap.add_argument("--tz", type=float, default=8)
    a = ap.parse_args()

    tz = dt.timezone(dt.timedelta(hours=a.tz))
    fmt_t = lambda ts: dt.datetime.fromtimestamp(ts, tz).strftime("%m-%d %H:%M:%S")
    attack = {x.strip() for x in a.attack.split(",") if x.strip()}
    office = {x.strip() for x in a.office.split(",") if x.strip()}

    files = sorted({p for pat in a.logs for p in glob.glob(pat)})
    if not files:
        sys.exit("没找到日志文件")

    stats = collections.defaultdict(IpStat)
    n = 0
    for path in files:
        parser = detect(path)
        if parser is None:
            print(f"[跳过] 无法识别格式：{path}")
            continue
        for ts, ip, method, uri, query, status, ua in parser(path):
            st = stats[ip]
            st.total += 1
            st.first = ts if st.first is None or ts < st.first else st.first
            st.last = ts if st.last is None or ts > st.last else st.last
            st.secs[ts] += 1
            st.paths[f"{method} {uri}"][status] += 1
            st.uas[ua[:90]] += 1
            st.hours[fmt_t(ts)[:8]] += 1
            if SENSITIVE.search(uri):
                st.sensitive += 1
            if TOOL_UA.search(ua):
                st.tool += 1
            if AUTH_PATH.search(uri):
                st.auth += 1
            if OAST.search(uri) or OAST.search(query):
                st.oast += 1
            if status.startswith("404"):
                st.notfound += 1
            n += 1

    if not stats:
        sys.exit("日志里没有可解析的请求行")

    pk = {ip: peaks(st.secs) for ip, st in stats.items()}
    first = min(st.first for st in stats.values())
    last = max(st.last for st in stats.values())

    def row(ip):
        st, p = stats[ip], pk[ip]
        tag = "[攻击]" if ip in attack else "[自己人]" if ip in office else ""
        return (f"{ip:<39} 总{st.total:>7}  {fmt_t(st.first)}~{fmt_t(st.last)}  "
                f"峰值1s/10s/60s={p[1]}/{p[10]}/{p[60]}  路径{len(st.paths)} 404:{st.notfound} "
                f"敏感{st.sensitive} 工具UA{st.tool} 认证{st.auth} 回连{st.oast} {tag}")

    print(f"== 概览 ==\n文件 {len(files)} 个，请求 {n} 条，独立来源 {len(stats)} 个，"
          f"时间 {fmt_t(first)} ~ {fmt_t(last)}（UTC{a.tz:+g} 显示）")
    print("提示：返回 200 不等于业务成功，很多接口失败也回 200，要结合响应体大小或业务库核对。\n")

    print(f"== 请求量前 {a.top} 的来源 ==")
    for ip in sorted(stats, key=lambda i: -stats[i].total)[:a.top]:
        print(row(ip))

    def suspicious(ip):
        st, p = stats[ip], pk[ip]
        return (st.sensitive >= 3 or (st.total >= 50 and st.tool * 2 >= st.total)
                or st.auth >= 100 or p[10] >= 100 or st.oast > 0
                or (len(st.paths) >= 200 and st.notfound * 2 >= st.total))

    sus = sorted((ip for ip in stats if ip not in office and suspicious(ip)), key=lambda i: -stats[i].total)
    print(f"\n== 可疑来源（敏感路径≥3 / 工具UA过半 / 认证类≥100 / 10 秒峰值≥100 / 带外回连 / 大量路径且 404 过半），共 {len(sus)} 个 ==")
    for ip in sus[:a.top]:
        print(row(ip))

    detail = [ip for ip in attack if ip in stats] or sus[:a.detail]
    for ip in detail:
        st = stats[ip]
        print(f"\n== 明细 {ip}（总 {st.total}，不同路径 {len(st.paths)} 个）==")
        print("  -- 路径前 20（状态码分布）--")
        for path, cnt in sorted(st.paths.items(), key=lambda kv: -sum(kv[1].values()))[:20]:
            dist = ",".join(f"{k}x{v}" for k, v in cnt.most_common(4))
            print(f"  {sum(cnt.values()):>7}  {path[:90]}  [{dist}]")
        print("  -- User-Agent 前 6 --")
        for ua, c in st.uas.most_common(6):
            print(f"  {c:>7}  {ua}")
        print("  -- 按小时 --")
        for h in sorted(st.hours):
            print(f"  {h}时  {st.hours[h]}")

    # 没给攻击名单时，把强信号（扫敏感文件、刷认证接口、10 秒破百）的来源当攻击方排除，工具 UA 单独不算
    strong = set(attack) if attack else {
        ip for ip in stats
        if stats[ip].sensitive >= 3 or stats[ip].auth >= 100 or pk[ip][10] >= 100 or stats[ip].oast > 0}
    normal = [ip for ip in stats if ip not in strong and not ip.startswith(("127.", "::1"))]
    print(f"\n== 限速阈值误伤评估（排除{'攻击名单' if attack else '强可疑来源'}与本机，共 {len(normal)} 个来源）==")
    for w, ths in ((10, (50, 100, 150, 200, 300)), (60, (100, 200, 300, 500, 800))):
        print(f"  {w} 秒窗口超过阈值的来源数：" + "，".join(f">{t}: {sum(1 for ip in normal if pk[ip][w] > t)}" for t in ths))
    print(f"  10 秒峰值最高的正常来源：")
    for ip in sorted(normal, key=lambda i: -pk[i][10])[:8]:
        print("   " + row(ip))
    for ip in sorted(office):
        if ip in stats:
            print(f"  自己人 {ip}：10 秒峰值 {pk[ip][10]}，60 秒峰值 {pk[ip][60]}")

    targets = [ip for ip in attack if ip in stats] or sus[:a.detail]
    plans = []
    for item in a.simulate.split(","):
        if "/" in item:
            lim, win = item.split("/")
            plans.append((int(lim), int(win)))
    if targets and plans:
        print("\n== 限速模拟（被拒的请求不计数：它是限速，不是封禁）==")
        for ip in targets + [ip for ip in office if ip in stats]:
            for lim, win in plans:
                ok, blocked = simulate(stats[ip].secs, lim, win)
                total = stats[ip].total
                print(f"  {ip:<39} {lim}次/{win}秒：总 {total:>7}  放行 {ok:>7}  拦下 {blocked:>7}（{blocked * 100 // max(1, total)}%）")


if __name__ == "__main__":
    main()
