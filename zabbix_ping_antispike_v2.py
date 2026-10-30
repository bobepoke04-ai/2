#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Zabbix 7.0.x 四节点 Ping 触发器防尖峰，v2.0。

默认只读预览：python3 zabbix_ping_antispike_v2.py --plan all_nodes_ping_plan.json
应用：--apply <本工具生成的计划.json>；回滚：--rollback <本工具生成的备份.json>
只依赖 Python 3.10+ 标准库，不需要 sudo。不会修改监控项、模板、邮件动作或历史数据。
固定 4 台主机 / 48 个完整键值；逐项核对截图中的关联触发器数量及双向 ID 关系。
存在未确认条件时整批停止，不提供 --force/--yes/模糊名称回退。
"""
from __future__ import annotations

import argparse
import copy
import datetime as dt
import getpass
import hashlib
import json
import math
import os
from pathlib import Path
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

VERSION = "2.0.0"
SCHEMA = "four-nodes-ping-antispike-v2"
DEFAULT_URL = "http://192.168.253.106:9000/api_jsonrpc.php"
# 技术主机名，不使用可见名称、巡检脚本中的防火墙地址或目标 IP 代替源主机。
# 每项：(目标区域, 网络, 目标IP, 延迟关联触发器数, 丢包关联触发器数)。数量来自本次截图。
SCOPE = {
    "XA-69": (
        ("北京", "内网", "192.168.1.134", 2, 2),
        ("北京", "公网", "103.118.54.42", 2, 2),
        ("上海", "内网", "192.168.5.162", 2, 2),
        ("上海", "公网", "61.169.185.146", 2, 2),
        ("IDC", "内网", "192.168.253.106", 2, 2),
        ("IDC", "公网", "1.81.5.164", 2, 2),
    ),
    "SH-162": (
        ("西安", "内网", "192.168.2.69", 2, 2),
        ("西安", "公网", "219.144.175.254", 2, 2),
        ("北京", "内网", "192.168.1.134", 2, 2),
        ("北京", "公网", "103.118.54.42", 2, 2),
        ("IDC", "内网", "192.168.253.106", 2, 2),
        ("IDC", "公网", "1.81.5.164", 2, 2),
    ),
    "Zabbix server": (
        ("西安", "内网", "192.168.2.69", 1, 1),
        ("西安", "公网", "219.144.175.254", 1, 1),
        ("北京", "内网", "192.168.1.134", 1, 1),
        ("北京", "公网", "103.118.54.42", 1, 1),
        ("上海", "内网", "192.168.5.162", 1, 1),
        ("上海", "公网", "61.169.185.146", 1, 1),
    ),
    "BJ-134": (
        ("西安", "内网", "192.168.2.69", 1, 1),
        ("西安", "公网", "219.144.175.254", 1, 1),
        ("上海", "内网", "192.168.5.162", 1, 1),
        ("上海", "公网", "61.169.185.146", 1, 1),
        ("IDC", "内网", "192.168.253.106", 1, 2),
        ("IDC", "公网", "113.200.121.196", 2, 2),
    ),
}
SOURCE_LABELS = {"XA-69": "西安", "SH-162": "上海", "Zabbix server": "IDC", "BJ-134": "北京"}
PREFIXES = ("ping.public.rtt.avg", "ping.public.loss")
WRITE_FIELDS = ("expression", "recovery_mode", "recovery_expression", "type")
ITEM_FIELDS = ["itemid", "hostid", "name", "key_", "type", "value_type", "status",
               "delay", "master_itemid", "units", "history", "trends", "interfaceid",
               "templateid", "flags", "timeout"]
TRIGGER_FIELDS = ["triggerid", "description", "expression", "recovery_mode", "recovery_expression",
                  "type", "status", "priority", "templateid", "flags", "value", "state", "error",
                  "opdata", "event_name", "comments", "url", "url_name", "correlation_mode",
                  "correlation_tag", "manual_close", "uuid"]
HOST_FIELDS = ["hostid", "host", "name", "status"]
THRESHOLD = r"(?:\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|\{\$[A-Z0-9_.]+\})"
CMP_TO_COUNT = {">=": "ge", ">": "gt", "=": "eq"}
INVERSE = {">=": "<", ">": "<=", "=": "<>"}


class SafeError(Exception):
    """拒绝不明确的操作；不自动重试配置写入。"""


def manifest() -> list[dict]:
    result = []
    for host, targets in SCOPE.items():
        for destination, network, ip, rtt_count, loss_count in targets:
            for prefix, count, metric in zip(PREFIXES, (rtt_count, loss_count), ("延迟", "丢包率")):
                result.append({"host": host, "key_": f"{prefix}[{ip}]", "target": ip,
                               "route": f"{SOURCE_LABELS[host]}到{destination}{network}{metric}",
                               "expected_triggers": count})
    return result


def validate_samples(n):
    if type(n) is not int or not 2 <= n <= 60:
        raise SafeError("--samples 必须是 2~60 的整数。")


def positive_id(value) -> str:
    s = str(value)
    if not re.fullmatch(r"[1-9]\d*", s):
        raise SafeError(f"API 返回无效对象 ID：{s!r}")
    return s


def unique(rows, key: str) -> dict:
    if not isinstance(rows, list):
        raise SafeError("API 未返回预期的对象数组。")
    out = {}
    for row in rows:
        identifier = positive_id(row[key])
        if identifier in out:
            raise SafeError(f"API 结果存在重复 {key}={identifier}，停止。")
        out[identifier] = row
    return out


def jkey(value) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def digest(value) -> str:
    return hashlib.sha256(jkey(value).encode("utf-8")).hexdigest()


def stamp() -> str:
    return dt.datetime.now().strftime("%Y%m%d_%H%M%S_%f")


def now_string() -> str:
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def dump_new(path: Path, value, *, text: bool = False):
    """独占创建、权限 0600、落盘；不覆盖旧计划/备份。"""
    data = value if text else json.dumps(value, ensure_ascii=False, indent=2) + "\n"
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as out:
        out.write(data)
        out.flush()
        os.fsync(out.fileno())
    # Linux 上刷新目录项；Windows 未提供 O_DIRECTORY 时不调用。
    if hasattr(os, "O_DIRECTORY"):
        dfd = os.open(str(path.parent), os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)


def seal(doc: dict) -> dict:
    out = copy.deepcopy(doc)
    out.pop("sha256", None)
    out["sha256"] = digest(out)
    return out


def load_doc(path: Path, kind: str | None = None) -> dict:
    with path.open(encoding="utf-8") as src:
        doc = json.load(src)
    if not isinstance(doc, dict):
        raise SafeError("计划/备份不是 JSON 对象。")
    given = doc.pop("sha256", None)
    if given != digest(doc):
        raise SafeError("文件校验失败或被改动。不要手工编辑计划/备份；重新生成预览。")
    if doc.get("schema") != SCHEMA or doc.get("tool_version") != VERSION:
        raise SafeError("不是本版本生成的文件。旧版 XA-69 计划不能用于新版脚本。")
    if doc.get("manifest") != manifest():
        raise SafeError("文件中的 48 项白名单与当前脚本不一致。")
    if kind is not None and doc.get("kind") != kind:
        raise SafeError("文件类型不正确。")
    validate_samples(doc.get("samples"))
    doc["sha256"] = given
    return doc


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise SafeError("API 发生重定向。请指定最终 api_jsonrpc.php 地址，凭据不转发。")


class API:
    def __init__(self, url: str, username: str | None = None, auth_field: bool = False):
        parsed = urllib.parse.urlsplit(url)
        if (parsed.scheme not in ("http", "https") or not parsed.hostname
                or parsed.username or parsed.password or parsed.query or parsed.fragment):
            raise SafeError("API URL 必须为不含凭据/查询参数/锚点的 http(s) 地址。")
        self.url, self.token, self.seq, self.login_session = url, "", 0, False
        self.auth_field = auth_field
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        self.version = self.call("apiinfo.version", {}, authenticated=False)
        if not re.fullmatch(r"7\.0\.\d+", str(self.version)):
            raise SafeError(f"检测到 Zabbix {self.version}；本脚本仅面向 7.0.x。")
        if parsed.scheme == "http":
            print("[NOTICE] API 使用 HTTP；仅在可信内网运行。已部署 HTTPS 时可用 --url 指定。")
        self.token = os.environ.get("ZABBIX_API_TOKEN", "").strip()
        if not self.token:
            user = username or input("Zabbix 用户名 [Admin]：").strip() or "Admin"
            password = getpass.getpass("Zabbix 密码（不显示、不写入文件）：")
            self.token = self.call("user.login", {"username": user, "password": password}, False)
            self.login_session = True

    def call(self, method: str, params, authenticated: bool = True):
        self.seq += 1
        data = {"jsonrpc": "2.0", "method": method, "params": params, "id": self.seq}
        headers = {"Content-Type": "application/json-rpc"}
        if authenticated:
            if not self.token:
                raise SafeError("认证令牌为空。")
            if self.auth_field:
                data["auth"] = self.token  # 7.0 兼容开关，不做自动认证回退。
            else:
                headers["Authorization"] = "Bearer " + self.token
        req = urllib.request.Request(self.url, json.dumps(data).encode("utf-8"), headers, method="POST")
        try:
            with self.opener.open(req, timeout=45) as response:
                raw = response.read(32 * 1024 * 1024 + 1)
            if len(raw) > 32 * 1024 * 1024:
                raise SafeError("API 响应异常过大，停止。")
            answer = json.loads(raw)
        except (urllib.error.URLError, OSError, TimeoutError, ValueError) as exc:
            raise SafeError(f"{method} 请求失败：{exc}。写请求失败不代表未生效，请核对状态/备份。") from exc
        if not isinstance(answer, dict) or answer.get("id") != self.seq:
            raise SafeError(f"{method} 返回了不匹配的 JSON-RPC 响应。")
        if "error" in answer:
            err = answer["error"]
            raise SafeError(f"{method}：{err.get('message', '')} {err.get('data', '')}")
        if "result" not in answer:
            raise SafeError(f"{method} 响应缺少 result。")
        return answer["result"]

    def close(self):
        if self.login_session:
            try:
                self.call("user.logout", [])
            except SafeError:
                print("[NOTICE] 会话退出请求未完成。", file=sys.stderr)
        self.token = ""


def paths_for(t: dict) -> list[str]:
    hosts = {x["hostid"]: x["host"] for x in t.get("hosts", [])}
    return [f"/{hosts[i['hostid']]}/{i['key_']}" for i in t.get("items", [])]


def compact(expr: str, paths: list[str] | tuple[str, ...] = ()) -> str:
    """仅去掉语法空白；保留查询路径、字符串中的空格。

    尤其不能把 /Zabbix server/key 变成 /Zabbixserver/key。
    """
    protected = sorted(set(paths), key=len, reverse=True)
    out, quoted, escaped, i = [], False, False, 0
    while i < len(expr):
        ch = expr[i]
        if quoted:
            out.append(ch)
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                quoted = False
            i += 1
            continue
        found = next((p for p in protected if expr.startswith(p, i)), None)
        if found is not None:
            out.append(found)
            i += len(found)
            continue
        if ch == '"':
            quoted = True
            out.append(ch)
        elif not ch.isspace():
            out.append(ch)
        i += 1
    if quoted:
        raise SafeError("表达式引号未闭合。")
    return "".join(out)


def expand_expression(expr: str, functions: dict[str, str]) -> tuple[str, set[str]]:
    """只展开引号外的 {functionid}；不展开用户宏或字符串中的花括号。"""
    out, used, quoted, escaped, i = [], set(), False, False, 0
    while i < len(expr):
        ch = expr[i]
        if quoted:
            out.append(ch)
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                quoted = False
            i += 1
            continue
        if ch == '"':
            quoted = True
        if ch == "{":
            m = re.match(r"\{(\d+)\}", expr[i:])
            if m:
                fid = m.group(1)
                if fid not in functions:
                    raise SafeError(f"函数 ID {fid} 未出现在 selectFunctions 中。")
                out.append(functions[fid])
                used.add(fid)
                i += len(m.group(0))
                continue
        out.append(ch)
        i += 1
    if quoted:
        raise SafeError("原表达式中存在未闭合引号。")
    return "".join(out), used


def uncompress(raw: dict) -> dict:
    t = copy.deepcopy(raw)
    items = unique(t.get("items", []), "itemid")
    hosts = unique(t.get("hosts", []), "hostid")
    fns = unique(t.get("functions", []), "functionid")
    if not fns or {f["itemid"] for f in fns.values()} != set(items):
        raise SafeError(f"triggerid={t['triggerid']} 的 functions.itemid 与 selectItems 不一致。")
    if {i["hostid"] for i in items.values()} != set(hosts):
        raise SafeError(f"triggerid={t['triggerid']} 的主机反查关系不一致。")
    expanded = {}
    for fid, fn in fns.items():
        item = items[fn["itemid"]]
        host = hosts[item["hostid"]]["host"]
        p = fn["parameter"]
        if p != "$" and not p.startswith("$,"):
            raise SafeError(f"triggerid={t['triggerid']} 存在不支持的函数参数格式。")
        if not re.fullmatch(r"[a-z_][a-z_0-9]*", fn["function"]):
            raise SafeError("函数名称格式异常。")
        expanded[fid] = f"{fn['function']}(/{host}/{item['key_']}{p[1:]})"
    used = set()
    for field in ("expression", "recovery_expression"):
        t[field], refs = expand_expression(t.get(field, ""), expanded)
        used |= refs
    if used != set(expanded):
        raise SafeError(f"triggerid={t['triggerid']} 的表达式与函数清单不完全一致。")
    return t


def get_triggers(api, **filters) -> list[dict]:
    raw = api.call("trigger.get", {"output": TRIGGER_FIELDS, "selectFunctions": "extend",
                                  "selectItems": ["itemid", "hostid", "key_"],
                                  "selectHosts": ["hostid", "host"],
                                  "selectDependencies": ["triggerid"], "selectTags": "extend", **filters})
    unique(raw, "triggerid")
    return [uncompress(t) for t in raw]


def mutable(t: dict) -> dict:
    return {field: str(t.get(field, "")) for field in WRITE_FIELDS}


def state_config(t: dict) -> dict:
    """比较配置，不用会变化的当前值/状态/函数 ID；所有身份路径保留。"""
    result = {k: copy.deepcopy(v) for k, v in t.items() if k not in {"functions", "value", "state", "error"}}
    for field in ("expression", "recovery_expression"):
        result[field] = compact(result.get(field, ""), paths_for(t))
    for field in ("items", "hosts", "dependencies", "tags"):
        result[field] = sorted(result.get(field, []), key=jkey)
    return result


def config_after(row: dict, direction: str) -> dict:
    expected = copy.deepcopy(row["config"])
    expected.update(row[direction])
    for field in ("expression", "recovery_expression"):
        expected[field] = compact(expected[field], paths_for(expected))
    return expected


def strip_outer(expr: str) -> str:
    # 仅支持完整外包围括号，不重写 AND/OR 内部结构。
    while expr.startswith("(") and expr.endswith(")"):
        depth, quoted, escaped, closed_at = 0, False, False, None
        for i, ch in enumerate(expr):
            if quoted:
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == '"':
                    quoted = False
            elif ch == '"':
                quoted = True
            elif ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    closed_at = i
                    break
        if closed_at != len(expr) - 1:
            break
        expr = expr[1:-1]
    return expr


def parse_condition(expression: str, path: str) -> tuple[str, str, dict]:
    expr = strip_outer(compact(expression, [path]))
    p = re.escape(path)
    period = r"(?:[1-9]\d*[smhdw]?|#[1-9]\d*)"
    m = re.fullmatch(rf"(avg|min|max)\({p},({period})\)(>=|>|=)({THRESHOLD})", expr)
    if m:
        return m.group(3), m.group(4), {"function": m.group(1), "period": m.group(2)}
    m = re.fullmatch(rf"last\({p}(?:,#1)?\)(>=|>|=)({THRESHOLD})", expr)
    if m:
        return m.group(1), m.group(2), {"function": "last", "period": "#1"}
    m = re.fullmatch(
        rf'count\({p},#([1-9]\d*),"(ge|gt|eq)",({THRESHOLD})\)=([1-9]\d*)'
        rf'andcount\({p},([1-9]\d*)([sm]?)\)>=([1-9]\d*)', expr)
    if m:
        n, op, threshold, eq_n, window, unit, fresh_n = m.groups()
        secs = int(window) * (60 if unit == "m" else 1)
        if n == eq_n == fresh_n and int(n) >= 2 and secs == int(n) * 60:
            return {"ge": ">=", "gt": ">", "eq": "="}[op], threshold, {
                "function": "confirmed", "period": "#" + n}
    raise SafeError("非支持的完整单项阈值：AND/OR、区间、跨项、复杂宏、时间偏移等须人工核对；不截取其中一段改写。")


def confirmation_span(meta: dict) -> int:
    period = meta["period"]
    if period.startswith("#"):
        return (int(period[1:]) - 1) * 60
    m = re.fullmatch(r"([1-9]\d*)([smhdw]?)", period)
    return int(m.group(1)) * {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}[m.group(2)]


def check_item(item: dict, master: dict | None, spec: dict, hostid: str) -> list[str]:
    errors = []
    if item.get("hostid") != hostid or item.get("key_") != spec["key_"]:
        errors.append("依赖项的主机/键值不匹配")
    if item.get("type") != "18" or item.get("value_type") not in ("0", "3"):
        errors.append("不是数值型依赖监控项")
    if item.get("status") != "0":
        errors.append("依赖项未启用")
    history = item.get("history", "")
    if not re.fullmatch(r"[1-9]\d*[smhdw]?", history):
        errors.append("历史保留时间为零或无法明确核实（含宏也需复核）")
    steps = item.get("preprocessing", [])
    if (len(steps) != 1 or steps[0].get("type") != "12"
            or steps[0].get("error_handler", "0") != "0"
            or not str(steps[0].get("params", "")).strip()):
        errors.append("依赖项不是单一 JSONPath/默认错误处理，需排除丢弃值或额外换算")
    if not master or master.get("hostid") != hostid:
        errors.append("无法唯一找到同主机的主监控项")
        return errors
    if master.get("key_") != f"ping.metrics[{spec['target']}]":
        errors.append("主监控项目标不匹配")
    if master.get("type") not in ("0", "7") or master.get("status") != "0":
        errors.append("主项不是启用的 Zabbix agent 采集项")
    if master.get("delay") not in ("1m", "60", "60s"):
        errors.append(f"主项间隔 {master.get('delay')!r} 不是已确认的固定 60 秒，含自定义间隔/宏时停止")
    if master.get("preprocessing"):
        errors.append("主项有预处理，不能确认每次正常采样都会传递给依赖项")
    return errors


def propose(t: dict, item: dict, host: str, samples: int) -> dict:
    validate_samples(samples)
    if t.get("templateid") != "0":
        raise SafeError("模板继承触发器：不修改来源模板或影响其他主机。")
    if t.get("flags") != "0":
        raise SafeError("自动发现生成/原型相关触发器：不直接改写生成对象。")
    if (len(t.get("items", [])) != 1 or t["items"][0]["itemid"] != item["itemid"]
            or len(t.get("hosts", [])) != 1 or t["hosts"][0]["host"] != host):
        raise SafeError("触发器引用多项、其他主机，或反查的 itemid 不一致。")
    if t.get("recovery_mode") == "2":
        raise SafeError("原配置不自动恢复（None）；不擅自改变关闭机制。")
    if t.get("state") not in (None, "0"):
        raise SafeError("触发器当前为计算错误状态，先排除原配置/数据异常。")
    path = f"/{host}/{item['key_']}"
    op, threshold, meta = parse_condition(t["expression"], path)
    if confirmation_span(meta) > (samples - 1) * 60:
        raise SafeError(f"原规则观察范围 {meta['period']} 大于本次确认跨度，不自动缩短；请保留原规则或明确确认次数。")
    if op == "=" and not item["key_"].startswith("ping.public.loss["):
        raise SafeError("延迟等值判断不纳入自动转换。")
    if not threshold.startswith("{") and not math.isfinite(float(threshold)):
        raise SafeError("阈值不是有限数值。")
    new = mutable(t)
    new["expression"] = (f'count({path},#{samples},"{CMP_TO_COUNT[op]}",{threshold})={samples}'
                         f' and count({path},{samples}m)>={samples}')
    new["type"] = "0"  # Single：仅改变事件生成模式，不改动作中的重复通知。
    if t.get("recovery_mode") == "0":
        new["recovery_mode"] = "1"
        new["recovery_expression"] = f"last({path}){INVERSE[op]}{threshold}"
    elif t.get("recovery_mode") != "1" or not t.get("recovery_expression"):
        raise SafeError("原恢复配置不完整，需核对。")
    return new


def scope_snapshot(doc: dict) -> dict:
    """预览与提交间的配置锁，不包含时间、问题值等运行数据。"""
    return {"manifest": doc["manifest"], "samples": doc["samples"], "url": doc["url"],
            "version": doc["version"], "hosts": doc["hosts"], "items": doc["items"],
            "masters": doc["masters"], "mapping": doc["mapping"], "blockers": doc["blockers"],
            "rows": [{k: r[k] for k in ("triggerid", "host", "itemids", "config", "status")}
                     | ({"after": r["after"]} if "after" in r else {}) for r in doc["rows"]]}


def inventory(api, samples: int) -> dict:
    validate_samples(samples)
    specs = manifest()
    hosts = api.call("host.get", {"output": HOST_FIELDS, "filter": {"host": list(SCOPE)}})
    unique(hosts, "hostid")
    if len(hosts) != 4 or {h["host"] for h in hosts} != set(SCOPE):
        raise SafeError("未唯一找到全部技术主机名 XA-69 / SH-162 / Zabbix server / BJ-134；不按显示名或 IP 自动替代。")
    hm = {h["host"]: h for h in hosts}
    host_by_id = {h["hostid"]: h for h in hosts}
    blockers, items = [], []
    for host in SCOPE:
        if hm[host]["status"] != "0":
            blockers.append(f"主机未启用：{host}")
        keys = [s["key_"] for s in specs if s["host"] == host]
        fetched = api.call("item.get", {"output": ITEM_FIELDS, "hostids": [hm[host]["hostid"]],
                                       "filter": {"key_": keys}, "selectPreprocessing": "extend",
                                       "selectTriggers": ["triggerid"]})
        for item in fetched:
            if item.get("hostid") != hm[host]["hostid"] or item.get("key_") not in keys:
                raise SafeError("API 返回范围外监控项，停止，不采用模糊结果。")
        items += fetched
    im = unique(items, "itemid")
    masters_ids = sorted({i["master_itemid"] for i in items if i.get("master_itemid") not in (None, "0")})
    masters = api.call("item.get", {"output": ITEM_FIELDS, "itemids": masters_ids,
                                   "selectPreprocessing": "extend"}) if masters_ids else []
    mm = unique(masters, "itemid")
    if set(mm) - set(masters_ids):
        raise SafeError("API 返回了未请求的主监控项。")
    # 反向查询不叠加 hostids；这样跨主机引用不会被主机过滤条件隐藏。
    triggers = get_triggers(api, itemids=sorted(im)) if im else []
    tm = unique(triggers, "triggerid")
    mapping, item_errors = [], {}
    for s in specs:
        hostid = hm[s["host"]]["hostid"]
        matches = [i for i in items if i["hostid"] == hostid and i["key_"] == s["key_"]]
        m = dict(s, hostid=hostid, itemid="", master_itemid="", actual_triggers=0, triggerids=[],
                 jsonpath="", master_key="", master_delay="", errors=[])
        if len(matches) != 1:
            m["errors"].append(f"监控项精确匹配数量为 {len(matches)}，必须为 1")
        else:
            item = matches[0]
            iid = item["itemid"]
            master = mm.get(item.get("master_itemid"))
            item_links = unique(item.get("triggers", []), "triggerid")
            reverse = {tid for tid, t in tm.items() if iid in {x["itemid"] for x in t["items"]}}
            steps = item.get("preprocessing", [])
            m.update(itemid=iid, master_itemid=item.get("master_itemid", ""),
                     triggerids=sorted(item_links, key=int), actual_triggers=len(item_links),
                     jsonpath=str(steps[0].get("params", "")) if steps else "",
                     master_key=master.get("key_", "") if master else "",
                     master_delay=master.get("delay", "") if master else "")
            m["errors"] += check_item(item, master, s, hostid)
            if len(item_links) != s["expected_triggers"]:
                m["errors"].append(f"关联数与截图不一致：预期 {s['expected_triggers']}，API 可见 {len(item_links)}")
            if set(item_links) != reverse:
                m["errors"].append("item.get.selectTriggers 与 trigger.get.selectItems 双向关联不一致")
            for tid in reverse:
                t = tm[tid]
                ref = next(x for x in t["items"] if x["itemid"] == iid)
                if ref["hostid"] != hostid or ref["key_"] != s["key_"]:
                    m["errors"].append(f"triggerid={tid} 的监控项身份反查不一致")
            item_errors[iid] = list(m["errors"])
        for error in m["errors"]:
            blockers.append(f"{s['host']} | {s['key_']}：{error}")
        mapping.append(m)
    all_link_ids = {tid for m in mapping for tid in m["triggerids"]}
    if all_link_ids != set(tm):
        blockers.append("48 项引用的 triggerid 集合与反向查询集合不一致")
    if len(items) != 48:
        blockers.append(f"只读取到 {len(items)}/48 个监控项")
    if not tm:
        blockers.append("没有读取到关联触发器")
    enabled_ids = sorted(tid for tid, t in tm.items() if t["status"] == "0")
    editable = api.call("trigger.get", {"output": ["triggerid"], "triggerids": enabled_ids,
                                        "editable": True}) if enabled_ids else []
    writable = set(unique(editable, "triggerid"))
    if writable != set(enabled_ids):
        blockers.append("API 账号不具备全部已启用目标触发器的写权限，或结果不完整")
    rows = []
    for tid, t in sorted(tm.items(), key=lambda kv: int(kv[0])):
        related = [iid for iid in (i["itemid"] for i in t["items"]) if iid in im]
        row_host = host_by_id.get(im[related[0]]["hostid"], {}).get("host", "") if related else ""
        row = {"triggerid": tid, "name": t["description"], "host": row_host, "itemids": sorted(related),
               "before": mutable(t), "config": state_config(t),
               "active_problem": t.get("value") == "1"}
        if t["status"] == "1":
            row.update(status="DISABLED", reason="原触发器已禁用，保持原状，不自动启用。")
        else:
            try:
                if t["status"] != "0" or len(related) != 1 or len(t["items"]) != 1:
                    raise SafeError("引用多项/范围外对象或状态异常，需逐条复核。")
                iid = related[0]
                if item_errors.get(iid):
                    raise SafeError("该监控项的身份、数量或采样配置校验未通过。")
                if tid not in writable:
                    raise SafeError("没有该触发器的配置写权限。")
                new = propose(t, im[iid], row_host, samples)
                row["after"] = new
                row["status"] = "UNCHANGED" if config_after(row, "after") == row["config"] else "CHANGE"
                row["reason"] = "保留原阈值/比较符；保留已有自定义恢复，无自定义恢复时用最新值回到正常侧恢复；Single。"
            except SafeError as exc:
                row.update(status="REVIEW", reason=str(exc))
        rows.append(row)
    # 子选择的返回顺序不是身份的一部分；预处理步骤顺序不能调整。
    for item in items:
        item["triggers"] = sorted(item.get("triggers", []), key=lambda x: int(x["triggerid"]))
    return {"schema": SCHEMA, "tool_version": VERSION, "kind": "plan", "created": now_string(),
            "manifest": specs, "samples": samples, "url": api.url, "version": api.version,
            "hosts": sorted(hosts, key=lambda h: h["host"]),
            "items": sorted(items, key=lambda i: int(i["itemid"])),
            "masters": sorted(masters, key=lambda i: int(i["itemid"])),
            "mapping": mapping, "blockers": blockers, "rows": rows}


def ensure_ready(doc: dict):
    if doc["blockers"] or any(r["status"] == "REVIEW" for r in doc["rows"]):
        raise SafeError("存在 BLOCK/REVIEW，整批停止，未提交任何触发器变更。请查看逐项报告。")
    if len(doc["mapping"]) != 48 or any(m["errors"] for m in doc["mapping"]):
        raise SafeError("48 项关联映射未全部通过。")


def report(doc: dict) -> str:
    rows, n = doc["rows"], doc["samples"]
    lines = ["四节点 Ping 触发器防尖峰：只读核对与修改预览", "=" * 88,
             f"生成：{doc['created']} | 工具 {VERSION} | Zabbix {doc['version']}", f"API：{doc['url']}",
             f"监控项：{len(doc['items'])}/48；截图预期关联数合计：75（不是未经核对的唯一触发器数）",
             f"API 关联数合计：{sum(m['actual_triggers'] for m in doc['mapping'])}；去重 triggerid：{len(rows)}",
             f"连续 {n} 次达到原阈值 + 最近 {n} 分钟至少 {n} 条记录；固定 1m 时首末采样约跨 {n-1} 分钟。",
             "不是逐秒连续性证明。保留邮件动作；100%丢包等简单阈值也增加确认时间。",
             "已有长观察范围不自动缩短；已有自定义恢复条件保留；None/复杂条件需人工复核。",
             "计划中的 SHA-256 仅用于发现意外改动，不是对来源真实性的数字签名。", "",
             "A. 48 个监控项逐项定位（主机名+完整键值 -> itemid -> 所有关联 triggerid）", "-" * 88]
    for index, m in enumerate(doc["mapping"], 1):
        lines += [f"[{index:02d}/48] {'BLOCK' if m['errors'] else 'MATCH'} | {m['host']} | {m['route']}",
                  f"  hostid={m['hostid']} | key={m['key_']}",
                  f"  itemid={m['itemid'] or '未唯一匹配'} | triggerids={','.join(m['triggerids']) or '无'}",
                  f"  预期/实际关联数={m['expected_triggers']}/{m['actual_triggers']}",
                  f"  master_itemid={m['master_itemid']} | master={m['master_key']} | delay={m['master_delay']}",
                  f"  依赖项 JSONPath={m['jsonpath']}"]
        lines += ["  [BLOCK] " + e for e in m["errors"]]
    lines += ["", "B. 每一个去重后的触发器及新旧表达式", "-" * 88]
    for row in rows:
        lines += [f"[{row['status']}] {row['host']} | triggerid={row['triggerid']} | itemids={','.join(row['itemids'])}",
                  f"  名称：{row['name']} | 当前：{'PROBLEM' if row['active_problem'] else 'OK'}",
                  "  原问题：" + row["before"]["expression"],
                  f"  原恢复：mode={row['before']['recovery_mode']} | {row['before']['recovery_expression']}"]
        if "after" in row:
            lines += ["  新问题：" + row["after"]["expression"],
                      f"  新恢复：mode={row['after']['recovery_mode']} | {row['after']['recovery_expression']}"]
        lines += ["  处理说明：" + row["reason"], ""]
    counts = {state: sum(r["status"] == state for r in rows) for state in ("CHANGE", "UNCHANGED", "REVIEW", "DISABLED")}
    lines += ["C. 汇总", "-" * 88, " | ".join(f"{s}={v}" for s, v in counts.items()),
              f"BLOCK={len(doc['blockers'])}"]
    lines += ["[BLOCK] " + e for e in doc["blockers"]]
    lines += ["", "只有 BLOCK=0、REVIEW=0，且逐项核对符合预期时，才进入 --apply。",
              "提交前重新读取两次（含确认输入后），发现新增/删除/修改/权限变化即停止。",
              "DISABLED 是原已禁用对象，不会被修改或启用；报告不把它们当作已优化。",
              "没有读取/修改邮件动作，也没有测试邮件投递；原动作仍决定收件人、抑制和重复通知。",
              "本文件由只读查询生成；生成报告不等于已经更新触发器。"]
    return "\n".join(lines) + "\n"


def check_plan_live(saved: dict, live: dict):
    if scope_snapshot(saved) != scope_snapshot(live):
        raise SafeError("预览之后主机/监控项/主项/触发器/权限或计划内容有变化，请生成新的预览；未提交修改。")
    ensure_ready(live)


def confirm(verb: str, rows: list[dict]):
    count = len(rows)
    active = sum(r.get("active_problem", False) for r in rows)
    print(f"即将 {verb} {count} 个现有触发器；当前 PROBLEM {active} 个。")
    print("修改会影响后续问题/恢复判断，原动作可能发送恢复通知；不会清除历史或撤回已发邮件。")
    phrase = f"{verb} {count}"
    if input(f"输入 {phrase} 确认（其他输入取消）：").strip() != phrase:
        raise SafeError("已取消，没有提交配置。")


def perform(api, rows: list[dict], evidence_base: Path, *, reverse: bool = False):
    """一次批量请求，不逐条试错；即使响应失败也不盲目重试。"""
    direction = "before" if reverse else "after"
    expected = {r["triggerid"]: config_after(r, direction) for r in rows}
    payload = [{"triggerid": r["triggerid"], **{k: r[direction][k] for k in WRITE_FIELDS}} for r in rows]
    request_error = None
    try:
        result = api.call("trigger.update", payload)
        if (not isinstance(result, dict) or not isinstance(result.get("triggerids"), list)
                or len(result["triggerids"]) != len(expected) or set(result["triggerids"]) != set(expected)):
            raise SafeError("更新响应中的 triggerid 集合/数量不一致。")
    except (SafeError, OSError, ValueError) as exc:
        request_error = str(exc)
    actual, verify_error = {}, None
    try:
        actual = {t["triggerid"]: state_config(t) for t in get_triggers(api, triggerids=sorted(expected))}
    except (SafeError, OSError, ValueError) as exc:
        verify_error = str(exc)
    bad = [tid for tid in expected if actual.get(tid) != expected[tid]]
    evidence = {"kind": "post_write_readback", "created": now_string(), "url": api.url,
                "direction": "rollback" if reverse else "apply", "request_error": request_error,
                "verification_error": verify_error, "expected_ids": sorted(expected),
                "mismatched_or_unreadable_ids": bad, "actual_configs": actual}
    result_path = evidence_base.with_name(evidence_base.stem + ".result_" + stamp() + ".json")
    dump_new(result_path, evidence)
    print("[READBACK REPORT] " + str(result_path.resolve()))
    if request_error or verify_error or bad:
        raise SafeError("写请求或写后核验未完整通过。状态可能已部分或全部生效；已保留备份和读回报告。不要盲目重跑 apply，先核对或用本备份执行 --rollback。")
    print(f"[VERIFIED] 已{'回滚' if reverse else '修改'}并逐条核验 {len(rows)} 个触发器；身份及其他已读取配置字段保持一致。")


def apply(api, path: Path):
    saved = load_doc(path, "plan")
    if saved["url"] != api.url or saved["version"] != api.version:
        raise SafeError("计划的 API 地址或 Zabbix 版本与当前连接不一致。")
    live = inventory(api, saved["samples"])
    check_plan_live(saved, live)
    rows = [r for r in live["rows"] if r["status"] == "CHANGE"]
    if not rows:
        print("[NO CHANGE] 目标触发器已符合所选规则；没有提交写入。")
        return
    confirm("APPLY", rows)
    # 用户审阅/输入确认期间也可能有人改配置；确认后必须再次读回。
    final_live = inventory(api, saved["samples"])
    check_plan_live(saved, final_live)
    rows = [r for r in final_live["rows"] if r["status"] == "CHANGE"]
    backup = path.with_name(path.stem + ".backup_" + stamp() + ".json")
    doc = {"schema": SCHEMA, "tool_version": VERSION, "kind": "backup", "created": now_string(),
           "manifest": manifest(), "url": api.url, "version": api.version, "samples": saved["samples"],
           "rows": rows, "hosts": final_live["hosts"], "items": final_live["items"], "masters": final_live["masters"]}
    dump_new(backup, seal(doc))
    print("[BACKUP] " + str(backup.resolve()), flush=True)
    perform(api, rows, backup)


def rollback_rows(api, doc: dict) -> list[dict]:
    rows = doc.get("rows", [])
    if not rows:
        raise SafeError("备份没有变更条目。")
    unique(rows, "triggerid")
    # 不以当前筛选结果扩大回滚范围；仅使用本备份的 triggerid，并反查其全部引用。
    actual = {t["triggerid"]: t for t in get_triggers(api, triggerids=[r["triggerid"] for r in rows])}
    if set(actual) != {r["triggerid"] for r in rows}:
        raise SafeError("部分备份触发器已删除或不可见，停止整个回滚。")
    hosts = api.call("host.get", {"output": HOST_FIELDS, "filter": {"host": list(SCOPE)}})
    if sorted(hosts, key=lambda h: h["host"]) != doc["hosts"]:
        raise SafeError("源主机身份/配置发生变化，停止回滚。")
    # 主项或依赖项之后有改动时，不把旧表达式直接套用到新采集定义。
    for field in ("items", "masters"):
        saved = [{k: v for k, v in x.items() if k != "triggers"} for x in doc[field]]
        current = api.call("item.get", {"output": ITEM_FIELDS, "itemids": [x["itemid"] for x in saved],
                                        "selectPreprocessing": "extend"})
        if sorted(saved, key=lambda x: int(x["itemid"])) != sorted(current, key=lambda x: int(x["itemid"])):
            raise SafeError("监控项/主项配置在应用后已变化；停止回滚，避免旧规则套用到新采集定义。")
    allowed = {(s["host"], s["key_"]) for s in manifest()}
    restore = []
    for row in rows:
        if set(row["before"]) != set(WRITE_FIELDS) or set(row["after"]) != set(WRITE_FIELDS):
            raise SafeError("备份中包含不允许的写入字段。")
        config = row["config"]
        if len(config.get("hosts", [])) != 1 or len(config.get("items", [])) != 1:
            raise SafeError("备份中的触发器不是单主机/单监控项。")
        host, item = config["hosts"][0], config["items"][0]
        if (host["host"], item["key_"]) not in allowed or item["hostid"] != host["hostid"]:
            raise SafeError("备份中的主机/监控项不在 48 项白名单内。")
        if row["triggerid"] != config["triggerid"] or row["itemids"] != [item["itemid"]]:
            raise SafeError("备份中的 triggerid/itemid 绑定关系异常。")
        if config_after(row, "before") != config:
            raise SafeError("备份中 before 与原配置不一致。")
        # 再根据原表达式重新生成 after，备份不是任意表达式的写入入口。
        original = copy.deepcopy(config)
        original.update(row["before"])
        original.update(state="0", value="0")
        candidate = propose(original, item, host["host"], doc["samples"])
        check = copy.deepcopy(row)
        check["after"] = candidate
        if config_after(check, "after") != config_after(row, "after"):
            raise SafeError("备份中的 after 不能由原配置安全重新推导。")
        t = actual[row["triggerid"]]
        current = state_config(t)
        if current == config:
            continue
        if current != config_after(row, "after"):
            raise SafeError(f"triggerid={row['triggerid']} 存在之后的人工配置变化，拒绝覆盖；未提交回滚。")
        restore.append(dict(row, active_problem=t.get("value") == "1"))
    return restore


def rollback(api, path: Path):
    doc = load_doc(path, "backup")
    if doc["url"] != api.url or doc["version"] != api.version:
        raise SafeError("备份的 API 地址或版本与当前连接不一致。")
    rows = rollback_rows(api, doc)
    if not rows:
        print("[ALREADY ORIGINAL] 备份中的触发器都处于原始配置，不需要回滚。")
        return
    confirm("ROLLBACK", rows)
    checked = rollback_rows(api, doc)
    if {r["triggerid"] for r in checked} != {r["triggerid"] for r in rows}:
        raise SafeError("输入确认期间状态发生变化，请重新核对。")
    journal = path.with_name(path.stem + ".rollback_" + stamp() + ".json")
    dump_new(journal, {"kind": "rollback_intent", "created": now_string(), "source_backup": str(path),
                       "triggerids": [r["triggerid"] for r in checked]})
    perform(api, checked, journal, reverse=True)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    group = p.add_mutually_exclusive_group()
    group.add_argument("--apply", type=Path, help="应用本版本生成并人工核对的 plan.json")
    group.add_argument("--rollback", type=Path, help="回滚本版本生成的 backup.json")
    p.add_argument("--plan", type=Path, default=Path("all_nodes_ping_plan.json"), help="默认只读预览文件")
    p.add_argument("--samples", type=int, default=2, help="连续确认采样次数，默认2；固定1m时3次约跨2分钟")
    p.add_argument("--url", help="API URL；apply/rollback 默认读取所选文件中的同一 URL")
    p.add_argument("--username", help="Zabbix 用户名；密码通过交互输入")
    p.add_argument("--auth-field", action="store_true", help="仅供 7.0 反向代理不传 Bearer 时显式使用 auth 字段")
    p.add_argument("--version", action="version", version=VERSION)
    args = p.parse_args()
    os.umask(0o077)
    api = None
    try:
        validate_samples(args.samples)
        source = args.apply or args.rollback
        doc = load_doc(source, "plan" if args.apply else "backup") if source else None
        url = args.url or (doc["url"] if doc else DEFAULT_URL)
        if not source:
            if args.plan.suffix.lower() != ".json" or not args.plan.parent.is_dir():
                raise SafeError("--plan 请使用已存在目录下的 .json 文件路径。")
            if args.plan.exists() or args.plan.with_suffix(".txt").exists():
                raise SafeError("计划/报告文件已存在，请换新文件名，不覆盖旧计划和备份。")
        api = API(url, args.username, args.auth_field)
        if args.apply:
            apply(api, args.apply)
        elif args.rollback:
            rollback(api, args.rollback)
        else:
            plan = inventory(api, args.samples)
            text = report(plan)
            dump_new(args.plan, seal(plan))
            dump_new(args.plan.with_suffix(".txt"), text, text=True)
            print(text)
            print("[PREVIEW ONLY] 未修改触发器、监控项、历史数据或邮件动作。")
            print("计划：" + str(args.plan.resolve()))
            print("报告：" + str(args.plan.with_suffix(".txt").resolve()))
            if plan["blockers"] or any(r["status"] == "REVIEW" for r in plan["rows"]):
                print("[STOP BEFORE APPLY] 有待核对项；已保存完整报告。")
                return 2
        return 0
    except (SafeError, OSError, ValueError, KeyError, TypeError) as exc:
        print("[STOP] " + str(exc), file=sys.stderr)
        return 1
    except (KeyboardInterrupt, EOFError):
        print("\n已中断。已开始写入时请先检查 BACKUP 和服务器状态，不要直接重试。", file=sys.stderr)
        return 130
    finally:
        if api is not None:
            api.close()


if __name__ == "__main__":
    sys.exit(main())
