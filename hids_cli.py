#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
轻量级主机入侵检测与日志分析系统（Mini-HIDS）
版本：v1.1
功能：CLI 命令行工具，专供 Agent 调用
定位：控制面 / Agent 专属调用接口，无阻塞、无死循环，执行完立刻返回标准 JSON 字符串
"""

import argparse
import json
import os
import time

from hids_common import (
    FirewallManager,
    delete_blacklist_entry,
    detect_firewall,
    init_db,
    list_blacklist_rows,
    load_config,
    purge_expired_blacklist_entries,
    upsert_blacklist_entry,
    validate_ip,
)


CONFIG = load_config()
FIREWALL = FirewallManager()


def ensure_runtime():
    init_db(CONFIG["BLACKLIST_DB"])
    purge_expired_blacklist_entries(CONFIG["BLACKLIST_DB"])


def ban_ip(ip, reason):
    if not validate_ip(ip):
        return {"success": False, "message": f"无效的 IP 地址: {ip}"}

    if ip in CONFIG["TRUSTED_IPS"]:
        return {"success": False, "message": f"IP {ip} 在白名单中，拒绝封禁"}

    current_blacklist = {row[0]: row[1] for row in list_blacklist_rows(CONFIG["BLACKLIST_DB"])}
    if current_blacklist.get(ip, 0) > int(time.time()):
        return {"success": True, "message": f"IP {ip} 已在黑名单中"}

    expiry_time = int(time.time() + CONFIG["BAN_TIME"])
    try:
        FIREWALL.ban_ip(ip, CONFIG["BAN_TIME"])
        upsert_blacklist_entry(CONFIG["BLACKLIST_DB"], ip, expiry_time, reason)
    except Exception as exc:
        try:
            FIREWALL.unban_ip(ip)
        except Exception:
            pass
        return {"success": False, "message": f"封禁失败: {exc}"}

    return {
        "success": True,
        "message": f"IP {ip} 已成功封禁，原因: {reason}",
        "data": {"expiry_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(expiry_time))},
    }


def unban_ip(ip):
    if not validate_ip(ip):
        return {"success": False, "message": f"无效的 IP 地址: {ip}"}

    current_blacklist = {row[0]: row[1] for row in list_blacklist_rows(CONFIG["BLACKLIST_DB"])}
    if ip not in current_blacklist:
        delete_blacklist_entry(CONFIG["BLACKLIST_DB"], ip)
        return {"success": True, "message": f"IP {ip} 当前不在黑名单中"}

    try:
        FIREWALL.unban_ip(ip)
        delete_blacklist_entry(CONFIG["BLACKLIST_DB"], ip)
    except Exception as exc:
        return {"success": False, "message": f"解封失败: {exc}"}

    return {"success": True, "message": f"IP {ip} 已成功解封"}


def get_status():
    is_running = False
    pid = None

    if os.path.exists(CONFIG["PID_FILE"]):
        try:
            with open(CONFIG["PID_FILE"], "r", encoding="utf-8") as pid_file:
                pid = int(pid_file.read().strip())
            os.kill(pid, 0)
            is_running = True
        except Exception:
            pid = None

    load_avg = ""
    try:
        with open("/proc/loadavg", "r", encoding="utf-8") as load_file:
            load_avg = load_file.read().strip()
    except Exception:
        pass

    return {
        "success": True,
        "data": {
            "is_running": is_running,
            "pid": pid,
            "load_avg": load_avg,
            "firewall_backend": detect_firewall(),
            "blacklist_db": CONFIG["BLACKLIST_DB"],
            "alert_log": CONFIG["ALERT_LOG"],
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        },
    }


def get_alerts(lines=10):
    if lines <= 0:
        return {"success": False, "message": "lines 必须大于 0"}

    alerts = []
    try:
        if os.path.exists(CONFIG["ALERT_LOG"]):
            with open(CONFIG["ALERT_LOG"], "r", encoding="utf-8", errors="ignore") as alert_file:
                recent_lines = alert_file.readlines()[-lines:]
            alerts = [line.strip() for line in recent_lines if line.strip()]
    except Exception as exc:
        return {"success": False, "message": f"读取告警日志失败: {exc}"}

    return {
        "success": True,
        "data": {
            "alerts": alerts,
            "count": len(alerts),
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        },
    }


def get_blacklist():
    current_time = int(time.time())
    blacklist = []

    try:
        for ip, ban_time, reason in list_blacklist_rows(CONFIG["BLACKLIST_DB"]):
            if ban_time <= current_time:
                continue
            blacklist.append(
                {
                    "ip": ip,
                    "ban_time": ban_time,
                    "expiry_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ban_time)),
                    "reason": reason,
                    "time_remaining": ban_time - current_time,
                }
            )
    except Exception as exc:
        return {"success": False, "message": f"读取黑名单失败: {exc}"}

    return {
        "success": True,
        "data": {
            "blacklist": blacklist,
            "count": len(blacklist),
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        },
    }


def main():
    ensure_runtime()

    parser = argparse.ArgumentParser(description="Mini-HIDS CLI 工具")
    parser.add_argument(
        "--action",
        type=str,
        required=True,
        choices=["status", "get_alerts", "get_blacklist", "ban", "unban"],
        help="执行的操作",
    )
    parser.add_argument("--ip", type=str, help="IP 地址")
    parser.add_argument("--reason", type=str, help="封禁原因")
    parser.add_argument("--lines", type=int, default=10, help="获取告警日志的行数")
    args = parser.parse_args()

    try:
        if args.action == "status":
            result = get_status()
        elif args.action == "get_alerts":
            result = get_alerts(args.lines)
        elif args.action == "get_blacklist":
            result = get_blacklist()
        elif args.action == "ban":
            if not args.ip:
                result = {"success": False, "message": "缺少 IP 地址参数"}
            elif not args.reason:
                result = {"success": False, "message": "缺少封禁原因参数"}
            else:
                result = ban_ip(args.ip, args.reason)
        else:
            if not args.ip:
                result = {"success": False, "message": "缺少 IP 地址参数"}
            else:
                result = unban_ip(args.ip)
    except Exception as exc:
        result = {"success": False, "message": f"执行操作失败: {exc}"}

    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
