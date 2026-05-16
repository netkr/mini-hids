#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Mini-HIDS control-plane API for MCP and agent integration.
"""

import os
import time

from hids_common import (
    COMPILED_WEBSHELL_PATTERNS,
    FirewallManager,
    delete_blacklist_entry,
    detect_firewall,
    execute_ban,
    execute_unban,
    init_db,
    list_blacklist_rows,
    load_config,
    parse_alert_line,
    purge_expired_blacklist_entries,
    upsert_blacklist_entry,
    validate_ban_request,
    validate_ip,
)


CONFIG = load_config()
FIREWALL = FirewallManager()


def ensure_runtime():
    init_db(CONFIG["BLACKLIST_DB"])
    purge_expired_blacklist_entries(CONFIG["BLACKLIST_DB"])


def ban_ip(ip, reason):
    validation_error = validate_ban_request(ip, CONFIG["TRUSTED_IPS"], CONFIG["BLACKLIST_DB"])
    if validation_error is not None:
        return validation_error

    try:
        expiry_time = execute_ban(ip, reason, CONFIG["BAN_TIME"], FIREWALL, CONFIG["BLACKLIST_DB"])
    except Exception as exc:
        return {"success": False, "message": f"封禁失败: {exc}"}

    return {
        "success": True,
        "message": f"IP {ip} 已成功封禁，原因: {reason}",
        "data": {"expiry_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(expiry_time))},
    }


def unban_ip(ip):
    if not validate_ip(ip):
        return {"success": False, "message": f"无效的 IP 地址: {ip}"}

    try:
        was_banned = execute_unban(ip, FIREWALL, CONFIG["BLACKLIST_DB"])
    except Exception as exc:
        return {"success": False, "message": f"解封失败: {exc}"}

    if not was_banned:
        return {"success": True, "message": f"IP {ip} 当前不在黑名单中"}

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


def get_alerts(lines=10, structured=True):
    if lines <= 0:
        return {"success": False, "message": "lines 必须大于 0"}

    alerts = []
    try:
        if os.path.exists(CONFIG["ALERT_LOG"]):
            with open(CONFIG["ALERT_LOG"], "r", encoding="utf-8", errors="ignore") as alert_file:
                recent_lines = alert_file.readlines()[-lines:]
            for line in recent_lines:
                line = line.strip()
                if not line:
                    continue
                if structured:
                    alerts.append(parse_alert_line(line))
                else:
                    alerts.append(line)
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


def scan_webshell():
    scan_start_time = time.time()
    scanned_files = 0
    suspicious_files = []

    for web_root in CONFIG["WEB_ROOT"]:
        if not os.path.exists(web_root):
            continue

        for root, _dirs, files in os.walk(web_root):
            for file_name in files:
                if not file_name.endswith((".php", ".py", ".sh", ".jsp", ".asp", ".aspx")):
                    continue

                file_path = os.path.join(root, file_name)
                try:
                    scanned_files += 1
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as source_file:
                        content = source_file.read()

                    matched_patterns = []
                    for pattern in COMPILED_WEBSHELL_PATTERNS:
                        if pattern.search(content):
                            matched_patterns.append(pattern.pattern)

                    if matched_patterns:
                        suspicious_files.append({
                            "file": file_path,
                            "patterns": matched_patterns,
                        })
                except Exception:
                    continue

    scan_duration = time.time() - scan_start_time
    return {
        "success": True,
        "data": {
            "scanned_files": scanned_files,
            "suspicious_files": suspicious_files,
            "suspicious_count": len(suspicious_files),
            "scan_duration": round(scan_duration, 2),
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        },
    }
