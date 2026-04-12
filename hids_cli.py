#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
轻量级主机入侵检测与日志分析系统（Mini-HIDS）
版本：v1.0
功能：CLI 命令行工具，专供 Agent 调用
定位：控制面 / Agent 专属调用接口，无阻塞、无死循环，执行完立刻返回标准 JSON 格式字符串
"""

import os
import sys
import argparse
import json
import socket
import time
import sqlite3
import subprocess

# 系统配置
CONFIG = {
    "BLACKLIST_DB": "blacklist.db",
    "ALERT_LOG": "hids_alert.log",
    "PID_FILE": "mini_hids.pid",
    "BAN_TIME": 3600  # 封禁时间（秒）
}


def validate_ip(ip):
    """验证IP地址格式"""
    try:
        socket.inet_pton(socket.AF_INET, ip)
        return True
    except socket.error:
        try:
            socket.inet_pton(socket.AF_INET6, ip)
            return True
        except socket.error:
            return False


def detect_firewall():
    """检测防火墙类型"""
    try:
        if subprocess.run(["which", "iptables"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
            return "iptables"
        elif subprocess.run(["which", "nftables"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
            return "nftables"
        elif subprocess.run(["which", "fail2ban-server"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
            return "fail2ban"
        else:
            return None
    except Exception:
        return None


def ban_ip(ip, reason):
    """封禁IP"""
    if not validate_ip(ip):
        return {"success": False, "message": f"无效的IP地址: {ip}"}
    
    firewall = detect_firewall()
    if not firewall:
        return {"success": False, "message": "未检测到防火墙，无法封禁IP"}
    
    # 计算封禁到期时间
    ban_time = int(time.time() + CONFIG["BAN_TIME"])
    
    # 添加到黑名单数据库
    try:
        conn = sqlite3.connect(CONFIG["BLACKLIST_DB"])
        c = conn.cursor()
        c.execute("INSERT OR REPLACE INTO blacklist VALUES (?, ?, ?)",
                  (ip, ban_time, reason))
        conn.commit()
        conn.close()
    except Exception as e:
        return {"success": False, "message": f"数据库操作失败: {e}"}
    
    # 执行封禁命令
    try:
        if firewall == "iptables":
            subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], 
                        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        elif firewall == "nftables":
            subprocess.run(["nft", "add", "rule", "ip", "filter", "input", "ip", "saddr", ip, "drop"], 
                        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        elif firewall == "fail2ban":
            subprocess.run(["fail2ban-client", "set", "sshd", "banip", ip], 
                        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError as e:
        return {"success": False, "message": f"执行防火墙命令失败: {e}"}
    
    return {"success": True, "message": f"IP {ip} 已成功封禁，原因: {reason}"}


def unban_ip(ip):
    """解封IP"""
    if not validate_ip(ip):
        return {"success": False, "message": f"无效的IP地址: {ip}"}
    
    firewall = detect_firewall()
    if not firewall:
        return {"success": False, "message": "未检测到防火墙，无法解封IP"}
    
    # 从黑名单数据库移除
    try:
        conn = sqlite3.connect(CONFIG["BLACKLIST_DB"])
        c = conn.cursor()
        c.execute("DELETE FROM blacklist WHERE ip = ?", (ip,))
        conn.commit()
        conn.close()
    except Exception as e:
        return {"success": False, "message": f"数据库操作失败: {e}"}
    
    # 执行解封命令
    try:
        if firewall == "iptables":
            subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], 
                        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        elif firewall == "nftables":
            subprocess.run(["nft", "delete", "rule", "ip", "filter", "input", "ip", "saddr", ip, "drop"], 
                        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        elif firewall == "fail2ban":
            subprocess.run(["fail2ban-client", "set", "sshd", "unbanip", ip], 
                        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError as e:
        return {"success": False, "message": f"执行防火墙命令失败: {e}"}
    
    return {"success": True, "message": f"IP {ip} 已成功解封"}


def get_status():
    """获取系统状态"""
    # 检查服务是否运行
    is_running = False
    pid = None
    if os.path.exists(CONFIG["PID_FILE"]):
        try:
            with open(CONFIG["PID_FILE"], 'r') as f:
                pid = int(f.read().strip())
            # 尝试发送信号 0 来检查进程是否存在
            os.kill(pid, 0)
            is_running = True
        except:
            pass
    
    # 获取系统负载
    load_avg = ""
    try:
        with open('/proc/loadavg', 'r') as f:
            load_avg = f.read().strip()
    except:
        pass
    
    return {
        "success": True,
        "data": {
            "is_running": is_running,
            "pid": pid,
            "load_avg": load_avg,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
    }


def get_alerts(lines=10):
    """获取告警日志"""
    alerts = []
    try:
        if os.path.exists(CONFIG["ALERT_LOG"]):
            with open(CONFIG["ALERT_LOG"], 'r') as f:
                # 读取所有行并反转，以便按时间倒序
                all_lines = f.readlines()
                recent_lines = all_lines[-lines:]
                # 再次反转，使最新的在最后
                for line in recent_lines:
                    line = line.strip()
                    if line:
                        alerts.append(line)
    except Exception as e:
        return {"success": False, "message": f"读取告警日志失败: {e}"}
    
    return {
        "success": True,
        "data": {
            "alerts": alerts,
            "count": len(alerts),
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
    }


def get_blacklist():
    """获取黑名单"""
    blacklist = []
    try:
        conn = sqlite3.connect(CONFIG["BLACKLIST_DB"])
        c = conn.cursor()
        c.execute("SELECT ip, ban_time, reason FROM blacklist")
        current_time = time.time()
        for row in c.fetchall():
            ip, ban_time, reason = row
            # 只返回未过期的封禁
            if ban_time > current_time:
                blacklist.append({
                    "ip": ip,
                    "ban_time": ban_time,
                    "expiry_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ban_time)),
                    "reason": reason,
                    "time_remaining": int(ban_time - current_time)
                })
        conn.close()
    except Exception as e:
        return {"success": False, "message": f"读取黑名单失败: {e}"}
    
    return {
        "success": True,
        "data": {
            "blacklist": blacklist,
            "count": len(blacklist),
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
    }


def main():
    """主函数"""
    parser = argparse.ArgumentParser(description='Mini-HIDS CLI 工具')
    parser.add_argument('--action', type=str, required=True, choices=['status', 'get_alerts', 'get_blacklist', 'ban', 'unban'],
                        help='执行的操作')
    parser.add_argument('--ip', type=str, help='IP地址')
    parser.add_argument('--reason', type=str, help='封禁原因')
    parser.add_argument('--lines', type=int, default=10, help='获取告警日志的行数')
    
    args = parser.parse_args()
    
    result = {}
    
    try:
        if args.action == 'status':
            result = get_status()
        elif args.action == 'get_alerts':
            result = get_alerts(args.lines)
        elif args.action == 'get_blacklist':
            result = get_blacklist()
        elif args.action == 'ban':
            if not args.ip:
                result = {"success": False, "message": "缺少IP地址参数"}
            elif not args.reason:
                result = {"success": False, "message": "缺少封禁原因参数"}
            else:
                result = ban_ip(args.ip, args.reason)
        elif args.action == 'unban':
            if not args.ip:
                result = {"success": False, "message": "缺少IP地址参数"}
            else:
                result = unban_ip(args.ip)
    except Exception as e:
        result = {"success": False, "message": f"执行操作失败: {e}"}
    
    # 输出标准 JSON 格式
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()