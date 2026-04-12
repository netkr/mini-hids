#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
轻量级主机入侵检测与日志分析系统（Mini-HIDS）
版本：v1.0
功能：实时监控系统日志，检测暴力破解和Webshell，自动封禁恶意IP
定位：后台守护进程，负责7×24小时底层监控与自动防御
"""

import os
import re
import socket
import time
import threading
import sqlite3
import stat
from collections import deque

# 系统配置
CONFIG = {
    "LOG_PATHS": {
        "auth": ["/var/log/auth.log", "/var/log/secure"],
        "web": ["/var/log/nginx/access.log", "/var/log/apache2/access.log"],
        "mysql": ["/var/log/mysql/mysql.log", "/var/log/mysql/error.log"]
    },
    "BAN_TIME": 3600,  # 封禁时间（秒）
    "TRUSTED_IPS": ["127.0.0.1", "192.168.1.1"],  # 白名单IP
    "WEB_ROOT": ["/var/www/html", "/var/www"],  # Web根目录
    "BLACKLIST_DB": "blacklist.db",
    "ALERT_LOG": "hids_alert.log",
    "MAX_FAILURES": 5,  # 最大失败次数
    "WINDOW_SECONDS": 300,  # 滑动窗口时间（秒）
}

# Webshell特征
WEBSHELL_PATTERNS = [
    r'eval\(base64_decode\(',
    r'proc_open\(',
    r'shell_exec\(',
    r'system\(',
    r'passthru\(',
    r'exec\(',
    r'popen\(',
    r'assert\(',
    r'create_function\(',
    r'array_map\(.*eval\(',
    r'\$\_GET\[.*\]\(.*\)',
    r'\$\_POST\[.*\]\(.*\)',
    r'\$\_REQUEST\[.*\]\(.*\)',
    r'file_put_contents\(.*\$\_',
    r'fwrite\(.*\$\_',
    r'\$\_FILES\[.*\]\[\'tmp_name\'\]'
]

# 预编译正则表达式
COMPILED_WEBSHELL_PATTERNS = [re.compile(pattern, re.IGNORECASE) for pattern in WEBSHELL_PATTERNS]

# Web攻击特征
WEB_ATTACK_PATTERNS = [
    r'\' OR\s+',
    r'UNION\s+SELECT',
    r'<script>',
    r'javascript:',
    r'../',
    r'\.\./'
]

# 预编译Web攻击特征
COMPILED_WEB_ATTACK_PATTERNS = [re.compile(pattern, re.IGNORECASE) for pattern in WEB_ATTACK_PATTERNS]

# SSH失败匹配规则
SSH_FAILURE_PATTERN = re.compile(r'Failed password for .* from (\S+)')

# IP提取规则
IP_EXTRACT_PATTERN = re.compile(r'(\S+) - - \[')

# 全局变量
ban_times = {}
blacklist = set()
# 滑动窗口计数器，记录每个IP的失败时间戳
ip_failures = {}

# Webshell扫描相关
last_scan_time = 0
# 存储文件修改时间的字典
file_modification_times = {}
# 扫描间隔（秒）
WEBSHELL_SCAN_INTERVAL = 3600


def setup_environment():
    """设置环境"""
    # 创建日志目录
    if not os.path.exists('logs'):
        os.makedirs('logs', mode=0o755)
    
    # 创建黑名单数据库
    conn = sqlite3.connect(CONFIG["BLACKLIST_DB"])
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS blacklist
                 (ip TEXT PRIMARY KEY, ban_time INTEGER, reason TEXT)''')
    conn.commit()
    conn.close()
    
    # 加载黑名单
    load_blacklist()
    
    # 加载封禁时间
    load_ban_times()


def load_blacklist():
    """加载黑名单"""
    global blacklist
    conn = sqlite3.connect(CONFIG["BLACKLIST_DB"])
    c = conn.cursor()
    c.execute("SELECT ip FROM blacklist")
    for row in c.fetchall():
        blacklist.add(row[0])
    conn.close()


def add_to_blacklist(ip, reason):
    """添加到黑名单"""
    global blacklist, ban_times
    if ip not in blacklist:
        blacklist.add(ip)
        # 计算封禁到期时间
        ban_time = int(time.time() + CONFIG["BAN_TIME"])
        conn = sqlite3.connect(CONFIG["BLACKLIST_DB"])
        c = conn.cursor()
        c.execute("INSERT OR REPLACE INTO blacklist VALUES (?, ?, ?)",
                  (ip, ban_time, reason))
        conn.commit()
        conn.close()
        # 更新内存中的封禁时间
        ban_times[ip] = ban_time


def remove_from_blacklist(ip):
    """从黑名单移除"""
    global blacklist
    if ip in blacklist:
        blacklist.remove(ip)
        conn = sqlite3.connect(CONFIG["BLACKLIST_DB"])
        c = conn.cursor()
        c.execute("DELETE FROM blacklist WHERE ip = ?", (ip,))
        conn.commit()
        conn.close()


def load_ban_times():
    """加载封禁时间"""
    global ban_times
    conn = sqlite3.connect(CONFIG["BLACKLIST_DB"])
    c = conn.cursor()
    c.execute("SELECT ip, ban_time FROM blacklist")
    current_time = time.time()
    for row in c.fetchall():
        ip, ban_time = row
        # 只加载未过期的封禁
        if ban_time > current_time:
            ban_times[ip] = ban_time
    conn.close()
    log_alert(f"[状态加载] 从数据库加载了 {len(ban_times)} 个未过期的封禁")


def log_alert(message):
    """记录告警"""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    alert_message = f"[{timestamp}] {message}\n"
    print(alert_message, end="")
    
    # 写入告警日志
    with open(CONFIG["ALERT_LOG"], "a") as f:
        f.write(alert_message)


def is_trusted_ip(ip):
    """检查是否为可信IP"""
    return ip in CONFIG["TRUSTED_IPS"]


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
    import subprocess
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
    if is_trusted_ip(ip) or not validate_ip(ip):
        return
    
    firewall = detect_firewall()
    if not firewall:
        log_alert(f"[警告] 未检测到防火墙，无法封禁IP: {ip}")
        return
    
    # 添加到黑名单
    add_to_blacklist(ip, reason)
    
    # 执行封禁命令
    import subprocess
    try:
        if firewall == "iptables":
            subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], 
                        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        elif firewall == "nftables":
            subprocess.run(["nft", "add", "rule", "ip", "filter", "input", "ip", "saddr", ip, "drop"], 
                        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        elif firewall == "fail2ban":
            # 使用 fail2ban 封禁 IP
            subprocess.run(["fail2ban-client", "set", "sshd", "banip", ip], 
                        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError as e:
        log_alert(f"[错误] 执行防火墙命令失败: {e}")
    
    log_alert(f"[封禁] IP {ip} 因 {reason} 被封禁")
    
    # 记录封禁时间
    ban_times[ip] = time.time() + CONFIG["BAN_TIME"]


def unban_ip(ip):
    """解封IP"""
    if not validate_ip(ip):
        return
    
    firewall = detect_firewall()
    if not firewall:
        return
    
    # 从黑名单移除
    remove_from_blacklist(ip)
    
    # 执行解封命令
    import subprocess
    try:
        if firewall == "iptables":
            subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], 
                        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        elif firewall == "nftables":
            subprocess.run(["nft", "delete", "rule", "ip", "filter", "input", "ip", "saddr", ip, "drop"], 
                        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        elif firewall == "fail2ban":
            # 使用 fail2ban 解封 IP
            subprocess.run(["fail2ban-client", "set", "sshd", "unbanip", ip], 
                        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError as e:
        log_alert(f"[错误] 执行防火墙命令失败: {e}")
    
    log_alert(f"[解封] IP {ip} 已自动解封")
    
    # 移除封禁时间记录
    if ip in ban_times:
        del ban_times[ip]


def check_ban_expiry():
    """检查封禁过期"""
    current_time = time.time()
    expired_ips = [ip for ip, expiry in ban_times.items() if current_time > expiry]
    for ip in expired_ips:
        unban_ip(ip)


def tail_log_file(log_path):
    """实时监控日志文件（支持日志轮转）"""
    while True:
        try:
            # 获取文件inode
            stat_info = os.stat(log_path)
            inode = stat_info.st_ino
            
            with open(log_path, 'r') as f:
                # 移动到文件末尾
                f.seek(0, 2)
                
                while True:
                    # 检查文件是否被轮转
                    new_stat = os.stat(log_path)
                    if new_stat.st_ino != inode:
                        log_alert(f"[日志轮转] {log_path} 发生轮转，重新打开")
                        break
                    
                    # 读取新内容
                    line = f.readline()
                    if not line:
                        time.sleep(0.1)
                        continue
                    
                    # 处理日志行
                    process_log_line(line, log_path)
        except FileNotFoundError:
            log_alert(f"[警告] 日志文件 {log_path} 不存在，5秒后重试")
            time.sleep(5)
        except Exception as e:
            log_alert(f"[错误] 监控日志文件 {log_path} 时出错: {e}")
            time.sleep(5)


def process_log_line(line, log_path):
    """处理日志行"""
    # 检测SSH暴力破解
    if "auth.log" in log_path or "secure" in log_path:
        detect_ssh_brute_force(line)
    
    # 检测Web攻击
    elif "access.log" in log_path:
        detect_web_attack(line)


def detect_ssh_brute_force(line):
    """检测SSH暴力破解"""
    # 匹配SSH登录失败
    match = SSH_FAILURE_PATTERN.search(line)
    if match:
        ip = match.group(1)
        if not is_trusted_ip(ip) and validate_ip(ip):
            # 使用滑动窗口计数器
            current_time = time.time()
            
            # 初始化该IP的失败记录
            if ip not in ip_failures:
                ip_failures[ip] = deque(maxlen=CONFIG["MAX_FAILURES"])
            
            # 添加当前失败时间戳
            ip_failures[ip].append(current_time)
            
            # 清理过期的时间戳
            while ip_failures[ip] and current_time - ip_failures[ip][0] > CONFIG["WINDOW_SECONDS"]:
                ip_failures[ip].popleft()
            
            # 检查是否达到阈值
            if len(ip_failures[ip]) >= CONFIG["MAX_FAILURES"]:
                log_alert(f"[SSH暴力破解] 检测到来自 {ip} 的登录失败，已达到阈值")
                # 直接封禁
                ban_ip(ip, "SSH暴力破解")


def detect_web_attack(line):
    """检测Web攻击"""
    # 匹配SQL注入、XSS等攻击特征
    for pattern in COMPILED_WEB_ATTACK_PATTERNS:
        if pattern.search(line):
            # 提取IP
            ip_match = IP_EXTRACT_PATTERN.search(line)
            if ip_match:
                ip = ip_match.group(1)
                if not is_trusted_ip(ip) and validate_ip(ip):
                    # 使用滑动窗口计数器
                    current_time = time.time()
                    
                    # 初始化该IP的失败记录
                    if ip not in ip_failures:
                        ip_failures[ip] = deque(maxlen=CONFIG["MAX_FAILURES"])
                    
                    # 添加当前失败时间戳
                    ip_failures[ip].append(current_time)
                    
                    # 清理过期的时间戳
                    while ip_failures[ip] and current_time - ip_failures[ip][0] > CONFIG["WINDOW_SECONDS"]:
                        ip_failures[ip].popleft()
                    
                    # 检查是否达到阈值
                    if len(ip_failures[ip]) >= CONFIG["MAX_FAILURES"]:
                        log_alert(f"[Web攻击] 检测到来自 {ip} 的可能攻击: {pattern}，已达到阈值")
                        # 直接封禁
                        ban_ip(ip, "Web攻击")
            break


def scan_webshell():
    """扫描Webshell（增量扫描）"""
    global last_scan_time, file_modification_times
    current_time = time.time()
    
    # 记录开始时间
    scan_start_time = time.time()
    scanned_files = 0
    modified_files = 0
    
    for web_root in CONFIG["WEB_ROOT"]:
        if not os.path.exists(web_root):
            continue
        
        for root, dirs, files in os.walk(web_root):
            for file in files:
                if file.endswith(('.php', '.py', '.sh', '.jsp', '.asp', '.aspx')):
                    file_path = os.path.join(root, file)
                    try:
                        # 获取文件修改时间
                        file_mtime = os.path.getmtime(file_path)
                        
                        # 检查文件是否被修改过
                        if file_path not in file_modification_times or file_mtime > file_modification_times.get(file_path, 0):
                            # 文件被修改，需要扫描
                            modified_files += 1
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                                for pattern in COMPILED_WEBSHELL_PATTERNS:
                                    if pattern.search(content):
                                        log_alert(f"[Webshell] 检测到可疑文件: {file_path}")
                                        # 这里可以添加更多处理逻辑，如隔离文件
                                        break
                            # 更新文件修改时间
                            file_modification_times[file_path] = file_mtime
                        scanned_files += 1
                    except Exception as e:
                        pass
    
    # 更新上次扫描时间
    last_scan_time = current_time
    
    # 记录扫描统计信息
    scan_duration = time.time() - scan_start_time
    log_alert(f"[Webshell扫描] 完成扫描，共扫描 {scanned_files} 个文件，其中 {modified_files} 个是修改过的文件，耗时 {scan_duration:.2f} 秒")


def main():
    """主函数"""
    # 检查平台
    if os.name != 'posix':
        print("Mini-HIDS 仅支持 Linux 系统")
        return
    
    # 检查是否已在运行
    pid_file = "mini_hids.pid"
    if os.path.exists(pid_file):
        with open(pid_file, 'r') as f:
            try:
                pid = int(f.read().strip())
                os.kill(pid, 0)
                print("Mini-HIDS 已经在运行中")
                return
            except:
                pass
    
    # 写入PID文件
    with open(pid_file, 'w') as f:
        f.write(str(os.getpid()))
    
    try:
        # 设置环境
        setup_environment()
        
        # 启动日志监控线程
        log_threads = []
        for log_type, paths in CONFIG["LOG_PATHS"].items():
            for path in paths:
                if os.path.exists(path):
                    thread = threading.Thread(target=tail_log_file, args=(path,))
                    thread.daemon = True
                    thread.start()
                    log_threads.append(thread)
                    log_alert(f"[监控启动] 开始监控 {path}")
        
        # 启动Webshell扫描线程
        webshell_thread = threading.Thread(target=scan_webshell)
        webshell_thread.daemon = True
        webshell_thread.start()
        log_alert("[Webshell扫描] 开始扫描Web目录")
        
        # 主循环
        while True:
            # 检查封禁过期
            check_ban_expiry()
            
            # 每3600秒重新扫描Webshell
            time.sleep(WEBSHELL_SCAN_INTERVAL)
            scan_webshell()
            
    except KeyboardInterrupt:
        log_alert("[停止] Mini-HIDS 已停止")
    finally:
        # 清理PID文件
        if os.path.exists(pid_file):
            os.remove(pid_file)


if __name__ == "__main__":
    main()