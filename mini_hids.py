#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
轻量级主机入侵检测与日志分析系统（Mini-HIDS）
版本：v0.1
功能：实时监控系统日志，检测暴力破解和Webshell，自动封禁恶意IP
"""

import os
import re
import json
import socket
import http.client
import time
import threading
import sqlite3
import stat
import fcntl

# ==================== AI 智能研判配置 ====================
LLM_CONFIG = {
    "API_KEY": "",
    "BASE_URL": "",
    "MODEL_NAME": "gpt-4-turbo",
    "ENABLED": False,
    "COOLDOWN_MINUTES": 60
}
# ========================================================

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
    "CHECK_INTERVAL": 1,  # 检查间隔（秒）
    "AI_COOLDOWN": LLM_CONFIG["COOLDOWN_MINUTES"] * 60  # AI冷却时间（秒）
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

# 全局变量
ai_cooldown_times = {}
ban_times = {}
blacklist = set()


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
    global blacklist
    if ip not in blacklist:
        blacklist.add(ip)
        conn = sqlite3.connect(CONFIG["BLACKLIST_DB"])
        c = conn.cursor()
        c.execute("INSERT OR REPLACE INTO blacklist VALUES (?, ?, ?)",
                  (ip, int(time.time()), reason))
        conn.commit()
        conn.close()


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
    if os.system("which iptables > /dev/null 2>&1") == 0:
        return "iptables"
    elif os.system("which nftables > /dev/null 2>&1") == 0:
        return "nftables"
    elif os.system("which fail2ban-server > /dev/null 2>&1") == 0:
        return "fail2ban"
    else:
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
    if firewall == "iptables":
        os.system(f"iptables -A INPUT -s {ip} -j DROP")
    elif firewall == "nftables":
        os.system(f"nft add rule ip filter input ip saddr {ip} drop")
    elif firewall == "fail2ban":
        # 使用 fail2ban 封禁 IP
        os.system(f"fail2ban-client set sshd banip {ip}")
    
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
    if firewall == "iptables":
        os.system(f"iptables -D INPUT -s {ip} -j DROP")
    elif firewall == "nftables":
        os.system(f"nft delete rule ip filter input ip saddr {ip} drop")
    elif firewall == "fail2ban":
        # 使用 fail2ban 解封 IP
        os.system(f"fail2ban-client set sshd unbanip {ip}")
    
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
    match = re.search(r'Failed password for .* from (\S+)', line)
    if match:
        ip = match.group(1)
        if not is_trusted_ip(ip) and validate_ip(ip):
            # 记录失败次数（简化版，实际应使用更复杂的计数机制）
            log_alert(f"[SSH暴力破解] 检测到来自 {ip} 的登录失败")
            ban_ip(ip, "SSH暴力破解")
            
            # 检查是否需要AI分析
            check_ai_analysis(ip, "SSH暴力破解", line)


def detect_web_attack(line):
    """检测Web攻击"""
    # 匹配SQL注入、XSS等攻击特征
    attack_patterns = [
        r'\' OR\s+',
        r'UNION\s+SELECT',
        r'<script>',
        r'javascript:',
        r'../',
        r'\.\./'
    ]
    
    for pattern in attack_patterns:
        if re.search(pattern, line, re.IGNORECASE):
            # 提取IP
            ip_match = re.search(r'(\S+) - - \[', line)
            if ip_match:
                ip = ip_match.group(1)
                if not is_trusted_ip(ip) and validate_ip(ip):
                    log_alert(f"[Web攻击] 检测到来自 {ip} 的可能攻击: {pattern}")
                    ban_ip(ip, "Web攻击")
                    
                    # 检查是否需要AI分析
                    check_ai_analysis(ip, "Web攻击", line)
            break


def scan_webshell():
    """扫描Webshell"""
    for web_root in CONFIG["WEB_ROOT"]:
        if not os.path.exists(web_root):
            continue
        
        for root, dirs, files in os.walk(web_root):
            for file in files:
                if file.endswith(('.php', '.py', '.sh', '.jsp', '.asp', '.aspx')):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            for pattern in WEBSHELL_PATTERNS:
                                if re.search(pattern, content, re.IGNORECASE):
                                    log_alert(f"[Webshell] 检测到可疑文件: {file_path}")
                                    # 这里可以添加更多处理逻辑，如隔离文件
                                    break
                    except Exception as e:
                        pass


def check_ai_analysis(ip, attack_type, log_line):
    """检查是否需要AI分析"""
    if not LLM_CONFIG["ENABLED"]:
        return
    
    # 检查冷却时间
    key = f"{attack_type}:{ip}"
    current_time = time.time()
    if key in ai_cooldown_times and current_time < ai_cooldown_times[key]:
        return
    
    # 更新冷却时间
    ai_cooldown_times[key] = current_time + CONFIG["AI_COOLDOWN"]
    
    # 收集上下文信息
    context = {
        "attack_type": attack_type,
        "ip": ip,
        "log_line": log_line,
        "system_info": get_system_info(),
        "current_time": time.strftime("%Y-%m-%d %H:%M:%S")
    }
    
    # 异步调用AI分析
    threading.Thread(target=analyze_with_ai, args=(context,)).start()


def get_system_info():
    """获取系统信息"""
    system_info = {}
    
    # 获取系统负载
    try:
        with open('/proc/loadavg', 'r') as f:
            system_info['load_avg'] = f.read().strip()
    except:
        pass
    
    # 获取登录用户
    try:
        import subprocess
        result = subprocess.run(['who'], capture_output=True, text=True)
        system_info['logged_in_users'] = result.stdout.strip()
    except:
        pass
    
    return system_info


def analyze_with_ai(context):
    """使用AI分析攻击"""
    try:
        # 检查API配置是否完整
        api_key = LLM_CONFIG["API_KEY"]
        base_url = LLM_CONFIG["BASE_URL"]
        
        if not api_key or not base_url:
            log_alert("[AI分析] 未配置API密钥或URL，跳过AI分析")
            return
        
        # 构建请求数据
        prompt = f"请分析以下安全事件：\n"
        prompt += f"攻击类型：{context['attack_type']}\n"
        prompt += f"攻击IP：{context['ip']}\n"
        prompt += f"原始日志：{context['log_line']}\n"
        prompt += f"系统信息：{json.dumps(context['system_info'], indent=2)}\n"
        prompt += "请提供详细的分析和处置建议。"
        
        # 构建API请求
        model = LLM_CONFIG["MODEL_NAME"]
        
        # 解析URL
        if base_url.startswith('https://'):
            base_url = base_url[8:]
        
        # 检查URL格式
        if '/' not in base_url:
            log_alert("[AI分析] URL格式不正确，跳过AI分析")
            return
        
        host, path = base_url.split('/', 1)
        path = f"/{path}/chat/completions"
        
        # 构建请求体
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": "你是一个专业的安全分析师，负责分析服务器安全事件并提供处置建议。"},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.7
        }
        
        # 发送请求
        conn = http.client.HTTPSConnection(host, timeout=10)
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}"
        }
        conn.request("POST", path, json.dumps(payload), headers)
        response = conn.getresponse()
        
        if response.status == 200:
            data = json.loads(response.read().decode())
            if "choices" in data and data["choices"]:
                analysis = data["choices"][0]["message"]["content"]
                log_alert(f"[AI分析] {context['ip']} - {analysis}")
        else:
            log_alert(f"[AI分析失败] 状态码: {response.status}")
            
    except Exception as e:
        log_alert(f"[AI分析错误] {e}")


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
            
            # 每60秒重新扫描Webshell
            time.sleep(60)
            scan_webshell()
            
    except KeyboardInterrupt:
        log_alert("[停止] Mini-HIDS 已停止")
    finally:
        # 清理PID文件
        if os.path.exists(pid_file):
            os.remove(pid_file)


if __name__ == "__main__":
    main()
