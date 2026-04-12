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
from collections import deque

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
    "AI_COOLDOWN": LLM_CONFIG["COOLDOWN_MINUTES"] * 60,  # AI冷却时间（秒）
    "WINDOW_SECONDS": 300,  # 滑动窗口时间（秒）
    "MAX_QUEUE_SIZE": 100,  # AI分析队列最大长度
    "WEBHOOK_URL": ""  # 协同防御Webhook地址
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
ai_cooldown_times = {}
ban_times = {}
blacklist = set()
# 滑动窗口计数器，记录每个IP的失败时间戳
ip_failures = {}
# AI分析队列
ai_analysis_queue = deque(maxlen=CONFIG["MAX_QUEUE_SIZE"])
# AI分析队列锁
ai_queue_lock = threading.Lock()

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
                # 快轨：直接封禁
                ban_ip(ip, "SSH暴力破解")
                
                # 智轨：加入AI分析队列
                attack_context = {
                    "attack_type": "SSH暴力破解",
                    "ip": ip,
                    "log_line": line,
                    "timestamp": current_time,
                    "failure_count": len(ip_failures[ip])
                }
                with ai_queue_lock:
                    ai_analysis_queue.append(attack_context)
                
                # 检查是否需要AI分析
                check_ai_analysis(ip, "SSH暴力破解", line)


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
                        # 快轨：直接封禁
                        ban_ip(ip, "Web攻击")
                        
                        # 智轨：加入AI分析队列
                        attack_context = {
                            "attack_type": "Web攻击",
                            "ip": ip,
                            "log_line": line,
                            "timestamp": current_time,
                            "failure_count": len(ip_failures[ip]),
                            "attack_pattern": pattern
                        }
                        with ai_queue_lock:
                            ai_analysis_queue.append(attack_context)
                        
                        # 检查是否需要AI分析
                        check_ai_analysis(ip, "Web攻击", line)
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


def process_ai_analysis_queue():
    """处理AI分析队列"""
    while True:
        try:
            # 检查队列是否有任务
            with ai_queue_lock:
                if ai_analysis_queue:
                    context = ai_analysis_queue.popleft()
                else:
                    context = None
            
            if context:
                # 调用AI分析
                analyze_with_ai(context)
            else:
                # 队列为空，休息一下
                time.sleep(1)
        except Exception as e:
            log_alert(f"[AI队列处理错误] {e}")
            time.sleep(1)


def parse_ai_strategy(raw_ai_response):
    """[安全核心] 解析AI返回的防御策略，严禁执行eval()或直接sh运行"""
    try:
        # 清理响应内容
        response = raw_ai_response.strip()
        
        # 尝试提取Markdown代码块中的JSON
        code_block_match = re.search(r'```json\n(.*?)\n```', response, re.DOTALL)
        if code_block_match:
            response = code_block_match.group(1).strip()
        
        # 尝试提取任何代码块中的JSON
        code_match = re.search(r'```(.*?)```', response, re.DOTALL)
        if code_match:
            response = code_match.group(1).strip()
        
        # 解析JSON
        strategy = json.loads(response)
        return strategy
    except Exception as e:
        log_alert(f"[AI策略解析失败] {e}，降级为单IP封禁")
        return None


def send_webhook_alert(alert_data):
    """发送Webhook告警"""
    if not CONFIG["WEBHOOK_URL"]:
        return
    
    try:
        import urllib.request
        import urllib.error
        
        # 构建告警数据
        data = json.dumps(alert_data).encode('utf-8')
        headers = {'Content-Type': 'application/json'}
        
        # 发送请求
        req = urllib.request.Request(CONFIG["WEBHOOK_URL"], data=data, headers=headers)
        with urllib.request.urlopen(req, timeout=5) as response:
            if response.getcode() == 200:
                log_alert("[Webhook] 告警发送成功")
            else:
                log_alert(f"[Webhook] 告警发送失败，状态码: {response.getcode()}")
    except Exception as e:
        log_alert(f"[Webhook] 告警发送错误: {e}")


def execute_ai_strategy(strategy, context):
    """执行AI生成的防御策略"""
    try:
        if not strategy:
            return
        
        action = strategy.get("action", "block")
        target = strategy.get("target", "IP")
        value = strategy.get("value", context["ip"])
        duration = strategy.get("duration", CONFIG["BAN_TIME"])
        threat_score = strategy.get("threat_score", 0)
        
        if action == "block":
            if target == "SUBNET":
                # 封禁整个子网
                log_alert(f"[AI策略] 执行子网封禁: {value}")
                # 这里可以实现子网封禁逻辑
            else:
                # 封禁单个IP
                log_alert(f"[AI策略] 执行IP封禁: {value}, 时长: {duration}秒, 威胁评分: {threat_score}")
                # 更新封禁时间
                ban_times[value] = time.time() + duration
        
        # 发送Webhook告警
        alert_data = {
            "action": action,
            "target": target,
            "value": value,
            "duration": duration,
            "threat_score": threat_score,
            "context": context
        }
        send_webhook_alert(alert_data)
    except Exception as e:
        log_alert(f"[AI策略执行错误] {e}")


def analyze_with_ai(context):
    """使用AI分析攻击并生成防御策略"""
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
        prompt += f"系统信息：{json.dumps(get_system_info(), indent=2)}\n"
        prompt += f"失败次数：{context.get('failure_count', 1)}\n"
        if 'attack_pattern' in context:
            prompt += f"攻击特征：{context['attack_pattern']}\n"
        prompt += "\n请从安全专家角度给出防御指令，返回JSON格式：\n"
        prompt += "{\"action\": \"block\", \"target\": \"IP|SUBNET\", \"value\": \"目标IP或子网\", \"duration\": 封禁时长(秒), \"threat_score\": 威胁评分(0-100)}"
        
        # 构建API请求
        model = LLM_CONFIG["MODEL_NAME"]
        
        # 解析URL
        import urllib.parse
        
        # 确保URL有协议
        if not base_url.startswith(('http://', 'https://')):
            base_url = 'https://' + base_url
        
        # 解析URL
        parsed_url = urllib.parse.urlparse(base_url)
        host = parsed_url.netloc
        path = parsed_url.path
        
        # 构建完整的API路径
        if not path.endswith('/chat/completions'):
            if path.endswith('/'):
                path += 'chat/completions'
            else:
                path += '/chat/completions'
        
        # 确保path以/开头
        if not path.startswith('/'):
            path = '/' + path
        
        # 构建请求体
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": "你是一个专业的安全分析师，负责分析服务器安全事件并提供处置建议。请严格返回JSON格式的防御指令，不要包含其他文本。"},
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
                raw_response = data["choices"][0]["message"]["content"]
                log_alert(f"[AI分析] 收到分析结果: {raw_response}")
                
                # 解析AI策略
                strategy = parse_ai_strategy(raw_response)
                # 执行AI策略
                execute_ai_strategy(strategy, context)
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
        
        # 启动AI分析队列处理线程
        ai_thread = threading.Thread(target=process_ai_analysis_queue)
        ai_thread.daemon = True
        ai_thread.start()
        log_alert("[AI分析] 启动AI分析队列处理线程")
        
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
