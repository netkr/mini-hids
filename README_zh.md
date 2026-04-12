# 轻量级主机入侵检测与日志分析系统（Mini-HIDS）

## 安全与权限说明

### 为什么需要 Root 权限
- **防火墙管理**：需要 Root 权限执行防火墙命令（iptables、nftables 或 fail2ban）来封禁和解封恶意 IP
- **日志访问**：某些系统日志文件（如 /var/log/auth.log）需要 Root 权限才能读取
- **系统监控**：访问系统信息（如 /proc/loadavg）可能需要提升权限

### API Key 处理
- **可选配置**：API Key 是可选的 - 系统可以在没有 AI 分析功能的情况下运行
- **安全建议**：使用环境变量存储 API Key，而不是硬编码在 Python 文件中
  ```bash
  # 示例：设置环境变量
  export MINI_HIDS_API_KEY="sk-xxxxxxxxxxxxxxxx"
  export MINI_HIDS_BASE_URL="https://api.your-provider.com/v1"
  
  # 然后修改 mini_hids.py 使用环境变量
  import os
  LLM_CONFIG = {
      "API_KEY": os.environ.get("MINI_HIDS_API_KEY", ""),
      "BASE_URL": os.environ.get("MINI_HIDS_BASE_URL", ""),
      "MODEL_NAME": "gpt-4-turbo",
      "ENABLED": bool(os.environ.get("MINI_HIDS_API_KEY", "")),
      "COOLDOWN_MINUTES": 60
  }
  ```
- **文件权限**：确保配置文件权限设置为 `600`，防止 API Key 泄露

### 系统路径访问
- **日志文件**：/var/log/auth.log, /var/log/secure, /var/log/nginx/access.log, /var/log/apache2/access.log, /var/log/mysql/mysql.log, /var/log/mysql/error.log
- **系统信息**：/proc/loadavg
- **Web 目录**：/var/www/html, /var/www（用于 Webshell 扫描）
- **本地文件**：hids_alert.log, blacklist.db, mini_hids.pid

## 项目简介

Mini-HIDS 是一个基于 Python 原生库的零依赖、智能化 Linux 服务器防御工具。它通过实时监听系统关键日志，配合自动化封禁逻辑与大模型智能分析，实现对暴力破解与 Webshell 的分钟级处置能力。

**安装方法**
1、没有使用agent的情况：git部署到云服务器，运行文件并填写您使用的大模型URL和API-key；
2、使用agent的情况：把本项目链接发给agent（比如openclaw、hermes agent），并告诉它“把这个项目封装成skill”并授权即可；

## 核心功能

- **日志实时监控**：支持 `tail -F` 逻辑，基于 Inode 监控实现日志轮转兼容
- **滑动窗口计数器**：使用滑动窗口算法检测慢速爆破攻击
- **双轨制防御**：快轨（直接封禁）和智轨（AI 分析）
- **暴力破解检测**：自动检测 SSH 暴力破解并封禁恶意 IP
- **Web 攻击检测**：检测 SQL 注入、XSS 等 Web 攻击
- **Webshell 扫描**：增量扫描 Web 根目录，降低 I/O 负载
- **AI 智能分析**：集成大模型分析能力，提供专业的安全建议
- **动态封禁**：支持设置封禁时间，自动过期解封
- **白名单豁免**：确保管理员 IP 永不被拦截
- **状态持久化**：使用 SQLite 数据库存储封禁时间，确保系统重启后规则依然生效
- **Webhook 集成**：支持向外部系统发送告警
- **正则表达式预编译**：通过预编译所有正则模式提高性能
- **安全命令执行**：使用 subprocess.run() 执行防火墙命令，提高安全性

## 快速开始

### 环境要求

- Python 3.6+
- Linux 系统
- 防火墙（iptables、nftables 或 fail2ban）

### 安装与运行

1. **克隆项目**
   ```bash
   git clone https://github.com/netkr/mini-hids.git
   cd mini-hids
   ```

2. **配置 AI 接口**
   编辑 `mini_hids.py` 文件顶部的 `LLM_CONFIG` 配置块，填入您的大模型 API 信息：
   ```python
   LLM_CONFIG = {
       "API_KEY": "sk-xxxxxxxxxxxxxxxx",
       "BASE_URL": "https://api.your-provider.com/v1",
       "MODEL_NAME": "gpt-4-turbo",
       "ENABLED": True,
       "COOLDOWN_MINUTES": 60
   }
   ```

3. **修改系统配置**
   编辑 `config.json` 文件，根据您的服务器环境调整配置：
   ```json
   {
       "LOG_PATHS": {
           "auth": ["/var/log/auth.log", "/var/log/secure"],
           "web": ["/var/log/nginx/access.log", "/var/log/apache2/access.log"],
           "mysql": ["/var/log/mysql/mysql.log", "/var/log/mysql/error.log"]
       },
       "BAN_TIME": 3600,
       "TRUSTED_IPS": ["127.0.0.1", "192.168.1.1"],
       "WEB_ROOT": ["/var/www/html", "/var/www"]
   }
   ```

4. **运行系统**
   ```bash
   sudo python3 mini_hids.py
   ```

## 配置说明

### 核心配置项

- **LOG_PATHS**：需要监控的日志文件路径
- **BAN_TIME**：IP 封禁时间（秒）
- **TRUSTED_IPS**：白名单 IP 列表
- **WEB_ROOT**：Web 根目录路径，用于 Webshell 扫描
- **BAN_TIME**：IP 封禁时间（秒）
- **MAX_FAILURES**：最大失败次数，超过此值将触发封禁

### AI 配置项

- **API_KEY**：大模型 API 密钥
- **BASE_URL**：大模型 API 地址
- **MODEL_NAME**：使用的模型名称
- **ENABLED**：是否启用 AI 分析
- **COOLDOWN_MINUTES**：AI 分析冷却时间（分钟）

## 日志与告警

- **hids_alert.log**：系统告警日志
- **blacklist.db**：黑名单数据库

## 安全建议

1. **权限设置**：确保配置文件权限为 `600`，防止 API Key 泄露
2. **定期更新**：定期更新 Webshell 特征库
3. **白名单管理**：合理配置白名单，避免误封
4. **监控频率**：根据服务器负载调整监控频率

## 注意事项

- 本系统需要 root 权限运行，以便执行防火墙命令
- 首次运行时会自动创建必要的目录和文件
- 系统会在后台运行，通过 PID 文件确保单实例运行

## 版本历史

- v1.0：重大优化与增强
  - 实现滑动窗口计数器，用于检测慢速爆破攻击
  - 添加双轨制防御系统（快轨 + 智轨）
  - 增强 AI 策略解析，支持 Markdown 代码块
  - 实现 Webshell 增量扫描，降低 I/O 负载
  - 优化正则表达式性能，使用预编译
  - 提高命令执行安全性，使用 subprocess.run()
  - 增强 API URL 解析，使用 urllib.parse
  - 添加状态持久化，使用 SQLite 数据库
  - 添加 Webhook 集成，支持外部告警
  - 添加全面的安全与权限文档
- v0.2：实现核心功能
