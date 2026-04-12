# 轻量级主机入侵检测与日志分析系统（Mini-HIDS）

## 项目简介

Mini-HIDS 是一个基于 Python 原生库的零依赖、智能化 Linux 服务器防御工具。它通过实时监听系统关键日志，配合自动化封禁逻辑与大模型智能分析，实现对暴力破解与 Webshell 的分钟级处置能力。

**安装方法**
1、没有使用agent的情况：git部署到云服务器，运行文件并填写您使用的大模型URL和API-key；
2、使用agent的情况：把本项目链接发给agent（比如openclaw、hermes agent），并告诉它“把这个项目封装成skill”并授权即可；

## 核心功能

- **日志实时监控**：支持 `tail -F` 逻辑，基于 Inode 监控实现日志轮转兼容
- **暴力破解检测**：自动检测 SSH 暴力破解并封禁恶意 IP
- **Web 攻击检测**：检测 SQL 注入、XSS 等 Web 攻击
- **Webshell 扫描**：深度递归扫描 Web 根目录，匹配高危指纹
- **AI 智能分析**：集成大模型分析能力，提供专业的安全建议
- **动态封禁**：支持设置封禁时间，自动过期解封
- **白名单豁免**：确保管理员 IP 永不被拦截

## 快速开始

### 环境要求

- Python 3.6+
- Linux 系统
- 防火墙（iptables、nftables 或 fail2ban）

### 安装与运行

1. **克隆项目**
   ```bash
   git clone <repository-url>
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

- v0.2：实现核心功能
