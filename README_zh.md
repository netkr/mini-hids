# Mini-HIDS

Mini-HIDS 是一个基于 Python 标准库实现的轻量级 Linux 主机入侵检测工具，适合小型服务器场景。它聚焦于 SSH 爆破检测、基础 Web 攻击检测、增量 Webshell 扫描，以及可被 Agent 或运维脚本调用的 JSON CLI。

## 架构

- `mini_hids.py`：后台守护进程，负责日志跟踪、滑动窗口统计、自动封禁和周期性 Webshell 扫描
- `hids_cli.py`：控制面 CLI，适合 Agent 或运维脚本调用，输出统一 JSON
- `hids_common.py`：共享配置、SQLite 持久化、IP 校验与防火墙后端逻辑
- `config.json`：daemon 和 CLI 共用的运行时配置文件

## v1.1 优化点

- `config.json` 不再是摆设，daemon 和 CLI 都会实际加载
- daemon 和 CLI 共用一套配置、数据库和防火墙逻辑，减少行为分叉
- 正确识别 `nft`，修复原先 `nftables` 探测不准的问题
- 封禁和解封流程更收敛，避免数据库状态和防火墙状态明显漂移
- daemon 不再按整小时睡眠，封禁到期检查改为短周期轮询
- 过期黑名单记录会自动清理
- `blacklist.db`、`hids_alert.log`、`mini_hids.pid` 在使用相对路径时会落到项目目录下

## 功能

- 兼容日志轮转的实时日志监控
- 基于滑动窗口的 SSH 慢速爆破检测
- 基于访问日志特征的 Web 攻击检测
- 面向常见脚本文件的增量 Webshell 扫描
- 自动过期解封
- 基于 SQLite 的状态持久化
- 支持查询状态、告警、黑名单、手动封禁和手动解封的 JSON CLI
- 支持 `iptables`、`nftables` 和 `fail2ban`

## 运行要求

- Python 3.6+
- Linux
- 执行防火墙操作和读取受保护日志时需要 root 权限
- 需要至少一种支持的防火墙后端：
  - `iptables`
  - `nft`
  - `fail2ban-client`

## 配置说明

请直接修改 `config.json`，不要再去手改 Python 文件。

```json
{
  "LOG_PATHS": {
    "auth": ["/var/log/auth.log", "/var/log/secure"],
    "web": ["/var/log/nginx/access.log", "/var/log/apache2/access.log"],
    "mysql": ["/var/log/mysql/mysql.log", "/var/log/mysql/error.log"]
  },
  "BAN_TIME": 3600,
  "TRUSTED_IPS": ["127.0.0.1", "192.168.1.1"],
  "WEB_ROOT": ["/var/www/html", "/var/www"],
  "BLACKLIST_DB": "blacklist.db",
  "ALERT_LOG": "hids_alert.log",
  "PID_FILE": "mini_hids.pid",
  "MAX_FAILURES": 5,
  "WINDOW_SECONDS": 300,
  "CHECK_INTERVAL": 1,
  "WEBSHELL_SCAN_INTERVAL": 3600
}
```

补充说明：

- `BLACKLIST_DB`、`ALERT_LOG`、`PID_FILE` 可以配置为绝对路径；如果写相对路径，会自动落到项目目录下。
- `CHECK_INTERVAL` 控制 daemon 检查封禁过期的频率。
- `WEBSHELL_SCAN_INTERVAL` 控制 Web 目录重扫频率。
- `TRUSTED_IPS` 中的地址不会被 daemon 或 CLI 封禁。

## 快速开始

```bash
git clone https://github.com/netkr/mini-hids.git
cd mini-hids
```

先调整 `config.json`，再启动 daemon：

```bash
sudo python3 mini_hids.py
```

CLI 用法：

```bash
python3 hids_cli.py --action status
python3 hids_cli.py --action get_alerts --lines 20
python3 hids_cli.py --action get_blacklist
python3 hids_cli.py --action ban --ip 192.168.1.100 --reason "手动封禁"
python3 hids_cli.py --action unban --ip 192.168.1.100
```

## CLI 返回示例

所有 CLI 命令都返回 JSON，例如：

```json
{
  "success": true,
  "data": {
    "is_running": true,
    "pid": 12345,
    "firewall_backend": "iptables"
  }
}
```

## 安全提示

- 如果要真正执行防火墙封禁或读取受限日志，请用 root 权限运行 daemon。
- 如果后续在 `config.json` 中加入敏感信息，请把文件权限收紧。
- `TRUSTED_IPS` 要谨慎维护，避免把自己锁在服务器外面。
- Web 攻击和 Webshell 检测目前是启发式规则，告警更适合作为信号，而不是最终结论。

## 当前限制

- 检测仍然是基于正则和简单规则，属于轻量方案。
- 项目目前还没有自带 systemd service 文件和自动化测试。
- `nftables` 采用独立的 `mini_hids` 表和带 timeout 的集合实现，上生产前仍建议结合现有防火墙策略一起验证。

## 运行时文件

- `blacklist.db`：SQLite 状态库
- `hids_alert.log`：告警日志
- `mini_hids.pid`：daemon PID 文件

## 后续建议

- 补充可回放的样例日志和回归测试
- 提供 systemd unit 与 logrotate 示例
- 按不同服务扩展 Web 攻击规则
- 增加 webhook、syslog 等结构化告警输出
