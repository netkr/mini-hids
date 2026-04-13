# Mini-HIDS

<table>
  <tr>
    <td style="padding: 10px;">
      <img src="images/1.png" alt="Image 1" style="width: 100%; max-width: 400px;">
    </td>
    <td style="padding: 10px;">
      <img src="images/2.png" alt="Image 2" style="width: 100%; max-width: 400px;">
    </td>
  </tr>
</table>

#### [中文文档](/README_zh.md)

Mini-HIDS is a lightweight Linux host intrusion detection tool built with the Python standard library. It is designed for small servers that need straightforward brute-force detection, basic web attack detection, incremental webshell scanning, and a scriptable JSON CLI.

## Architecture

- `mini_hids.py`: background daemon that tails logs, tracks attack windows, manages automatic blocking, and runs periodic webshell scans
- `hids_cli.py`: control-plane CLI for agents or operators, always returns JSON
- `hids_common.py`: shared configuration, SQLite persistence, IP validation, and firewall backend helpers
- `config.json`: runtime configuration loaded by both the daemon and the CLI

## What Changed In v1.1

- `config.json` is now actually loaded and merged with built-in defaults
- daemon and CLI now share the same config, database, and firewall logic
- firewall detection now correctly recognizes `nft`
- ban and unban operations are idempotent for the database path and do not intentionally duplicate `iptables` rules
- the daemon checks expiry on a short interval instead of sleeping for a full scan window
- expired blacklist records are cleaned automatically
- runtime files such as `blacklist.db`, `hids_alert.log`, and `mini_hids.pid` resolve relative to the project directory when configured with relative paths

## Features

- Real-time log tailing with log rotation awareness
- Sliding-window detection for slow SSH brute-force attempts
- Pattern-based web attack detection for access logs
- Incremental webshell scanning for common script file types
- Automatic ban expiry handling
- SQLite-backed state persistence
- JSON CLI for status, alerts, blacklist inspection, manual ban, and manual unban
- Support for `iptables`, `nftables`, and `fail2ban`

## Requirements

- Python 3.6+
- Linux
- Root privileges for firewall operations and protected log access
- One supported firewall backend:
  - `iptables`
  - `nft`
  - `fail2ban-client`

## Configuration

Edit `config.json` instead of modifying the Python files.

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

Notes:

- `BLACKLIST_DB`, `ALERT_LOG`, and `PID_FILE` can be absolute paths. If they are relative, they are created in the project directory.
- `CHECK_INTERVAL` controls how often the daemon checks for expired bans.
- `WEBSHELL_SCAN_INTERVAL` controls how often the daemon rescans web roots.
- `TRUSTED_IPS` are never banned by the daemon or the CLI.

## Quick Start

```bash
git clone https://github.com/netkr/mini-hids.git
cd mini-hids
```

Adjust `config.json`, then start the daemon:

```bash
sudo python3 mini_hids.py
```

Use the CLI:

```bash
python3 hids_cli.py --action status
python3 hids_cli.py --action get_alerts --lines 20
python3 hids_cli.py --action get_blacklist
python3 hids_cli.py --action ban --ip 192.168.1.100 --reason "manual ban"
python3 hids_cli.py --action unban --ip 192.168.1.100
```

## CLI Output

All CLI commands return JSON. Example:

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

## Security Notes

- Run the daemon as root if you need firewall enforcement or access to privileged logs.
- Keep `config.json` permissions restrictive if you add sensitive paths or future secrets.
- Review `TRUSTED_IPS` carefully to avoid locking out legitimate operators.
- Web attack and webshell detection are heuristic. Treat alerts as signals, not final verdicts.

## Limitations

- Detection is regex-based and intentionally simple.
- The project does not yet ship with systemd service files or automated tests.
- `nftables` support is implemented through a dedicated `mini_hids` table and timeout-enabled sets, so existing custom firewall policies should still be reviewed before production use.

## Runtime Files

- `blacklist.db`: SQLite state store
- `hids_alert.log`: alert log
- `mini_hids.pid`: daemon PID file

## Recommended Next Steps

- Add replayable sample logs and regression tests
- Add a systemd unit and logrotate examples
- Extend web attack patterns with per-service profiles
- Add structured alert delivery such as webhook or syslog forwarding
