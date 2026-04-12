# Lightweight Host Intrusion Detection and Log Analysis System (Mini-HIDS)

## Security and Permissions

### Why Root Privileges Are Needed
- **Firewall Management**: Root privileges are required to execute firewall commands (iptables, nftables, or fail2ban) to block and unblock malicious IPs
- **Log Access**: Some system log files (e.g., /var/log/auth.log) require root access to read
- **System Monitoring**: Access to system information (e.g., /proc/loadavg) may require elevated privileges

### API Key Handling
- **Optional Configuration**: API Key is optional - the system can run without AI analysis capabilities
- **Security Recommendation**: Use environment variables to store API Key instead of hardcoding it in the Python file
  ```bash
  # Example: Set environment variables
  export MINI_HIDS_API_KEY="sk-xxxxxxxxxxxxxxxx"
  export MINI_HIDS_BASE_URL="https://api.your-provider.com/v1"
  
  # Then modify mini_hids.py to use environment variables
  import os
  LLM_CONFIG = {
      "API_KEY": os.environ.get("MINI_HIDS_API_KEY", ""),
      "BASE_URL": os.environ.get("MINI_HIDS_BASE_URL", ""),
      "MODEL_NAME": "gpt-4-turbo",
      "ENABLED": bool(os.environ.get("MINI_HIDS_API_KEY", "")),
      "COOLDOWN_MINUTES": 60
  }
  ```
- **File Permissions**: Ensure configuration files have permissions set to `600` to prevent API Key leakage

### System Paths Accessed
- **Log Files**: /var/log/auth.log, /var/log/secure, /var/log/nginx/access.log, /var/log/apache2/access.log, /var/log/mysql/mysql.log, /var/log/mysql/error.log
- **System Information**: /proc/loadavg
- **Web Directories**: /var/www/html, /var/www (for Webshell scanning)
- **Local Files**: hids_alert.log, blacklist.db, mini_hids.pid

## Project Introduction

Mini-HIDS is a zero-dependency, intelligent Linux server defense tool based on Python native libraries. It uses a C/S (Client/Server) architecture to achieve minute-level handling capabilities for brute force attacks and Webshells.

**Architecture Overview**
- **mini_hids.py** (Data Plane / Background Daemon): Runs 7×24 hours, responsible for underlying monitoring and automatic defense
- **hids_cli.py** (Control Plane / Agent-specific Interface): Command-line tool for Agent calls, returns standard JSON format immediately after execution

**Installation Methods**
1. **Traditional deployment**: Deploy to a cloud server via git, run the daemon and use the CLI tool for management
2. **Agent integration**: Send the project link to an agent (such as openclaw, hermes agent), and tell it to "package this project into a skill" and authorize it;

## Core Features

- **Real-time Log Monitoring**: Supports `tail -F` logic, based on Inode monitoring to achieve log rotation compatibility
- **Sliding Window Counter**: Uses sliding window algorithm to detect slow brute force attacks
- **Dual-track Defense**: Fast track (immediate blocking) and intelligent track (AI analysis)
- **Brute Force Attack Detection**: Automatically detects SSH brute force attacks and blocks malicious IPs
- **Web Attack Detection**: Detects SQL injection, XSS and other web attacks
- **Webshell Scanning**: Incremental scanning of web root directories, reducing I/O load
- **AI Intelligent Analysis**: Integrates large model analysis capabilities to provide professional security recommendations
- **Dynamic Blocking**: Supports setting blocking time, automatically unblocks after expiration
- **Whitelist Exemption**: Ensures administrator IPs are never intercepted
- **State Persistence**: Uses SQLite database to store ban times, ensuring rules persist after system restart
- **Webhook Integration**: Supports sending alerts to external systems via webhook
- **Regular Expression Pre-compilation**: Improves performance by pre-compiling all regex patterns
- **Secure Command Execution**: Uses subprocess.run() for secure firewall command execution

## Quick Start

### Environment Requirements

- Python 3.6+
- Linux system
- Firewall (iptables, nftables, or fail2ban)

### Installation and Running

1. **Clone the project**
   ```bash
   git clone https://github.com/netkr/mini-hids.git
   cd mini-hids
   ```

2. **Modify system configuration**
   Edit the `mini_hids.py` file, adjust the configuration according to your server environment:
   ```python
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
   ```

3. **Run the background daemon**
   ```bash
   sudo python3 mini_hids.py
   ```

4. **Use the CLI tool**
   ```bash
   # Check system status
   python3 hids_cli.py --action status
   
   # Get recent alerts
   python3 hids_cli.py --action get_alerts --lines 20
   
   # Get current blacklist
   python3 hids_cli.py --action get_blacklist
   
   # Manually ban an IP
   python3 hids_cli.py --action ban --ip 192.168.1.100 --reason "Manual ban"
   
   # Manually unban an IP
   python3 hids_cli.py --action unban --ip 192.168.1.100
   ```

## Configuration Instructions

### Core Configuration Items

- **LOG_PATHS**: Paths to log files that need to be monitored
- **BAN_TIME**: IP blocking time (seconds)
- **TRUSTED_IPS**: Whitelist IP list
- **WEB_ROOT**: Web root directory path, used for Webshell scanning
- **BAN_TIME**: IP blocking time (seconds)
- **MAX_FAILURES**: Maximum number of failures, exceeding this value will trigger blocking

### AI Configuration Items

- **API_KEY**: Large model API key
- **BASE_URL**: Large model API address
- **MODEL_NAME**: Model name used
- **ENABLED**: Whether to enable AI analysis
- **COOLDOWN_MINUTES**: AI analysis cooldown time (minutes)

## Logs and Alerts

- **hids_alert.log**: System alert logs
- **blacklist.db**: Blacklist database

## Security Recommendations

1. **Permission Settings**: Ensure configuration file permissions are `600` to prevent API Key leakage
2. **Regular Updates**: Regularly update the Webshell signature database
3. **Whitelist Management**: Properly configure whitelist to avoid false blocking
4. **Monitoring Frequency**: Adjust monitoring frequency based on server load

## Notes

- This system requires root privileges to run in order to execute firewall commands
- Necessary directories and files will be automatically created during the first run
- The system will run in the background, ensuring single instance operation through PID files

## Version History

- v1.0: Major optimization and enhancement
  - Implemented sliding window counter for slow brute force detection
  - Added dual-track defense system (fast track + intelligent track)
  - Enhanced AI strategy parsing with Markdown code block support
  - Implemented incremental Webshell scanning to reduce I/O load
  - Optimized regex performance with pre-compilation
  - Improved command execution security with subprocess.run()
  - Enhanced API URL parsing with urllib.parse
  - Added state persistence using SQLite database
  - Added Webhook integration for external alerting
  - Added comprehensive security and permissions documentation
- v0.2: Implemented core features