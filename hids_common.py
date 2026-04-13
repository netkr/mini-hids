#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Mini-HIDS shared helpers.
"""

import json
import os
import shutil
import socket
import sqlite3
import subprocess
import time


BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DEFAULT_CONFIG = {
    "LOG_PATHS": {
        "auth": ["/var/log/auth.log", "/var/log/secure"],
        "web": ["/var/log/nginx/access.log", "/var/log/apache2/access.log"],
        "mysql": ["/var/log/mysql/mysql.log", "/var/log/mysql/error.log"],
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
    "WEBSHELL_SCAN_INTERVAL": 3600,
}


def _deep_merge(defaults, overrides):
    merged = dict(defaults)
    for key, value in overrides.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def resolve_path(path_value):
    if os.path.isabs(path_value):
        return path_value
    return os.path.join(BASE_DIR, path_value)


def load_config():
    config = dict(DEFAULT_CONFIG)
    config_path = os.path.join(BASE_DIR, "config.json")

    if os.path.exists(config_path):
        with open(config_path, "r", encoding="utf-8") as config_file:
            loaded = json.load(config_file)
        config = _deep_merge(config, loaded)

    for path_key in ("BLACKLIST_DB", "ALERT_LOG", "PID_FILE"):
        config[path_key] = resolve_path(config[path_key])

    return config


def validate_ip(ip):
    try:
        socket.inet_pton(socket.AF_INET, ip)
        return True
    except OSError:
        try:
            socket.inet_pton(socket.AF_INET6, ip)
            return True
        except OSError:
            return False


def is_ipv6(ip):
    try:
        socket.inet_pton(socket.AF_INET6, ip)
        return True
    except OSError:
        return False


def detect_firewall():
    if shutil.which("iptables"):
        return "iptables"
    if shutil.which("nft"):
        return "nftables"
    if shutil.which("fail2ban-client"):
        return "fail2ban"
    return None


def ensure_parent_dir(path_value):
    parent = os.path.dirname(path_value)
    if parent:
        os.makedirs(parent, exist_ok=True)


def init_db(db_path):
    ensure_parent_dir(db_path)
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS blacklist (
                ip TEXT PRIMARY KEY,
                ban_time INTEGER NOT NULL,
                reason TEXT NOT NULL
            )
            """
        )
        conn.commit()


def list_blacklist_rows(db_path):
    if not os.path.exists(db_path):
        return []

    with sqlite3.connect(db_path) as conn:
        return conn.execute(
            "SELECT ip, ban_time, reason FROM blacklist ORDER BY ban_time ASC"
        ).fetchall()


def upsert_blacklist_entry(db_path, ip, ban_time, reason):
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO blacklist (ip, ban_time, reason) VALUES (?, ?, ?)",
            (ip, ban_time, reason),
        )
        conn.commit()


def delete_blacklist_entry(db_path, ip):
    with sqlite3.connect(db_path) as conn:
        conn.execute("DELETE FROM blacklist WHERE ip = ?", (ip,))
        conn.commit()


def purge_expired_blacklist_entries(db_path, current_time=None):
    if not os.path.exists(db_path):
        return 0

    if current_time is None:
        current_time = int(time.time())

    with sqlite3.connect(db_path) as conn:
        cursor = conn.execute("DELETE FROM blacklist WHERE ban_time <= ?", (current_time,))
        conn.commit()
        return cursor.rowcount


class FirewallManager:
    def __init__(self, backend=None):
        self.backend = backend or detect_firewall()

    def _run(self, command, check=True):
        return subprocess.run(
            command,
            check=check,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    def _capture(self, command):
        return subprocess.run(
            command,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )

    def _iptables_binary(self, ip):
        if is_ipv6(ip):
            return "ip6tables" if shutil.which("ip6tables") else None
        return "iptables" if shutil.which("iptables") else None

    def _iptables_rule_exists(self, ip):
        binary = self._iptables_binary(ip)
        if not binary:
            return False
        result = self._run([binary, "-C", "INPUT", "-s", ip, "-j", "DROP"], check=False)
        return result.returncode == 0

    def _ensure_nft_structure(self, ip):
        family = "ip6" if is_ipv6(ip) else "ip"
        set_name = "blocked_ipv6" if is_ipv6(ip) else "blocked_ipv4"
        addr_type = "ipv6_addr" if is_ipv6(ip) else "ipv4_addr"
        ruleset = self._capture(["nft", "list", "table", family, "mini_hids"]).stdout

        self._run(["nft", "add", "table", family, "mini_hids"], check=False)
        if "chain input {" not in ruleset:
            self._run(
                [
                    "nft",
                    "add",
                    "chain",
                    family,
                    "mini_hids",
                    "input",
                    "{",
                    "type",
                    "filter",
                    "hook",
                    "input",
                    "priority",
                    "0",
                    ";",
                    "}",
                ],
                check=False,
            )
        if f"set {set_name} " not in ruleset:
            self._run(
                [
                    "nft",
                    "add",
                    "set",
                    family,
                    "mini_hids",
                    set_name,
                    "{",
                    "type",
                    addr_type,
                    ";",
                    "flags",
                    "timeout",
                    ";",
                    "}",
                ],
                check=False,
            )
        if f"{family} saddr @{set_name} drop" not in ruleset:
            rule = [family, "saddr", "@{}".format(set_name), "drop"]
            self._run(["nft", "add", "rule", family, "mini_hids", "input"] + rule, check=False)
        return family, set_name

    def ban_ip(self, ip, duration):
        if self.backend == "iptables":
            binary = self._iptables_binary(ip)
            if not binary:
                raise RuntimeError("iptables backend is unavailable for this IP family")
            if self._iptables_rule_exists(ip):
                return
            self._run([binary, "-A", "INPUT", "-s", ip, "-j", "DROP"])
            return

        if self.backend == "nftables":
            family, set_name = self._ensure_nft_structure(ip)
            timeout = "{}s".format(int(duration))
            self._run(
                [
                    "nft",
                    "add",
                    "element",
                    family,
                    "mini_hids",
                    set_name,
                    "{",
                    "{} timeout {}".format(ip, timeout),
                    "}",
                ]
            )
            return

        if self.backend == "fail2ban":
            self._run(["fail2ban-client", "set", "sshd", "banip", ip])
            return

        raise RuntimeError("no supported firewall backend found")

    def unban_ip(self, ip):
        if self.backend == "iptables":
            binary = self._iptables_binary(ip)
            if not binary:
                raise RuntimeError("iptables backend is unavailable for this IP family")
            while self._iptables_rule_exists(ip):
                self._run([binary, "-D", "INPUT", "-s", ip, "-j", "DROP"])
            return

        if self.backend == "nftables":
            family, set_name = self._ensure_nft_structure(ip)
            self._run(
                ["nft", "delete", "element", family, "mini_hids", set_name, "{", ip, "}"],
                check=False,
            )
            return

        if self.backend == "fail2ban":
            self._run(["fail2ban-client", "set", "sshd", "unbanip", ip], check=False)
            return

        raise RuntimeError("no supported firewall backend found")
