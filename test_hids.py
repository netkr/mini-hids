#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Mini-HIDS unit tests.
"""

import os
import sqlite3
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch

from hids_common import (
    FirewallManager,
    delete_blacklist_entry,
    execute_ban,
    execute_unban,
    init_db,
    list_blacklist_rows,
    load_config,
    parse_alert_line,
    purge_expired_blacklist_entries,
    upsert_blacklist_entry,
    validate_ban_request,
    validate_ip,
)


class TestValidateIP(unittest.TestCase):
    def test_valid_ipv4(self):
        self.assertTrue(validate_ip("192.168.1.1"))
        self.assertTrue(validate_ip("10.0.0.1"))
        self.assertTrue(validate_ip("8.8.8.8"))

    def test_valid_ipv6(self):
        self.assertTrue(validate_ip("::1"))
        self.assertTrue(validate_ip("fe80::1"))
        self.assertTrue(validate_ip("2001:db8::1"))

    def test_invalid_ip(self):
        self.assertFalse(validate_ip("not-an-ip"))
        self.assertFalse(validate_ip("256.256.256.256"))
        self.assertFalse(validate_ip(""))
        self.assertFalse(validate_ip("192.168.1"))


class TestConfigLoading(unittest.TestCase):
    def test_load_config_defaults(self):
        with patch("hids_common.BASE_DIR", tempfile.gettempdir()):
            config = load_config()
            self.assertIn("LOG_PATHS", config)
            self.assertIn("BAN_TIME", config)
            self.assertIn("TRUSTED_IPS", config)
            self.assertEqual(config["BAN_TIME"], 3600)

    def test_config_path_resolution(self):
        with patch("hids_common.BASE_DIR", tempfile.gettempdir()):
            config = load_config()
            self.assertTrue(os.path.isabs(config["BLACKLIST_DB"]))
            self.assertTrue(os.path.isabs(config["ALERT_LOG"]))
            self.assertTrue(os.path.isabs(config["PID_FILE"]))


class TestSQLiteOperations(unittest.TestCase):
    def setUp(self):
        self.db_fd, self.db_path = tempfile.mkstemp(suffix=".db")
        init_db(self.db_path)

    def tearDown(self):
        os.close(self.db_fd)
        os.unlink(self.db_path)

    def test_init_db_creates_table(self):
        with sqlite3.connect(self.db_path) as conn:
            tables = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
            table_names = [t[0] for t in tables]
            self.assertIn("blacklist", table_names)

    def test_upsert_and_list(self):
        upsert_blacklist_entry(self.db_path, "192.168.1.100", int(time.time()) + 3600, "test ban")
        rows = list_blacklist_rows(self.db_path)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][0], "192.168.1.100")
        self.assertEqual(rows[0][2], "test ban")

    def test_delete_entry(self):
        upsert_blacklist_entry(self.db_path, "192.168.1.100", int(time.time()) + 3600, "test")
        delete_blacklist_entry(self.db_path, "192.168.1.100")
        rows = list_blacklist_rows(self.db_path)
        self.assertEqual(len(rows), 0)

    def test_purge_expired(self):
        past_time = int(time.time()) - 100
        future_time = int(time.time()) + 3600
        upsert_blacklist_entry(self.db_path, "10.0.0.1", past_time, "expired")
        upsert_blacklist_entry(self.db_path, "10.0.0.2", future_time, "active")

        purged = purge_expired_blacklist_entries(self.db_path)
        self.assertEqual(purged, 1)

        rows = list_blacklist_rows(self.db_path)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][0], "10.0.0.2")


class TestValidateBanRequest(unittest.TestCase):
    def setUp(self):
        self.db_fd, self.db_path = tempfile.mkstemp(suffix=".db")
        init_db(self.db_path)

    def tearDown(self):
        os.close(self.db_fd)
        os.unlink(self.db_path)

    def test_invalid_ip(self):
        result = validate_ban_request("invalid", [], self.db_path)
        self.assertIsNotNone(result)
        self.assertFalse(result["success"])

    def test_trusted_ip(self):
        result = validate_ban_request("192.168.1.1", ["192.168.1.1"], self.db_path)
        self.assertIsNotNone(result)
        self.assertFalse(result["success"])

    def test_already_banned(self):
        future_time = int(time.time()) + 3600
        upsert_blacklist_entry(self.db_path, "10.0.0.1", future_time, "test")
        result = validate_ban_request("10.0.0.1", [], self.db_path)
        self.assertIsNotNone(result)
        self.assertTrue(result["success"])

    def test_valid_request(self):
        result = validate_ban_request("10.0.0.1", [], self.db_path)
        self.assertIsNone(result)


class TestExecuteBanUnban(unittest.TestCase):
    def setUp(self):
        self.db_fd, self.db_path = tempfile.mkstemp(suffix=".db")
        init_db(self.db_path)
        self.mock_firewall = MagicMock()

    def tearDown(self):
        os.close(self.db_fd)
        os.unlink(self.db_path)

    def test_execute_ban_success(self):
        expiry_time = execute_ban("10.0.0.1", "test", 3600, self.mock_firewall, self.db_path)
        self.assertGreater(expiry_time, int(time.time()))
        self.mock_firewall.ban_ip.assert_called_once_with("10.0.0.1", 3600)
        rows = list_blacklist_rows(self.db_path)
        self.assertEqual(len(rows), 1)

    def test_execute_ban_failure_rollback(self):
        self.mock_firewall.ban_ip.side_effect = RuntimeError("firewall error")
        with self.assertRaises(RuntimeError):
            execute_ban("10.0.0.1", "test", 3600, self.mock_firewall, self.db_path)
        self.mock_firewall.unban_ip.assert_called_once_with("10.0.0.1")

    def test_execute_unban_success(self):
        future_time = int(time.time()) + 3600
        upsert_blacklist_entry(self.db_path, "10.0.0.1", future_time, "test")
        result = execute_unban("10.0.0.1", self.mock_firewall, self.db_path)
        self.assertTrue(result)
        self.mock_firewall.unban_ip.assert_called_once_with("10.0.0.1")
        rows = list_blacklist_rows(self.db_path)
        self.assertEqual(len(rows), 0)

    def test_execute_unban_not_in_blacklist(self):
        result = execute_unban("10.0.0.1", self.mock_firewall, self.db_path)
        self.assertFalse(result)


class TestParseAlertLine(unittest.TestCase):
    def test_ssh_brute_force(self):
        line = "[2025-06-18 10:23:45] [SSH暴力破解] 检测到来自 192.168.1.100 的登录失败，已达到阈值"
        result = parse_alert_line(line)
        self.assertEqual(result["type"], "ssh_brute_force")
        self.assertEqual(result["ip"], "192.168.1.100")
        self.assertEqual(result["timestamp"], "2025-06-18 10:23:45")

    def test_web_attack(self):
        line = "[2025-06-18 10:23:45] [Web攻击] 检测到来自 10.0.0.1 的可能攻击: <script>，已达到阈值"
        result = parse_alert_line(line)
        self.assertEqual(result["type"], "web_attack")
        self.assertEqual(result["ip"], "10.0.0.1")

    def test_webshell(self):
        line = "[2025-06-18 10:23:45] [Webshell] 检测到可疑文件: /var/www/html/shell.php"
        result = parse_alert_line(line)
        self.assertEqual(result["type"], "webshell")

    def test_ban(self):
        line = "[2025-06-18 10:23:45] [封禁] IP 192.168.1.100 因 SSH暴力破解 被封禁"
        result = parse_alert_line(line)
        self.assertEqual(result["type"], "ban")
        self.assertEqual(result["ip"], "192.168.1.100")

    def test_system_event(self):
        line = "[2025-06-18 10:23:45] [监控启动] 开始监控 /var/log/auth.log"
        result = parse_alert_line(line)
        self.assertEqual(result["type"], "system")

    def test_error_event(self):
        line = "[2025-06-18 10:23:45] [错误] 执行封禁失败 10.0.0.1: permission denied"
        result = parse_alert_line(line)
        self.assertEqual(result["type"], "error")

    def test_raw_line(self):
        line = "unformatted log line"
        result = parse_alert_line(line)
        self.assertEqual(result["raw"], "unformatted log line")


if __name__ == "__main__":
    unittest.main()
