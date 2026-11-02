from types import SimpleNamespace
import unittest
from unittest.mock import patch

from custos.resource_rules import matches, validate_rule


class ResourceRuleTests(unittest.TestCase):
    def setUp(self):
        self.vm = SimpleNamespace(inventory_name="APP-WEB-01", remote_system_id="vc",
                                  primary_ip="192.0.2.1", tags={"env": "dev"})

    def test_name_regex_and_combined_rules(self):
        self.assertTrue(matches({"name_regex": r"^APP-(WEB|DB)-\d+$", "tags": {"env": "dev"}}, self.vm))
        self.assertFalse(matches({"name_regex": "^DB-"}, self.vm))
        self.assertFalse(matches({"name_regex": "^APP-", "subnet": "10.0.0.0/8"}, self.vm))

    def test_subnet_uses_secondary_ipv4_and_ipv6(self):
        self.assertTrue(matches({"subnet": "10.20.30.0/24"}, self.vm, ["10.20.30.9"]))
        self.assertTrue(matches({"subnet": "2001:db8::/64"}, self.vm, ["2001:db8::8"]))
        self.assertFalse(matches({"subnet": "2001:db8::/64"}, self.vm))

    def test_ranges_include_endpoints_and_same_ip_satisfies_conditions(self):
        rule = {"ip_range": {"start": "10.0.0.10", "end": "10.0.0.20"}}
        for ip in ["10.0.0.10", "10.0.0.20"]:
            self.assertTrue(matches(rule, self.vm, [ip]))
        self.assertFalse(matches(rule, self.vm, ["10.0.0.21"]))
        self.assertFalse(matches({**rule, "subnet": "192.0.2.0/24"}, self.vm, ["10.0.0.10"]))

    def test_malformed_rules_denied(self):
        for rule in [{}, {"name_regex": "["}, {"subnet": "10.1.2.3/24"},
                     {"ip_range": {"start": "10.0.0.9", "end": "10.0.0.1"}},
                     {"ip_range": {"start": "::1", "end": "192.0.2.1"}}, {"execute": "true"}]:
            with self.subTest(rule=rule):
                with self.assertRaises(ValueError):
                    validate_rule(rule)
                self.assertFalse(matches(rule, self.vm))

    def test_regex_timeout_denies_match(self):
        with patch("custos.resource_rules.regex.search", side_effect=TimeoutError):
            self.assertFalse(matches({"name_regex": "APP"}, self.vm))
