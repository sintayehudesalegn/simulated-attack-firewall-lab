"""Verifies the firewall classifies each simulated attack from packet content alone."""
import unittest

from lab.detector import Firewall
from lab.simulator import SCENARIOS, make_packet

VICTIM, ATTACKER = "196.102.21.5", "10.66.6.6"

EXPECTED = {
    "dos_http_flood": "DoS", "dos_syn_flood": "DoS", "dos_udp_flood": "DoS",
    "dos_icmp_flood": "DoS", "dos_slowloris": "DoS",
    "scan_syn": "Network Scan", "scan_common_ports": "Network Scan", "scan_xmas": "Network Scan",
    "scan_null": "Network Scan", "scan_fin": "Network Scan", "scan_udp": "Network Scan",
    "scan_nmap_nse": "Network Scan", "scan_nikto": "Network Scan", "scan_sqlmap": "Network Scan",
    "scan_dirb": "Network Scan",
    "bf_ssh": "Brute Force", "bf_http": "Brute Force", "bf_ftp": "Brute Force",
    "bf_mysql": "Brute Force", "bf_stuffing": "Brute Force",
    "pl_sqli_union": "Payload", "pl_sqli_bool": "Payload", "pl_sqli_time": "Payload",
    "pl_xss_script": "Payload", "pl_xss_event": "Payload", "pl_traversal": "Payload",
    "pl_cmdi": "Payload", "pl_lfi_php": "Payload", "pl_log4shell": "Payload",
    "pl_shellshock": "Payload", "pl_ssti": "Payload", "pl_xxe": "Payload", "pl_ssrf": "Payload",
    "pl_eicar": "Malware", "pl_fake_malware": "Malware", "pl_c2_beacon": "Malware",
    "other_dns_tunnel": "Other", "other_smuggling": "Other",
}


def run(key, dst=VICTIM, fw=None):
    fw = fw or Firewall()
    t, out = 1_000_000.0, []
    for step in SCENARIOS[key].build(dst):
        t += step.delay
        out.append(fw.inspect(make_packet(ATTACKER, dst, step, ts=t)))
    return out


class LabTests(unittest.TestCase):
    def test_every_scenario_is_covered(self):
        self.assertEqual(set(SCENARIOS), set(EXPECTED) | {"other_benign"})

    def test_each_attack_is_classified_from_content(self):
        for key, cat in EXPECTED.items():
            with self.subTest(scenario=key):
                blocked = [v for v in run(key) if v["action"] == "BLOCKED"]
                self.assertTrue(blocked, "nothing blocked")
                self.assertEqual({v["category"] for v in blocked}, {cat}, blocked[0]["detection"])

    def test_packets_do_not_reveal_attack_name(self):
        for key, scen in SCENARIOS.items():
            pkt = make_packet(ATTACKER, VICTIM, scen.build(VICTIM)[0])
            self.assertNotIn(key, str(pkt))
            self.assertNotIn("scenario", pkt)

    def test_benign_not_blocked(self):
        self.assertFalse([v for v in run("other_benign") if v["action"] == "BLOCKED"])

    def test_out_of_range_ignored(self):
        v = run("pl_sqli_union", dst="8.8.8.8")
        self.assertTrue(all(x["action"] == "IGNORED" for x in v))

    def test_range_boundaries(self):
        fw = Firewall()
        for ip, expected in (("196.102.21.0", "BLOCKED"), ("196.102.21.13", "BLOCKED"),
                             ("196.102.21.14", "IGNORED")):
            v = run("pl_xss_script", dst=ip, fw=fw)[0]
            self.assertEqual(v["action"], expected, ip)


if __name__ == "__main__":
    unittest.main()
