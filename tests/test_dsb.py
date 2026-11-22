"""Unit and API tests for Deadlock Server Blocker - DSB."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
import urllib.request
from pathlib import Path
from unittest.mock import MagicMock

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from dsb.app import DSBBackend, start_http_server  # noqa: E402
from dsb.config import ConfigStore, get_config_dir  # noqa: E402
from dsb.firewall import (  # noqa: E402
    CHAIN_NAME,
    FirewallError,
    FirewallManager,
    WindowsFirewallManager,
)
from dsb.ping import PingManager, parse_ping_output  # noqa: E402
from dsb.sdr import classify_region, parse_sdr_payload  # noqa: E402


class FakeIptables:
    """In-memory mock of sudo + iptables -w 5 commands for deterministic firewall tests."""

    def __init__(self, initial_input: list[str] | None = None, sudo_ok: bool = True):
        self.sudo_ok = sudo_ok
        self.chains: dict[str, list[str]] = {
            "INPUT": list(initial_input or ["-A INPUT -j ufw-before-input"]),
        }
        self.calls: list[list[str]] = []

    def __call__(self, cmd: list[str], **_kwargs) -> subprocess.CompletedProcess[str]:
        self.calls.append(list(cmd))
        if cmd[:3] == ["/usr/bin/sudo", "-n", "-v"]:
            return subprocess.CompletedProcess(
                cmd, 0 if self.sudo_ok else 1, stdout="", stderr="" if self.sudo_ok else "sudo: a password is required\n"
            )

        if not self.sudo_ok:
            return subprocess.CompletedProcess(
                cmd, 1, stdout="", stderr="sudo: a password is required\n"
            )

        # Strip ['/usr/bin/sudo', '-n', '/usr/bin/iptables', '-w', '5']
        args = cmd[5:]
        op = args[0]

        if op == "-N":
            chain = args[1]
            if chain in self.chains:
                return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="iptables: Chain already exists.\n")
            self.chains[chain] = []
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        if op == "-S":
            chain = args[1]
            if chain not in self.chains:
                return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="iptables: No chain/target/match by that name.\n")
            header = f"-P {chain} ACCEPT" if chain == "INPUT" else f"-N {chain}"
            lines = [header, *self.chains[chain]]
            return subprocess.CompletedProcess(cmd, 0, stdout="\n".join(lines) + "\n", stderr="")

        if op == "-I":
            chain, pos, target_flag, target = args[1], int(args[2]), args[3], args[4]
            assert target_flag == "-j"
            self.chains[chain].insert(pos - 1, f"-A {chain} -j {target}")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        if op == "-A":
            chain = args[1]
            if chain not in self.chains:
                return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="iptables: No chain/target/match by that name.\n")
            if args[2] == "-s":
                for ip in args[3].split(","):
                    self.chains[chain].append(f"-A {chain} -s {ip}/32 -j DROP")
                return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
            return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="unsupported -A")

        if op == "-D":
            chain = args[1]
            if chain not in self.chains:
                return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="No chain")
            if args[2] == "-j":
                rule = f"-A {chain} -j {args[3]}"
            elif args[2] == "-s":
                ip = args[3]
                rule = f"-A {chain} -s {ip}/32 -j DROP"
            else:
                return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="unsupported -D")
            if rule in self.chains[chain]:
                self.chains[chain].remove(rule)
                return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
            return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="iptables: Bad rule (does a matching rule exist in that chain?).\n")

        if op == "-F":
            chain = args[1]
            if chain not in self.chains:
                return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="No chain")
            self.chains[chain] = []
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        if op == "-X":
            chain = args[1]
            if chain not in self.chains:
                return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="No chain")
            if self.chains[chain]:
                return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="Directory not empty")
            del self.chains[chain]
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        raise AssertionError(f"Unexpected iptables args: {args}")


class TestSDR(unittest.TestCase):
    def test_parse_sdr_payload_unclustered_and_clustered(self) -> None:
        sample = {
            "revision": 4242,
            "pops": {
                "fra": {
                    "desc": "Frankfurt (Germany)",
                    "relays": [{"ipv4": "155.133.226.68"}, {"ipv4": "155.133.226.68"}],
                },
                "sto": {
                    "desc": "Stockholm (Kista) (Sweden)",
                    "relays": [{"ipv4": "155.133.252.37"}],
                },
                "sto2": {
                    "desc": "Stockholm (Bromma) (Sweden)",
                    "relays": [{"ipv4": "155.133.252.38"}],
                },
                "empty_pop": {
                    "desc": "Broken PoP",
                    "relays": [],
                },
                "bad_ip_pop": {
                    "desc": "Invalid IP",
                    "relays": [{"ipv4": "not-an-ip"}],
                },
            },
        }
        parsed = parse_sdr_payload(sample)
        self.assertEqual(parsed["revision"], "4242")
        self.assertEqual([s["id"] for s in parsed["unclustered"]], ["fra", "sto2", "sto"])

        fra = parsed["unclustered"][0]
        self.assertEqual(fra["name"], "Frankfurt")
        self.assertEqual(fra["region"], "Germany")
        self.assertEqual(fra["ips"], ["155.133.226.68"])

        clustered_ids = [s["id"] for s in parsed["clustered"]]
        self.assertEqual(clustered_ids, ["fra", "cluster:sweden"])
        sweden = parsed["clustered"][1]
        self.assertEqual(sweden["ips"], ["155.133.252.37", "155.133.252.38"])
        self.assertEqual(sorted(sweden["member_ids"]), ["sto", "sto2"])
        self.assertEqual(fra["group"], "Europe")
        self.assertEqual(sweden["group"], "Europe")

    def test_classify_region_all_continents(self) -> None:
        cases = [
            ("fra", "Frankfurt (Germany)", "Europe"),
            ("dfra", "Datapacket Frankfurt (Germany)", "Europe"),
            ("sto", "Stockholm - Kista (Sweden)", "Europe"),
            ("atl", "Atlanta (Georgia)", "North America"),
            ("iad", "Sterling (Virginia)", "North America"),
            ("gru", "Sao Paulo (Brazil)", "South America"),
            ("bom2", "Mumbai (India)", "Asia"),
            ("tyo", "Tokyo Koto City (Japan)", "Asia"),
            ("sgp", "Singapore", "Asia"),
            ("dxb", "Dubai (United Arab Emirates)", "Middle East"),
            ("dfjr", "Datapacket Fujairah (UAE)", "Middle East"),
            ("syd", "Sydney (Australia)", "Oceania"),
            ("gum", "Guam", "Oceania"),
            ("jnb", "Johannesburg (South Africa)", "Africa"),
            ("", "India", "Asia"),
            ("", "Netherlands", "Europe"),
            ("", "China", "Asia"),
        ]
        for pop_id, desc, expected in cases:
            with self.subTest(pop_id=pop_id, desc=desc):
                self.assertEqual(classify_region(pop_id, desc), expected)


class TestFirewall(unittest.TestCase):
    def test_chain_inserted_before_ufw_and_repositioned(self) -> None:
        fake = FakeIptables(
            initial_input=[
                "-A INPUT -j ufw-before-input",
                f"-A INPUT -j {CHAIN_NAME}",
            ]
        )
        fw = FirewallManager(runner=fake)
        blocked = fw.block_ips(["155.133.226.68", "155.133.226.69"])

        self.assertEqual(blocked, {"155.133.226.68", "155.133.226.69"})
        self.assertEqual(fake.chains["INPUT"][0], f"-A INPUT -j {CHAIN_NAME}")
        self.assertEqual(fake.chains["INPUT"][1], "-A INPUT -j ufw-before-input")
        self.assertEqual(fake.chains["INPUT"].count(f"-A INPUT -j {CHAIN_NAME}"), 1)

        # Idempotent block does not duplicate rules
        fw.block_ips(["155.133.226.68"])
        self.assertEqual(len(fake.chains[CHAIN_NAME]), 2)

        # Unblock removes only specified IP
        remaining = fw.unblock_ips(["155.133.226.68"])
        self.assertEqual(remaining, {"155.133.226.69"})

    def test_reset_preserves_ufw_and_cleans_legacy_deadlock_rules(self) -> None:
        fake = FakeIptables(
            initial_input=[
                "-A INPUT -j ufw-before-input",
                "-A INPUT -s 155.133.246.34/32 -j DROP",
                "-A INPUT -s 192.168.1.50/32 -j DROP",
            ]
        )
        fw = FirewallManager(runner=fake)
        fw.block_ips(["155.133.226.68"])
        fw.reset_firewall(known_deadlock_ips=["155.133.246.34", "155.133.226.68"])

        self.assertNotIn(CHAIN_NAME, fake.chains)
        self.assertIn("-A INPUT -j ufw-before-input", fake.chains["INPUT"])
        self.assertIn("-A INPUT -s 192.168.1.50/32 -j DROP", fake.chains["INPUT"])
        self.assertNotIn("-A INPUT -s 155.133.246.34/32 -j DROP", fake.chains["INPUT"])
        # Ensure INPUT was never flushed directly
        self.assertFalse(any(c[5:] == ["-F", "INPUT"] for c in fake.calls))

    def test_invalid_ip_rejected(self) -> None:
        fw = FirewallManager(runner=FakeIptables())
        with self.assertRaises(FirewallError):
            fw.block_ips(["bad;rm -rf /"])


class FakeNetsh:
    """In-memory mock of Windows netsh advfirewall firewall commands."""

    def __init__(self, initial_rules: dict[str, list[str]] | None = None):
        self.rules: dict[str, list[str]] = dict(initial_rules or {})
        self.calls: list[list[str]] = []

    def __call__(self, cmd: list[str], **_kwargs) -> subprocess.CompletedProcess[str]:
        self.calls.append(list(cmd))
        # cmd: ['netsh', 'advfirewall', 'firewall', op, 'rule', ...]
        args = cmd[3:]
        op = args[0]

        if op == "show":
            name = args[2].split("=", 1)[1]
            if name not in self.rules:
                return subprocess.CompletedProcess(
                    cmd, 1, stdout="No rules match the specified criteria.\n", stderr=""
                )
            formatted = []
            for ip in self.rules[name]:
                formatted.append(ip if "-" in ip else f"{ip}/32")
            out = (
                f"Rule Name:                            {name}\n"
                f"Enabled:                              Yes\n"
                f"Direction:                            Out\n"
                f"LocalIP:                              Any\n"
                f"RemoteIP:                             {','.join(formatted)}\n"
                f"Action:                               Block\n"
            )
            return subprocess.CompletedProcess(cmd, 0, stdout=out, stderr="")

        if op == "add":
            kv = dict(item.split("=", 1) for item in args[2:])
            self.rules[kv["name"]] = kv["remoteip"].split(",")
            return subprocess.CompletedProcess(cmd, 0, stdout="Ok.\n", stderr="")

        if op == "delete":
            name = args[2].split("=", 1)[1]
            if name not in self.rules:
                return subprocess.CompletedProcess(
                    cmd, 1, stdout="No rules match the specified criteria.\n", stderr=""
                )
            del self.rules[name]
            return subprocess.CompletedProcess(cmd, 0, stdout="Ok.\n", stderr="")

        raise AssertionError(f"Unexpected netsh args: {args}")


class TestWindowsFirewall(unittest.TestCase):
    def test_block_unblock_batching_and_range_extraction(self) -> None:
        fake = FakeNetsh(
            initial_rules={
                "OtherAppRule": ["1.2.3.4"],
                f"{CHAIN_NAME}_0": ["155.133.252.84-155.133.252.86"],
            }
        )
        fw = WindowsFirewallManager(runner=fake, admin_checker=lambda: True)
        self.assertTrue(fw.check_sudo())
        self.assertEqual(
            fw.get_blocked_ips(),
            {"155.133.252.84", "155.133.252.85", "155.133.252.86"},
        )

        # Adding 45 more IPs splits across DSB_BLOCK_0 and DSB_BLOCK_1 without touching OtherAppRule
        extra = [f"155.133.10.{i}" for i in range(1, 46)]
        blocked = fw.block_ips(extra)
        self.assertEqual(len(blocked), 48)
        self.assertIn(f"{CHAIN_NAME}_0", fake.rules)
        self.assertIn(f"{CHAIN_NAME}_1", fake.rules)
        self.assertIn("OtherAppRule", fake.rules)

        # Unblock subset
        remaining = fw.unblock_ips(["155.133.252.85", "155.133.10.1"])
        self.assertEqual(len(remaining), 46)
        self.assertNotIn("155.133.252.85", remaining)

        # Reset deletes only DSB_BLOCK_* rules, never calls netsh advfirewall reset
        fw.reset_firewall()
        self.assertEqual(list(fake.rules.keys()), ["OtherAppRule"])
        self.assertFalse(any("reset" in c for c in fake.calls))

    def test_unprivileged_windows_rejects_mutation(self) -> None:
        fw = WindowsFirewallManager(runner=FakeNetsh(), admin_checker=lambda: False)
        self.assertFalse(fw.check_sudo())
        with self.assertRaises(FirewallError):
            fw.block_ips(["155.133.226.68"])


class TestPingAndConfig(unittest.TestCase):
    def test_parse_ping_output(self) -> None:
        ok_out = (
            "4 packets transmitted, 4 received, 0% packet loss, time 603ms\n"
            "rtt min/avg/max/mdev = 25.612/26.100/27.011/0.511 ms\n"
        )
        self.assertEqual(parse_ping_output(ok_out), (26, 0))

        partial_out = (
            "4 packets transmitted, 3 received, 25% packet loss, time 604ms\n"
            "rtt min/avg/max/mdev = 41.100/43.200/45.300/1.200 ms\n"
        )
        self.assertEqual(parse_ping_output(partial_out), (41, 25))

        drop_out = "4 packets transmitted, 0 received, 100% packet loss, time 3055ms\n"
        self.assertEqual(parse_ping_output(drop_out), (None, 100))

        win_ok = (
            "Pinging 155.133.226.68 with 32 bytes of data:\n"
            "Reply from 155.133.226.68: bytes=32 time=26ms TTL=53\n"
            "Reply from 155.133.226.68: bytes=32 time=25ms TTL=53\n"
            "Packets: Sent = 2, Received = 2, Lost = 0 (0% loss),\n"
            "Approximate round trip times in milli-seconds:\n"
            "    Minimum = 25ms, Maximum = 26ms, Average = 25ms\n"
        )
        self.assertEqual(parse_ping_output(win_ok), (25, 0))

        win_de = (
            "Antwort von 155.133.226.68: Bytes=32 Zeit=42ms TTL=53\n"
            "Antwort von 155.133.226.68: Bytes=32 Zeit<1ms TTL=53\n"
            "    Pakete: Gesendet = 4, Empfangen = 3, Verloren = 1\n"
            "    (25% Verlust),\n"
        )
        self.assertEqual(parse_ping_output(win_de), (1, 25))

        win_drop = "    Packets: Sent = 4, Received = 0, Lost = 4 (100% loss),\n"
        self.assertEqual(parse_ping_output(win_drop), (None, 100))

    def test_config_dir_and_presets_persistence(self) -> None:
        self.assertEqual(get_config_dir().name, "deadlock-server-blocker")
        with tempfile.TemporaryDirectory() as tmp:
            cfg_path = Path(tmp) / "config.json"
            store = ConfigStore(cfg_path)
            store.save_preset("EU Low", False, ["waw", "iad"])
            self.assertEqual(store.active_preset, "EU Low")

            reloaded = ConfigStore(cfg_path)
            self.assertEqual(reloaded.presets["EU Low"]["blocked_ids"], ["iad", "waw"])
            reloaded.delete_preset("EU Low")
            self.assertIsNone(reloaded.active_preset)
            self.assertEqual(reloaded.presets, {})


class TestBackendHTTP(unittest.TestCase):
    def test_http_endpoints_and_token_auth(self) -> None:
        sample_sdr = {
            "revision": 99,
            "pops": {
                "fra": {"desc": "Frankfurt (Germany)", "relays": [{"ipv4": "155.133.226.68"}]},
                "ams": {"desc": "Amsterdam (Netherlands)", "relays": [{"ipv4": "155.133.248.36"}]},
                "iad": {"desc": "Sterling (Virginia)", "relays": [{"ipv4": "162.254.192.88"}]},
            },
        }
        fake_fw = FakeIptables()
        mock_ping = MagicMock(spec=PingManager)
        mock_ping.get_snapshot.return_value = (
            {"fra": {"ping_ms": 26, "loss": 0, "probing": False}},
            False,
        )

        with tempfile.TemporaryDirectory() as tmp:
            backend = DSBBackend(
                firewall=FirewallManager(runner=fake_fw),
                ping_manager=mock_ping,
                config_store=ConfigStore(Path(tmp) / "cfg.json"),
                sdr_fetcher=lambda: parse_sdr_payload(sample_sdr) | {"from_cache": False},
            )
            httpd, port = start_http_server(backend)
            try:
                base = f"http://127.0.0.1:{port}"
                # HTML page injects token and /icon.png serves valid PNG
                html = urllib.request.urlopen(f"{base}/").read().decode("utf-8")
                self.assertIn(backend.api_token, html)
                self.assertNotIn("__DSB_TOKEN__", html)
                icon_bytes = urllib.request.urlopen(f"{base}/icon.png").read()
                self.assertTrue(icon_bytes.startswith(b"\x89PNG"))

                # State endpoint works and includes region group and platform
                state = json.loads(urllib.request.urlopen(f"{base}/api/state").read().decode("utf-8"))
                self.assertEqual(len(state["servers"]), 3)
                self.assertTrue(state["sudo_ready"])
                self.assertIn(state["platform"], ("linux", "windows"))
                groups = {s["id"]: s["group"] for s in state["servers"]}
                self.assertEqual(groups, {"ams": "Europe", "fra": "Europe", "iad": "North America"})

                # POST without token is rejected with 403
                bad_req = urllib.request.Request(
                    f"{base}/api/toggle",
                    data=json.dumps({"id": "fra", "blocked": True}).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with self.assertRaises(urllib.error.HTTPError) as ctx:
                    urllib.request.urlopen(bad_req)
                self.assertEqual(ctx.exception.code, 403)

                # Valid POST toggles fra in DSB_BLOCK and saves preset cleanly
                good_req = urllib.request.Request(
                    f"{base}/api/toggle",
                    data=json.dumps({"id": "fra", "blocked": True}).encode("utf-8"),
                    headers={
                        "Content-Type": "application/json",
                        "X-DSB-Token": backend.api_token,
                    },
                    method="POST",
                )
                toggled = json.loads(urllib.request.urlopen(good_req).read().decode("utf-8"))
                fra_row = next(s for s in toggled["servers"] if s["id"] == "fra")
                self.assertTrue(fra_row["blocked"])
                self.assertIn("155.133.226.68/32", fake_fw.chains[CHAIN_NAME][0])

                # Region-scoped bulk endpoint blocks iad without disturbing fra, then unblocks iad only
                bulk_block_req = urllib.request.Request(
                    f"{base}/api/bulk",
                    data=json.dumps({"ids": ["iad"], "blocked": True}).encode("utf-8"),
                    headers={
                        "Content-Type": "application/json",
                        "X-DSB-Token": backend.api_token,
                    },
                    method="POST",
                )
                bulk_blocked = json.loads(urllib.request.urlopen(bulk_block_req).read().decode("utf-8"))
                blocked_map = {s["id"]: s["blocked"] for s in bulk_blocked["servers"]}
                self.assertEqual(blocked_map, {"ams": False, "fra": True, "iad": True})

                bulk_unblock_req = urllib.request.Request(
                    f"{base}/api/bulk",
                    data=json.dumps({"ids": ["iad"], "blocked": False}).encode("utf-8"),
                    headers={
                        "Content-Type": "application/json",
                        "X-DSB-Token": backend.api_token,
                    },
                    method="POST",
                )
                bulk_unblocked = json.loads(urllib.request.urlopen(bulk_unblock_req).read().decode("utf-8"))
                unblocked_map = {s["id"]: s["blocked"] for s in bulk_unblocked["servers"]}
                self.assertEqual(unblocked_map, {"ams": False, "fra": True, "iad": False})

                # Save & apply preset
                save_req = urllib.request.Request(
                    f"{base}/api/presets/save",
                    data=json.dumps({"name": "No FRA"}).encode("utf-8"),
                    headers={
                        "Content-Type": "application/json",
                        "X-DSB-Token": backend.api_token,
                    },
                    method="POST",
                )
                saved = json.loads(urllib.request.urlopen(save_req).read().decode("utf-8"))
                self.assertEqual(saved["presets"], ["No FRA"])
                self.assertEqual(saved["active_preset"], "No FRA")
            finally:
                backend.shutdown()
                httpd.shutdown()
                httpd.server_close()


if __name__ == "__main__":
    unittest.main()
