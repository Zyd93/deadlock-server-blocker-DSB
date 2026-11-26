"""Cross-platform firewall manager for Linux (UFW-safe DSB_BLOCK) and Windows (netsh)."""

from __future__ import annotations

import ctypes
import ipaddress
import re
import subprocess
import sys
from typing import Callable, Iterable

from dsb import find_binary

CHAIN_NAME = "DSB_BLOCK"
_SUDO_BIN = find_binary("sudo", "/usr/bin/sudo")
_IPTABLES_BIN = find_binary("iptables", "/usr/bin/iptables")
_IPTABLES_RESTORE_BIN = find_binary("iptables-restore", "/usr/bin/iptables-restore")
_BATCH_SIZE = 40
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

_CHAIN_RULE_RE = re.compile(
    rf"^-A\s+{CHAIN_NAME}\s+-s\s+(\d+\.\d+\.\d+\.\d+)(?:/32)?\s+-j\s+DROP\s*$"
)
_INPUT_DROP_RE = re.compile(
    r"^-A\s+INPUT\s+-s\s+(\d+\.\d+\.\d+\.\d+)(?:/32)?\s+-j\s+DROP\s*$"
)
_IPV4_RANGE_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})-(\d{1,3}(?:\.\d{1,3}){3})\b")
_IPV4_SINGLE_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


class FirewallError(RuntimeError):
    """Raised when a firewall or elevation operation fails."""


def _validate_ipv4_list(ips: Iterable[str]) -> list[str]:
    """Validate and deduplicate IPv4 addresses in sorted order."""
    valid: set[str] = set()
    for raw in ips:
        try:
            valid.add(str(ipaddress.IPv4Address(str(raw).strip())))
        except ValueError as exc:
            raise FirewallError(f"Invalid IPv4 address: {raw!r}") from exc
    return sorted(valid)


def _is_sudo_auth_error(stderr: str) -> bool:
    low = stderr.lower()
    return "password is required" in low or "terminal is required" in low


def _is_windows_admin() -> bool:
    if sys.platform != "win32":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception:
        return False


class FirewallManager:
    """Manages Deadlock server packet drops on Linux in an isolated DSB_BLOCK chain ahead of UFW."""

    def __init__(self, runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run):
        self._runner = runner

    def _run_iptables(self, args: list[str]) -> subprocess.CompletedProcess[str]:
        cmd = [_SUDO_BIN, "-n", _IPTABLES_BIN, "-w", "5", *args]
        try:
            return self._runner(cmd, capture_output=True, text=True, check=False)
        except OSError as exc:
            raise FirewallError(f"Cannot run {_SUDO_BIN}/{_IPTABLES_BIN}: {exc}") from exc

    def _run_iptables_restore(self, rules: str) -> subprocess.CompletedProcess[str]:
        """Apply an iptables-restore script; with --noflush only chains it names change."""
        cmd = [_SUDO_BIN, "-n", _IPTABLES_RESTORE_BIN, "-w", "5", "--noflush"]
        try:
            return self._runner(cmd, input=rules, capture_output=True, text=True, check=False)
        except OSError as exc:
            raise FirewallError(f"Cannot run {_SUDO_BIN}/{_IPTABLES_RESTORE_BIN}: {exc}") from exc

    def check_sudo(self) -> bool:
        """Return True if non-interactive sudo credentials are currently valid."""
        try:
            res = self._runner([_SUDO_BIN, "-n", "-v"], capture_output=True, text=True, check=False)
        except OSError as exc:
            raise FirewallError(f"Cannot run {_SUDO_BIN}: {exc}") from exc
        return res.returncode == 0

    def ensure_chain(self) -> None:
        """Create DSB_BLOCK if missing and guarantee '-A INPUT -j DSB_BLOCK' is at INPUT #1."""
        create_res = self._run_iptables(["-N", CHAIN_NAME])
        if create_res.returncode != 0 and "chain already exists" not in create_res.stderr.lower():
            raise FirewallError(
                create_res.stderr.strip() or f"Failed to create chain {CHAIN_NAME}"
            )

        input_res = self._run_iptables(["-S", "INPUT"])
        if input_res.returncode != 0:
            raise FirewallError(input_res.stderr.strip() or "Failed to read iptables INPUT chain")

        rule_lines = [
            line.strip()
            for line in input_res.stdout.splitlines()
            if line.strip().startswith("-A INPUT ")
        ]
        target_rule = f"-A INPUT -j {CHAIN_NAME}"
        if rule_lines and rule_lines[0] == target_rule:
            return

        # Remove any existing DSB_BLOCK jumps lower in INPUT before inserting at position 1.
        for _ in range(16):
            del_res = self._run_iptables(["-D", "INPUT", "-j", CHAIN_NAME])
            if del_res.returncode != 0:
                break

        ins_res = self._run_iptables(["-I", "INPUT", "1", "-j", CHAIN_NAME])
        if ins_res.returncode != 0:
            raise FirewallError(
                ins_res.stderr.strip() or f"Failed to insert {CHAIN_NAME} at INPUT position 1"
            )

    def get_blocked_ips(self, strict: bool = False) -> set[str]:
        """Return all IPv4 addresses currently dropped in DSB_BLOCK."""
        res = self._run_iptables(["-S", CHAIN_NAME])
        if res.returncode != 0:
            stderr = res.stderr.strip()
            if "no chain/target/match by that name" in stderr.lower():
                return set()
            if not strict:
                return set()
            raise FirewallError(stderr or f"Failed to query {CHAIN_NAME}")

        blocked: set[str] = set()
        for line in res.stdout.splitlines():
            match = _CHAIN_RULE_RE.match(line.strip())
            if match:
                blocked.add(match.group(1))
        return blocked

    def _append_batched(self, ips: list[str]) -> None:
        for i in range(0, len(ips), _BATCH_SIZE):
            batch = ips[i : i + _BATCH_SIZE]
            csv_ips = ",".join(batch)
            res = self._run_iptables(["-A", CHAIN_NAME, "-s", csv_ips, "-j", "DROP"])
            if res.returncode != 0:
                raise FirewallError(
                    res.stderr.strip() or f"Failed to add DROP rule for {csv_ips}"
                )

    def block_ips(self, ips: Iterable[str]) -> set[str]:
        """Ensure target IPs are blocked in DSB_BLOCK without duplicating existing rules."""
        target = set(_validate_ipv4_list(ips))
        if not target:
            return self.get_blocked_ips(strict=True)
        self.ensure_chain()
        current = self.get_blocked_ips(strict=True)
        missing = sorted(target - current)
        if missing:
            self._append_batched(missing)
        return self.get_blocked_ips(strict=True)

    def unblock_ips(self, ips: Iterable[str]) -> set[str]:
        """Remove target IPs from DSB_BLOCK if currently present."""
        target = set(_validate_ipv4_list(ips))
        if not target:
            return self.get_blocked_ips(strict=True)
        current = self.get_blocked_ips(strict=True)
        to_remove = sorted(current & target)
        for ip in to_remove:
            for _ in range(16):
                res = self._run_iptables(["-D", CHAIN_NAME, "-s", ip, "-j", "DROP"])
                if res.returncode != 0:
                    break
        return self.get_blocked_ips(strict=True)

    def set_blocked_ips(self, target_ips: Iterable[str]) -> set[str]:
        """Replace DSB_BLOCK rules with exactly target_ips without touching INPUT or UFW."""
        desired = _validate_ipv4_list(target_ips)
        self.ensure_chain()
        # One iptables-restore transaction: the chain is emptied and refilled
        # atomically, so relays are never briefly unblocked and a failure
        # leaves the previous block list fully in place.
        lines = ["*filter", f":{CHAIN_NAME} - [0:0]"]
        for i in range(0, len(desired), _BATCH_SIZE):
            batch = ",".join(desired[i : i + _BATCH_SIZE])
            lines.append(f"-A {CHAIN_NAME} -s {batch} -j DROP")
        lines.append("COMMIT")
        res = self._run_iptables_restore("\n".join(lines) + "\n")
        if res.returncode != 0:
            raise FirewallError(res.stderr.strip() or f"Failed to replace {CHAIN_NAME} rules")
        return self.get_blocked_ips(strict=True)

    def reset_firewall(self, known_deadlock_ips: Iterable[str] | None = None) -> set[str]:
        """Remove DSB_BLOCK and optional known Deadlock INPUT drops without flushing UFW."""
        chain_res = self._run_iptables(["-S", CHAIN_NAME])
        if chain_res.returncode != 0 and _is_sudo_auth_error(chain_res.stderr):
            raise FirewallError(chain_res.stderr.strip())

        if chain_res.returncode == 0:
            flush_res = self._run_iptables(["-F", CHAIN_NAME])
            if flush_res.returncode != 0:
                raise FirewallError(flush_res.stderr.strip() or f"Failed to flush {CHAIN_NAME}")

        for _ in range(16):
            del_jump = self._run_iptables(["-D", "INPUT", "-j", CHAIN_NAME])
            if del_jump.returncode != 0:
                break

        if chain_res.returncode == 0:
            del_chain = self._run_iptables(["-X", CHAIN_NAME])
            if del_chain.returncode != 0 and "no chain" not in del_chain.stderr.lower():
                raise FirewallError(del_chain.stderr.strip() or f"Failed to delete {CHAIN_NAME}")

        # Clean up any legacy direct-INPUT DROP rules for known Deadlock IPs (never flush INPUT).
        if known_deadlock_ips:
            known_set = set(_validate_ipv4_list(known_deadlock_ips))
            input_res = self._run_iptables(["-S", "INPUT"])
            if input_res.returncode == 0:
                legacy_ips: set[str] = set()
                for line in input_res.stdout.splitlines():
                    match = _INPUT_DROP_RE.match(line.strip())
                    if match and match.group(1) in known_set:
                        legacy_ips.add(match.group(1))
                for ip in sorted(legacy_ips):
                    for _ in range(16):
                        rm_res = self._run_iptables(["-D", "INPUT", "-s", ip, "-j", "DROP"])
                        if rm_res.returncode != 0:
                            break

        return set()


LinuxFirewallManager = FirewallManager


class WindowsFirewallManager:
    """Manages Deadlock outbound packet blocks in Windows Defender Firewall via netsh."""

    def __init__(
        self,
        runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
        admin_checker: Callable[[], bool] = _is_windows_admin,
    ):
        self._runner = runner
        self._admin_checker = admin_checker

    def _run_netsh(self, args: list[str]) -> subprocess.CompletedProcess[str]:
        cmd = ["netsh", "advfirewall", "firewall", *args]
        return self._runner(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            creationflags=_NO_WINDOW,
        )

    def check_sudo(self) -> bool:
        """Return True if the current Windows process has Administrator privileges."""
        return bool(self._admin_checker())

    @staticmethod
    def _extract_ips_from_output(output: str) -> set[str]:
        ips: set[str] = set()
        # Handle compressed ranges (e.g. 155.133.252.84-155.133.252.89) emitted by netsh.
        for start_raw, end_raw in _IPV4_RANGE_RE.findall(output):
            try:
                start_ip = ipaddress.IPv4Address(start_raw)
                end_ip = ipaddress.IPv4Address(end_raw)
            except ValueError:
                continue
            start_int, end_int = int(start_ip), int(end_ip)
            if 0 <= (end_int - start_int) <= 4096:
                for val in range(start_int, end_int + 1):
                    ips.add(str(ipaddress.IPv4Address(val)))

        for ip_raw in _IPV4_SINGLE_RE.findall(output):
            try:
                ips.add(str(ipaddress.IPv4Address(ip_raw)))
            except ValueError:
                continue
        return ips

    def get_blocked_ips(self, strict: bool = False) -> set[str]:
        """Return all IPv4 addresses currently blocked by DSB_BLOCK_* Windows Firewall rules."""
        blocked: set[str] = set()
        for idx in range(64):
            rule_name = f"{CHAIN_NAME}_{idx}"
            res = self._run_netsh(["show", "rule", f"name={rule_name}"])
            if res.returncode != 0:
                break
            blocked.update(self._extract_ips_from_output(res.stdout))

        legacy = self._run_netsh(["show", "rule", f"name={CHAIN_NAME}"])
        if legacy.returncode == 0:
            blocked.update(self._extract_ips_from_output(legacy.stdout))
        elif strict and not self.check_sudo():
            raise FirewallError("Administrator privileges required to query Windows Firewall rules.")

        return blocked

    def _delete_dsb_rules(self) -> None:
        for idx in range(64):
            rule_name = f"{CHAIN_NAME}_{idx}"
            show_res = self._run_netsh(["show", "rule", f"name={rule_name}"])
            if show_res.returncode != 0:
                break
            del_res = self._run_netsh(["delete", "rule", f"name={rule_name}"])
            if del_res.returncode != 0:
                msg = (del_res.stderr or del_res.stdout).strip()
                raise FirewallError(msg or f"Failed to delete Windows Firewall rule {rule_name}")

        legacy = self._run_netsh(["show", "rule", f"name={CHAIN_NAME}"])
        if legacy.returncode == 0:
            del_legacy = self._run_netsh(["delete", "rule", f"name={CHAIN_NAME}"])
            if del_legacy.returncode != 0:
                msg = (del_legacy.stderr or del_legacy.stdout).strip()
                raise FirewallError(msg or f"Failed to delete Windows Firewall rule {CHAIN_NAME}")

    def block_ips(self, ips: Iterable[str]) -> set[str]:
        """Ensure target IPs are blocked in Windows Firewall without disturbing other rules."""
        target = set(_validate_ipv4_list(ips))
        if not target:
            return self.get_blocked_ips()
        current = self.get_blocked_ips()
        return self.set_blocked_ips(current | target)

    def unblock_ips(self, ips: Iterable[str]) -> set[str]:
        """Remove target IPs from DSB Windows Firewall block rules."""
        target = set(_validate_ipv4_list(ips))
        if not target:
            return self.get_blocked_ips()
        current = self.get_blocked_ips()
        return self.set_blocked_ips(current - target)

    def set_blocked_ips(self, target_ips: Iterable[str]) -> set[str]:
        """Replace DSB_BLOCK_* rules with exactly target_ips without touching other firewall rules."""
        desired = _validate_ipv4_list(target_ips)
        if not self.check_sudo():
            raise FirewallError("Administrator privileges required to modify Windows Firewall rules.")

        self._delete_dsb_rules()

        for idx, start in enumerate(range(0, len(desired), _BATCH_SIZE)):
            batch = desired[start : start + _BATCH_SIZE]
            rule_name = f"{CHAIN_NAME}_{idx}"
            res = self._run_netsh(
                [
                    "add",
                    "rule",
                    f"name={rule_name}",
                    "dir=out",
                    "action=block",
                    "profile=any",
                    "enable=yes",
                    f"remoteip={','.join(batch)}",
                ]
            )
            if res.returncode != 0:
                msg = (res.stderr or res.stdout).strip()
                raise FirewallError(msg or f"Failed to create Windows Firewall rule {rule_name}")

        return set(desired)

    def reset_firewall(self, known_deadlock_ips: Iterable[str] | None = None) -> set[str]:
        """Remove only DSB_BLOCK_* Windows Firewall rules (never calls netsh advfirewall reset)."""
        if not self.check_sudo():
            raise FirewallError("Administrator privileges required to reset Windows Firewall rules.")
        self._delete_dsb_rules()
        return set()


def create_firewall_manager() -> FirewallManager | WindowsFirewallManager:
    """Instantiate the appropriate firewall manager for the current operating system."""
    if sys.platform == "win32":
        return WindowsFirewallManager()
    return FirewallManager()
