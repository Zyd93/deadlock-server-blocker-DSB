"""Cross-platform concurrent live ping and packet-loss probing for Deadlock relay servers."""

from __future__ import annotations

import re
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable

_LINUX_PING_BIN = "/usr/bin/ping"
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

_LINUX_LOSS_RE = re.compile(r"(\d+(?:\.\d+)?)%\s+packet loss")
_WIN_LOSS_RE = re.compile(r"\(\s*(\d+(?:\.\d+)?)%[^)]*\)")
_LINUX_RTT_RE = re.compile(r"=\s*([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)\s*ms")
_WIN_MIN_RE = re.compile(r"Minimum\s*=\s*(\d+)\s*ms", re.IGNORECASE)
_PACKET_TIME_RE = re.compile(r"([=<])\s*(\d+)\s*ms", re.IGNORECASE)


def parse_ping_output(stdout: str) -> tuple[int | None, int]:
    """Parse Linux or Windows ping stdout into (min_ping_ms_or_none, packet_loss_percent)."""
    loss_match = _LINUX_LOSS_RE.search(stdout) or _WIN_LOSS_RE.search(stdout)
    loss = int(round(float(loss_match.group(1)))) if loss_match else 100
    loss = max(0, min(100, loss))

    if loss >= 100:
        return None, 100

    rtt_match = _LINUX_RTT_RE.search(stdout)
    if rtt_match:
        return int(round(float(rtt_match.group(1)))), loss

    win_min = _WIN_MIN_RE.search(stdout)
    if win_min:
        return int(win_min.group(1)), loss

    packet_times = [
        1 if (op == "<" and int(val) <= 1) else int(val)
        for op, val in _PACKET_TIME_RE.findall(stdout)
    ]
    if packet_times:
        return min(packet_times), loss

    return None, loss


def probe_server(
    ips: list[str],
    count: int = 4,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    platform: str | None = None,
) -> dict[str, Any]:
    """Probe up to 2 relay IPs and return the best ping_ms and packet loss."""
    target_platform = platform or sys.platform
    candidates = ips[:2]
    best_result: dict[str, Any] = {"ping_ms": None, "loss": 100, "ip": None}

    for ip in candidates:
        try:
            if target_platform == "win32":
                res = runner(
                    ["ping", "-n", str(count), "-w", "1000", ip],
                    capture_output=True,
                    text=True,
                    timeout=8,
                    check=False,
                    creationflags=_NO_WINDOW,
                )
            else:
                res = runner(
                    [_LINUX_PING_BIN, "-n", "-c", str(count), "-i", "0.2", "-W", "1", ip],
                    capture_output=True,
                    text=True,
                    timeout=6,
                    check=False,
                )
            ping_ms, loss = parse_ping_output(res.stdout)
        except Exception:
            ping_ms, loss = None, 100

        if ping_ms is not None and (
            best_result["ping_ms"] is None or ping_ms < best_result["ping_ms"]
        ):
            best_result = {"ping_ms": ping_ms, "loss": loss, "ip": ip}

        # Stop early on a healthy zero-loss probe of the primary relay.
        if ping_ms is not None and loss == 0:
            break

    return best_result


class PingManager:
    """Thread-pooled probe scheduler with generation tracking and thread-safe telemetry."""

    def __init__(
        self,
        max_workers: int = 20,
        prober: Callable[[list[str]], dict[str, Any]] = probe_server,
    ):
        self._executor = ThreadPoolExecutor(max_workers=max_workers)
        self._prober = prober
        self._lock = threading.Lock()
        self._generation = 0
        self._pending_count = 0
        self._results: dict[str, dict[str, Any]] = {}

    def refresh_all(self, servers: list[dict[str, Any]]) -> None:
        """Start asynchronous ping/packet-loss probes for all given servers."""
        with self._lock:
            self._generation += 1
            gen = self._generation
            self._pending_count = len(servers)
            for srv in servers:
                prev = self._results.get(srv["id"], {})
                self._results[srv["id"]] = {
                    "ping_ms": prev.get("ping_ms"),
                    "loss": prev.get("loss", 0),
                    "probing": True,
                }

        for srv in servers:
            self._executor.submit(self._run_one, gen, srv["id"], list(srv["ips"]))

    def probe_single(self, server_id: str, ips: list[str]) -> None:
        """Quickly re-probe a single server (e.g., right after toggling block state)."""
        with self._lock:
            gen = self._generation
            prev = self._results.get(server_id, {})
            self._results[server_id] = {
                "ping_ms": prev.get("ping_ms"),
                "loss": prev.get("loss", 0),
                "probing": True,
            }
            self._pending_count += 1

        self._executor.submit(self._run_one, gen, server_id, list(ips))

    def _run_one(self, gen: int, server_id: str, ips: list[str]) -> None:
        try:
            outcome = self._prober(ips)
        except Exception:
            outcome = {"ping_ms": None, "loss": 100, "ip": None}

        with self._lock:
            if gen == self._generation:
                self._results[server_id] = {
                    "ping_ms": outcome.get("ping_ms"),
                    "loss": outcome.get("loss", 100),
                    "probing": False,
                }
                self._pending_count = max(0, self._pending_count - 1)

    def get_snapshot(self) -> tuple[dict[str, dict[str, Any]], bool]:
        """Return (per_server_metrics_copy, is_any_probe_running)."""
        with self._lock:
            copy = {k: dict(v) for k, v in self._results.items()}
            return copy, self._pending_count > 0

    def shutdown(self) -> None:
        with self._lock:
            self._generation += 1
            self._pending_count = 0
        self._executor.shutdown(wait=False, cancel_futures=True)
