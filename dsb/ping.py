"""Cross-platform concurrent live ping and packet-loss probing for Deadlock relay servers."""

from __future__ import annotations

import inspect
import os
import re
import socket
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable

from dsb.sdr import DEFAULT_SDR_PORT

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


def is_fake_tun_icmp(stdout: str) -> bool:
    """Return True if ICMP ping stdout reflects a local sub-1ms fake TUN proxy echo."""
    rtt_match = _LINUX_RTT_RE.search(stdout)
    if rtt_match:
        return float(rtt_match.group(1)) < 1.0

    win_min = _WIN_MIN_RE.search(stdout)
    if win_min:
        return int(win_min.group(1)) == 0

    packet_times = _PACKET_TIME_RE.findall(stdout)
    if packet_times:
        return all((op == "<" and int(val) <= 1) or int(val) == 0 for op, val in packet_times)

    return False


def probe_udp_relay(
    ip: str,
    port: int = DEFAULT_SDR_PORT,
    *,
    first_timeout: float = 1.8,
    timeout: float = 1.0,
    gap: float = 0.25,
    socket_factory: Callable[..., Any] = socket.socket,
    sleep_fn: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> tuple[list[float], int]:
    """Send lightweight UDP SDR probes on one reused socket, capped at <= 2 Valve replies."""
    sock = socket_factory(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        def _send_once(wait_s: float) -> float | None:
            sock.settimeout(wait_s)
            payload = b"\x00" + os.urandom(31)
            t0 = clock()
            try:
                sock.sendto(payload, (ip, port))
                _data, addr = sock.recvfrom(1024)
            except (socket.timeout, OSError):
                return None
            if addr and addr[0] == ip:
                return max(0.0, (clock() - t0) * 1000.0)
            return None

        rtt0 = _send_once(first_timeout)
        sleep_fn(gap)
        rtt1 = _send_once(timeout)

        if rtt0 is not None:
            rtts = [rtt0]
            if rtt1 is not None:
                rtts.append(rtt1)
            return rtts, 2

        if rtt1 is None:
            return [], 2

        # Cold-dial probe #0 timed out while #1 succeeded; take one warm follow-up
        # probe so proxy setup latency does not report false steady-state packet loss.
        sleep_fn(gap)
        rtt2 = _send_once(timeout)
        rtts = [rtt1]
        if rtt2 is not None:
            rtts.append(rtt2)
        return rtts, 2
    finally:
        sock.close()


def probe_server_udp(
    ips: list[str],
    relay_ports: dict[str, int] | None = None,
    *,
    relay_prober: Callable[[str, int], tuple[list[float], int]] = probe_udp_relay,
    max_relays: int = 2,
    max_candidates: int = 4,
) -> dict[str, Any]:
    """Probe up to max_relays responsive SDR relays over UDP for RTT and packet loss."""
    ports = relay_ports or {}
    all_rtts: list[float] = []
    total_sent = 0
    total_recv = 0
    responsive_relays = 0
    consecutive_dead = 0
    best_ip: str | None = None
    best_ip_rtt: float | None = None

    for ip in ips[:max_candidates]:
        port = ports.get(ip, DEFAULT_SDR_PORT)
        try:
            rtts, sent = relay_prober(ip, port)
        except Exception:
            rtts, sent = [], 2

        if rtts:
            responsive_relays += 1
            consecutive_dead = 0
            all_rtts.extend(rtts)
            total_sent += sent
            total_recv += len(rtts)
            relay_min = min(rtts)
            if best_ip_rtt is None or relay_min < best_ip_rtt:
                best_ip_rtt = relay_min
                best_ip = ip
            if responsive_relays >= max_relays:
                break
        else:
            consecutive_dead += 1
            if responsive_relays == 0 and consecutive_dead >= 3:
                break

    if not all_rtts or total_sent <= 0:
        return {"ping_ms": None, "loss": 100, "ip": None}

    ping_ms = max(1, int(round(min(all_rtts))))
    loss = max(0, min(100, int(round(((total_sent - total_recv) / total_sent) * 100))))
    return {"ping_ms": ping_ms, "loss": loss, "ip": best_ip}


def probe_server_icmp(
    ips: list[str],
    count: int = 4,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    platform: str | None = None,
    reject_fake_tun: bool = True,
) -> dict[str, Any]:
    """Probe up to 2 relay IPs via ICMP ping and return the best ping_ms and packet loss."""
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
            if reject_fake_tun and is_fake_tun_icmp(res.stdout):
                ping_ms, loss = None, 100
            else:
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


def probe_server(
    ips: list[str],
    count: int = 4,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    platform: str | None = None,
    relay_ports: dict[str, int] | None = None,
    udp_prober: Callable[..., dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Probe relay IPs over UDP first (SDR), falling back to non-TUN ICMP ping."""
    udp_fn = udp_prober or probe_server_udp
    udp_res = udp_fn(ips, relay_ports=relay_ports)
    if udp_res.get("ping_ms") is not None:
        return udp_res
    return probe_server_icmp(
        ips,
        count=max(1, min(count, 2)),
        runner=runner,
        platform=platform,
        reject_fake_tun=True,
    )


class PingManager:
    """Thread-pooled probe scheduler with generation tracking and thread-safe telemetry."""

    def __init__(
        self,
        max_workers: int = 12,
        prober: Callable[..., dict[str, Any]] = probe_server,
    ):
        self._executor = ThreadPoolExecutor(max_workers=max_workers)
        self._prober = prober
        self._prober_accepts_ports = self._supports_relay_ports(prober)
        self._lock = threading.Lock()
        self._generation = 0
        self._pending_count = 0
        self._results: dict[str, dict[str, Any]] = {}

    @staticmethod
    def _supports_relay_ports(prober: Callable[..., Any]) -> bool:
        try:
            sig = inspect.signature(prober)
        except (TypeError, ValueError):
            return False
        return any(
            name == "relay_ports" or p.kind == inspect.Parameter.VAR_KEYWORD
            for name, p in sig.parameters.items()
        )

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
            ports = dict(srv.get("relay_ports") or {})
            self._executor.submit(self._run_one, gen, srv["id"], list(srv["ips"]), ports)

    def probe_single(
        self,
        server_id: str,
        ips: list[str],
        relay_ports: dict[str, int] | None = None,
    ) -> None:
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

        ports = dict(relay_ports) if relay_ports else None
        self._executor.submit(self._run_one, gen, server_id, list(ips), ports)

    def _run_one(
        self,
        gen: int,
        server_id: str,
        ips: list[str],
        relay_ports: dict[str, int] | None = None,
    ) -> None:
        try:
            if self._prober_accepts_ports:
                outcome = self._prober(ips, relay_ports=relay_ports)
            else:
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
