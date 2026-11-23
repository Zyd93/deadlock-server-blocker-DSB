"""Valve Deadlock Steam Datagram Relay (SDR) fetcher and parser."""

from __future__ import annotations

import ipaddress
import json
import re
import urllib.request
from pathlib import Path
from typing import Any

from dsb.config import get_config_dir

DEADLOCK_APP_ID = 1422450
DEFAULT_SDR_PORT = 27015
SDR_URL = f"https://api.steampowered.com/ISteamApps/GetSDRConfig/v1/?appid={DEADLOCK_APP_ID}"
CLUSTER_KEYWORDS = ("China", "Hong Kong", "Sweden", "India", "Netherlands")

REGION_ORDER = (
    "Europe",
    "North America",
    "South America",
    "Asia",
    "Middle East",
    "Oceania",
    "Africa",
    "Other",
)

_REGION_POP_IDS: tuple[tuple[str, frozenset[str]], ...] = (
    ("Europe", frozenset({"ams", "dfra", "dlhr", "dvie", "fra", "lhr", "mad", "par", "sto", "sto2", "vie", "waw", "hel", "lux", "mil"})),
    ("North America", frozenset({"atl", "dfw", "iad", "lax", "ord", "sea", "jfk", "mia", "den", "sjc", "eat", "yyz", "yul"})),
    ("South America", frozenset({"eze", "gru", "lim", "scl", "bog"})),
    ("Asia", frozenset({"bom", "bom2", "maa", "maa2", "hkg", "hkg4", "seo", "sgp", "tyo", "tyo1", "tyo2", "osa", "tpe"})),
    ("Middle East", frozenset({"dfjr", "dxb", "ruh", "doh", "bah"})),
    ("Oceania", frozenset({"gum", "syd", "mel", "akl"})),
    ("Africa", frozenset({"jnb", "cpt", "cai"})),
)

_REGION_KEYWORDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("Europe", ("germany", "netherlands", "england", "united kingdom", "austria", "spain", "france", "sweden", "poland", "finland", "italy", "ireland", "switzerland", "czech", "romania", "luxembourg", "norway", "denmark", "belgium", "portugal", "greece", "europe")),
    ("North America", ("atlanta", "georgia", "texas", "virginia", "california", "illinois", "washington", "new york", "florida", "colorado", "arizona", "oregon", "canada", "mexico", "united states", "north america")),
    ("South America", ("argentina", "brazil", "peru", "chile", "colombia", "uruguay", "ecuador", "south america")),
    ("Asia", ("india", "hong kong", "south korea", "korea", "singapore", "japan", "china", "taiwan", "philippines", "thailand", "vietnam", "indonesia", "malaysia", "asia")),
    ("Middle East", ("uae", "united arab emirates", "dubai", "fujairah", "saudi", "qatar", "doha", "bahrain", "kuwait", "oman", "israel", "middle east")),
    ("Oceania", ("australia", "guam", "new zealand", "sydney", "melbourne", "auckland", "oceania")),
    ("Africa", ("south africa", "johannesburg", "cape town", "egypt", "cairo", "kenya", "nigeria", "africa")),
)

DEFAULT_CACHE_PATH = get_config_dir() / "sdr_cache.json"

_DESC_PAREN_RE = re.compile(r"^(.*?)\s*\(([^()]+)\)\s*$")


def classify_region(pop_id: str, full_desc: str) -> str:
    """Classify a Valve SDR PoP or cluster into a continent/region group."""
    pid = pop_id.strip().lower()
    if pid:
        for region, ids in _REGION_POP_IDS:
            if pid in ids:
                return region

    desc_low = full_desc.strip().lower()
    if desc_low:
        for region, keywords in _REGION_KEYWORDS:
            if any(kw in desc_low for kw in keywords):
                return region

    return "Other"


def _parse_description(desc: str, pop_id: str) -> tuple[str, str]:
    """Split a Valve SDR description such as 'Frankfurt (Germany)' into (name, region)."""
    cleaned = desc.strip() or pop_id.upper()
    match = _DESC_PAREN_RE.match(cleaned)
    if match:
        name = match.group(1).strip()
        region = match.group(2).strip()
        if name:
            return name, region
    return cleaned, pop_id.upper()


def _parse_relay_port(port_range: Any) -> int:
    """Return the starting UDP port from a relay port_range or DEFAULT_SDR_PORT."""
    if isinstance(port_range, list) and port_range:
        raw_port = port_range[0]
        if not isinstance(raw_port, bool):
            try:
                port = int(raw_port)
                if 1 <= port <= 65535:
                    return port
            except (TypeError, ValueError):
                pass
    return DEFAULT_SDR_PORT


def _extract_valid_relays(relays: list[Any]) -> tuple[list[str], dict[str, int]]:
    """Return unique valid IPv4 strings and first-seen UDP ports from a PoP relay list."""
    seen: set[str] = set()
    ips: list[str] = []
    relay_ports: dict[str, int] = {}
    for relay in relays:
        if not isinstance(relay, dict):
            continue
        raw = relay.get("ipv4")
        if not raw:
            continue
        try:
            ip = str(ipaddress.IPv4Address(str(raw).strip()))
        except ValueError:
            continue
        if ip not in seen:
            seen.add(ip)
            ips.append(ip)
            relay_ports[ip] = _parse_relay_port(relay.get("port_range"))
    return ips, relay_ports


def _extract_valid_ips(relays: list[Any]) -> list[str]:
    """Return unique valid IPv4 strings from a PoP relay list preserving order."""
    ips, _ = _extract_valid_relays(relays)
    return ips


def parse_sdr_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Parse Valve GetSDRConfig JSON payload into unclustered and clustered server lists."""
    revision = str(payload.get("revision", ""))
    pops = payload.get("pops")
    if not isinstance(pops, dict):
        raise ValueError("Invalid SDR payload: missing 'pops' dictionary")

    unclustered: list[dict[str, Any]] = []
    clustered_map: dict[str, dict[str, Any]] = {}
    clustered_list: list[dict[str, Any]] = []

    for pop_id, pop_data in pops.items():
        if not isinstance(pop_data, dict):
            continue
        relays = pop_data.get("relays")
        if not isinstance(relays, list) or not relays:
            continue

        ips, relay_ports = _extract_valid_relays(relays)
        if not ips:
            continue

        full_desc = str(pop_data.get("desc") or pop_id).strip()
        name, region = _parse_description(full_desc, str(pop_id))

        server_entry = {
            "id": str(pop_id),
            "name": name,
            "region": region,
            "group": classify_region(str(pop_id), full_desc),
            "full_desc": full_desc,
            "ips": ips,
            "relay_ports": relay_ports,
            "member_ids": [str(pop_id)],
        }
        unclustered.append(server_entry)

        matched_kw = next((kw for kw in CLUSTER_KEYWORDS if kw in full_desc), None)
        if matched_kw:
            cluster_id = f"cluster:{matched_kw.lower().replace(' ', '_')}"
            cluster_entry = clustered_map.get(cluster_id)
            if cluster_entry is None:
                cluster_entry = {
                    "id": cluster_id,
                    "name": matched_kw,
                    "region": "Cluster",
                    "group": classify_region("", matched_kw),
                    "full_desc": f"{matched_kw} (Cluster)",
                    "ips": [],
                    "relay_ports": {},
                    "member_ids": [],
                }
                clustered_map[cluster_id] = cluster_entry
                clustered_list.append(cluster_entry)

            existing_ips = set(cluster_entry["ips"])
            for ip in ips:
                if ip not in existing_ips:
                    existing_ips.add(ip)
                    cluster_entry["ips"].append(ip)
                    cluster_entry["relay_ports"][ip] = relay_ports.get(ip, DEFAULT_SDR_PORT)
            cluster_entry["member_ids"].append(str(pop_id))
        else:
            clustered_list.append(dict(server_entry))

    unclustered.sort(key=lambda s: (s["name"].lower(), s["id"].lower()))
    clustered_list.sort(key=lambda s: (s["name"].lower(), s["id"].lower()))

    return {
        "revision": revision,
        "unclustered": unclustered,
        "clustered": clustered_list,
    }


def fetch_deadlock_servers(
    cache_path: Path | None = None,
    timeout: float = 10.0,
) -> dict[str, Any]:
    """Fetch live Deadlock SDR servers from Valve API, falling back to local cache on error."""
    target_cache = cache_path or DEFAULT_CACHE_PATH
    req = urllib.request.Request(
        SDR_URL,
        headers={"User-Agent": "DeadlockServerBlocker-DSB/1.0"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw_bytes = resp.read()
        payload = json.loads(raw_bytes.decode("utf-8"))
        parsed = parse_sdr_payload(payload)
        target_cache.parent.mkdir(parents=True, exist_ok=True)
        target_cache.write_text(json.dumps(payload), encoding="utf-8")
        parsed["from_cache"] = False
        return parsed
    except Exception as exc:
        if target_cache.exists():
            payload = json.loads(target_cache.read_text(encoding="utf-8"))
            parsed = parse_sdr_payload(payload)
            parsed["from_cache"] = True
            parsed["cache_reason"] = str(exc)
            return parsed
        raise RuntimeError(f"Failed to fetch Deadlock server list: {exc}") from exc
