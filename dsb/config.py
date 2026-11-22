"""Persistent user preferences and server blocking presets."""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any


def get_config_dir() -> Path:
    """Return the per-user configuration directory for Linux or Windows."""
    if sys.platform == "win32":
        appdata = os.environ.get("APPDATA")
        base = Path(appdata) if appdata else (Path.home() / "AppData" / "Roaming")
        return base / "deadlock-server-blocker"
    return Path.home() / ".config" / "deadlock-server-blocker"


DEFAULT_CONFIG_PATH = get_config_dir() / "config.json"


class ConfigStore:
    """Loads and atomically saves cluster mode and named blocking presets."""

    def __init__(self, path: Path | None = None):
        self.path = path or DEFAULT_CONFIG_PATH
        self.data: dict[str, Any] = {
            "clustered": False,
            "active_preset": None,
            "presets": {},
        }
        self.load()

    def load(self) -> dict[str, Any]:
        if not self.path.exists():
            return self.data
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                self.data["clustered"] = bool(raw.get("clustered", False))
                active = raw.get("active_preset")
                self.data["active_preset"] = str(active) if isinstance(active, str) else None
                presets = raw.get("presets")
                if isinstance(presets, dict):
                    clean_presets: dict[str, dict[str, Any]] = {}
                    for name, entry in presets.items():
                        if isinstance(name, str) and isinstance(entry, dict):
                            ids = entry.get("blocked_ids", [])
                            clean_presets[name] = {
                                "clustered": bool(entry.get("clustered", False)),
                                "blocked_ids": [str(x) for x in ids if isinstance(x, str)],
                            }
                    self.data["presets"] = clean_presets
        except Exception:
            pass
        return self.data

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(self.data, indent=2)
        fd, tmp_name = tempfile.mkstemp(
            dir=str(self.path.parent),
            prefix=".config.",
            suffix=".tmp",
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(payload)
            os.replace(tmp_name, self.path)
        except Exception:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise

    @property
    def clustered(self) -> bool:
        return bool(self.data.get("clustered", False))

    @clustered.setter
    def clustered(self, value: bool) -> None:
        self.data["clustered"] = bool(value)

    @property
    def active_preset(self) -> str | None:
        val = self.data.get("active_preset")
        return val if isinstance(val, str) else None

    @active_preset.setter
    def active_preset(self, value: str | None) -> None:
        self.data["active_preset"] = value

    @property
    def presets(self) -> dict[str, dict[str, Any]]:
        return self.data["presets"]

    def save_preset(self, name: str, clustered: bool, blocked_ids: list[str]) -> None:
        clean_name = name.strip()
        if not clean_name:
            raise ValueError("Preset name cannot be empty")
        self.presets[clean_name] = {
            "clustered": bool(clustered),
            "blocked_ids": sorted(set(blocked_ids)),
        }
        self.active_preset = clean_name
        self.save()

    def delete_preset(self, name: str) -> None:
        self.presets.pop(name, None)
        if self.active_preset == name:
            self.active_preset = None
        self.save()
