"""Local HTTP backend and cross-platform desktop window for Deadlock Server Blocker - DSB."""

from __future__ import annotations

import ctypes
import hmac
import json
import os
import secrets
import shutil
import subprocess
import sys
import threading
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

PROJECT_ROOT = Path(__file__).resolve().parent.parent
BUNDLE_ROOT = Path(getattr(sys, "_MEIPASS", PROJECT_ROOT))
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from dsb import APP_NAME, VERSION  # noqa: E402
from dsb.config import ConfigStore  # noqa: E402
from dsb.firewall import (  # noqa: E402
    FirewallError,
    FirewallManager,
    WindowsFirewallManager,
    create_firewall_manager,
)
from dsb.ping import PingManager  # noqa: E402
from dsb.sdr import fetch_deadlock_servers  # noqa: E402


class DSBBackend:
    """Thread-safe coordinator between Valve SDR data, DSB_BLOCK firewall rules, and pings."""

    def __init__(
        self,
        firewall: FirewallManager | WindowsFirewallManager | None = None,
        ping_manager: PingManager | None = None,
        config_store: ConfigStore | None = None,
        sdr_fetcher=fetch_deadlock_servers,
        ui_dir: Path | None = None,
        assets_dir: Path | None = None,
    ):
        self.firewall = firewall or create_firewall_manager()
        self.ping_manager = ping_manager or PingManager()
        self.config = config_store or ConfigStore()
        self._sdr_fetcher = sdr_fetcher
        self.ui_dir = ui_dir or (BUNDLE_ROOT / "ui")
        self.assets_dir = assets_dir or (BUNDLE_ROOT / "assets")
        self.api_token = secrets.token_hex(24)
        self._op_lock = threading.Lock()

        self.sdr_data: dict[str, Any] = {
            "revision": "",
            "unclustered": [],
            "clustered": [],
            "from_cache": False,
        }
        self.sdr_error: str | None = None
        self.reload_sdr(start_ping=False)

    def reload_sdr(self, start_ping: bool = True) -> None:
        try:
            self.sdr_data = self._sdr_fetcher()
            self.sdr_error = None
        except Exception as exc:
            self.sdr_error = str(exc)
            if not self.sdr_data["unclustered"]:
                self.sdr_data = {
                    "revision": "",
                    "unclustered": [],
                    "clustered": [],
                    "from_cache": False,
                }
        if start_ping and self._active_servers():
            self.ping_manager.refresh_all(self._active_servers())

    def _active_servers(self) -> list[dict[str, Any]]:
        key = "clustered" if self.config.clustered else "unclustered"
        return list(self.sdr_data.get(key, []))

    def _all_known_ips(self) -> list[str]:
        seen: set[str] = set()
        result: list[str] = []
        for srv in self.sdr_data.get("unclustered", []):
            for ip in srv.get("ips", []):
                if ip not in seen:
                    seen.add(ip)
                    result.append(ip)
        return result

    def get_state(self) -> dict[str, Any]:
        sudo_ready = False
        blocked_ips: set[str] = set()
        blocked_known = False
        blocked_error: str | None = None
        try:
            sudo_ready = self.firewall.check_sudo()
            if sudo_ready:
                blocked_ips = self.firewall.get_blocked_ips(strict=True)
                blocked_known = True
            else:
                blocked_error = "Cannot read the firewall: sudo/administrator access is not available."
        except FirewallError as exc:
            blocked_error = str(exc)
        ping_map, ping_running = self.ping_manager.get_snapshot()

        servers_out: list[dict[str, Any]] = []
        for srv in self._active_servers():
            ips = srv.get("ips", [])
            is_blocked = bool(ips) and all(ip in blocked_ips for ip in ips)
            metrics = ping_map.get(srv["id"], {})
            servers_out.append(
                {
                    "id": srv["id"],
                    "name": srv["name"],
                    "region": srv["region"],
                    "group": srv.get("group", "Other"),
                    "full_desc": srv["full_desc"],
                    "ips": ips,
                    "blocked": is_blocked,
                    "ping_ms": metrics.get("ping_ms"),
                    "loss": metrics.get("loss", 0),
                    "probing": bool(metrics.get("probing", False)),
                }
            )

        return {
            "version": VERSION,
            "servers": servers_out,
            "clustered": self.config.clustered,
            "presets": sorted(self.config.presets.keys()),
            "active_preset": self.config.active_preset,
            "revision": self.sdr_data.get("revision", ""),
            "from_cache": bool(self.sdr_data.get("from_cache", False)),
            "sdr_error": self.sdr_error,
            "sudo_ready": sudo_ready,
            "blocked_known": blocked_known,
            "blocked_error": blocked_error,
            "ping_running": ping_running,
            "platform": "windows" if sys.platform == "win32" else "linux",
        }

    def toggle_server(self, server_id: str, blocked: bool) -> dict[str, Any]:
        with self._op_lock:
            target = next((s for s in self._active_servers() if s["id"] == server_id), None)
            if target is None:
                raise ValueError(f"Unknown server ID: {server_id}")

            ips = target.get("ips", [])
            if blocked:
                self.firewall.block_ips(ips)
            else:
                self.firewall.unblock_ips(ips)

            self.config.active_preset = None
            self.config.save()
            self.ping_manager.probe_single(
                target["id"], ips, relay_ports=target.get("relay_ports")
            )
            return self.get_state()

    def bulk_set(self, server_ids: list[str], blocked: bool) -> dict[str, Any]:
        with self._op_lock:
            wanted = {str(sid) for sid in server_ids}
            targets = [s for s in self._active_servers() if s["id"] in wanted]
            if not targets:
                return self.get_state()

            seen_ips: set[str] = set()
            ips: list[str] = []
            for srv in targets:
                for ip in srv.get("ips", []):
                    if ip not in seen_ips:
                        seen_ips.add(ip)
                        ips.append(ip)

            if blocked:
                self.firewall.block_ips(ips)
            else:
                self.firewall.unblock_ips(ips)

            self.config.active_preset = None
            self.config.save()

            if len(targets) > 6:
                self.ping_manager.refresh_all(targets)
            else:
                for srv in targets:
                    self.ping_manager.probe_single(
                        srv["id"],
                        srv.get("ips", []),
                        relay_ports=srv.get("relay_ports"),
                    )
            return self.get_state()

    def block_all(self) -> dict[str, Any]:
        with self._op_lock:
            all_ips = self._all_known_ips()
            self.firewall.set_blocked_ips(all_ips)
            self.config.active_preset = None
            self.config.save()
            servers = self._active_servers()
            if servers:
                self.ping_manager.refresh_all(servers)
            return self.get_state()

    def unblock_all(self) -> dict[str, Any]:
        with self._op_lock:
            self.firewall.set_blocked_ips([])
            self.config.active_preset = None
            self.config.save()
            servers = self._active_servers()
            if servers:
                self.ping_manager.refresh_all(servers)
            return self.get_state()

    def reset_firewall(self) -> dict[str, Any]:
        with self._op_lock:
            self.firewall.reset_firewall(self._all_known_ips())
            self.config.active_preset = None
            self.config.save()
            servers = self._active_servers()
            if servers:
                self.ping_manager.refresh_all(servers)
            return self.get_state()

    def set_clustered(self, clustered: bool) -> dict[str, Any]:
        with self._op_lock:
            changed = self.config.clustered != bool(clustered)
            self.config.clustered = bool(clustered)
            if changed:
                self.config.active_preset = None
                self.config.save()
                servers = self._active_servers()
                if servers:
                    self.ping_manager.refresh_all(servers)
            return self.get_state()

    def refresh(self, reload_sdr: bool = False) -> dict[str, Any]:
        with self._op_lock:
            if reload_sdr or self.sdr_error or not self._active_servers():
                self.reload_sdr(start_ping=True)
            else:
                self.ping_manager.refresh_all(self._active_servers())
            return self.get_state()

    def save_preset(self, name: str) -> dict[str, Any]:
        with self._op_lock:
            state = self.get_state()
            if not state["blocked_known"]:
                raise FirewallError(
                    state["blocked_error"]
                    or "Cannot read the current firewall state, so the preset was not saved."
                )
            blocked_ids = [s["id"] for s in state["servers"] if s["blocked"]]
            self.config.save_preset(name, self.config.clustered, blocked_ids)
            return self.get_state()

    def apply_preset(self, name: str) -> dict[str, Any]:
        with self._op_lock:
            preset = self.config.presets.get(name)
            if preset is None:
                raise ValueError(f"Unknown preset: {name}")

            clustered = bool(preset.get("clustered", False))
            blocked_set = set(preset.get("blocked_ids", []))
            key = "clustered" if clustered else "unclustered"
            servers = list(self.sdr_data.get(key, []))
            target_ips: list[str] = []
            for srv in servers:
                if srv["id"] in blocked_set:
                    target_ips.extend(srv.get("ips", []))

            # Firewall first: if it fails, config stays untouched.
            self.firewall.set_blocked_ips(target_ips)
            self.config.clustered = clustered
            self.config.active_preset = name
            self.config.save()
            if servers:
                self.ping_manager.refresh_all(servers)
            return self.get_state()

    def delete_preset(self, name: str) -> dict[str, Any]:
        with self._op_lock:
            if name not in self.config.presets:
                raise ValueError(f"Unknown preset: {name}")
            self.config.delete_preset(name)
            return self.get_state()

    def shutdown(self) -> None:
        self.ping_manager.shutdown()


def make_handler(backend: DSBBackend):
    """Build an HTTP request handler bound to a DSBBackend instance."""

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: Any) -> None:
            return

        def _send_bytes(self, status: int, content_type: str, body: bytes) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _send_json(self, status: int, data: dict[str, Any]) -> None:
            raw = json.dumps(data).encode("utf-8")
            self._send_bytes(status, "application/json; charset=utf-8", raw)

        def _read_json_body(self) -> dict[str, Any]:
            length = int(self.headers.get("Content-Length") or "0")
            if length <= 0:
                return {}
            raw = self.rfile.read(length)
            parsed = json.loads(raw.decode("utf-8"))
            if not isinstance(parsed, dict):
                raise ValueError("JSON body must be an object")
            return parsed

        def _host_allowed(self) -> bool:
            """Reject unexpected Host headers (DNS-rebinding defence)."""
            port = self.server.server_address[1]
            host = (self.headers.get("Host") or "").strip().lower()
            return host in (f"127.0.0.1:{port}", f"localhost:{port}")

        def _reject_bad_host(self) -> bool:
            if self._host_allowed():
                return False
            self._send_json(HTTPStatus.FORBIDDEN, {"error": "Forbidden: invalid Host header"})
            return True

        def do_GET(self) -> None:
            if self._reject_bad_host():
                return
            path = urlparse(self.path).path
            if path == "/":
                html_path = backend.ui_dir / "index.html"
                html = html_path.read_text(encoding="utf-8").replace(
                    "__DSB_TOKEN__", backend.api_token
                )
                self._send_bytes(
                    HTTPStatus.OK, "text/html; charset=utf-8", html.encode("utf-8")
                )
                return

            if path == "/bg.png":
                bg_path = backend.assets_dir / "dsb_background.png"
                if not bg_path.exists():
                    self._send_json(HTTPStatus.NOT_FOUND, {"error": "Background not found"})
                    return
                self._send_bytes(HTTPStatus.OK, "image/png", bg_path.read_bytes())
                return

            if path == "/icon.png":
                icon_path = backend.assets_dir / "icon.png"
                if not icon_path.exists():
                    self._send_json(HTTPStatus.NOT_FOUND, {"error": "Icon not found"})
                    return
                self._send_bytes(HTTPStatus.OK, "image/png", icon_path.read_bytes())
                return

            if path == "/api/state":
                self._send_json(HTTPStatus.OK, backend.get_state())
                return

            self._send_json(HTTPStatus.NOT_FOUND, {"error": "Not found"})

        def do_POST(self) -> None:
            if self._reject_bad_host():
                return
            supplied = (self.headers.get("X-DSB-Token") or "").encode("utf-8", "replace")
            if not hmac.compare_digest(supplied, backend.api_token.encode("utf-8")):
                self._send_json(HTTPStatus.FORBIDDEN, {"error": "Forbidden: invalid token"})
                return

            path = urlparse(self.path).path
            try:
                body = self._read_json_body()
                if path == "/api/toggle":
                    server_id = str(body.get("id", ""))
                    blocked = bool(body.get("blocked", False))
                    self._send_json(HTTPStatus.OK, backend.toggle_server(server_id, blocked))
                elif path == "/api/bulk":
                    raw_ids = body.get("ids", [])
                    if not isinstance(raw_ids, list):
                        raise ValueError("'ids' must be a list")
                    blocked = bool(body.get("blocked", False))
                    self._send_json(
                        HTTPStatus.OK,
                        backend.bulk_set([str(x) for x in raw_ids], blocked),
                    )
                elif path == "/api/block-all":
                    self._send_json(HTTPStatus.OK, backend.block_all())
                elif path == "/api/unblock-all":
                    self._send_json(HTTPStatus.OK, backend.unblock_all())
                elif path == "/api/reset":
                    self._send_json(HTTPStatus.OK, backend.reset_firewall())
                elif path == "/api/cluster":
                    self._send_json(
                        HTTPStatus.OK, backend.set_clustered(bool(body.get("clustered", False)))
                    )
                elif path == "/api/refresh":
                    self._send_json(
                        HTTPStatus.OK,
                        backend.refresh(reload_sdr=bool(body.get("reload_sdr", False))),
                    )
                elif path == "/api/presets/save":
                    self._send_json(
                        HTTPStatus.OK, backend.save_preset(str(body.get("name", "")))
                    )
                elif path == "/api/presets/apply":
                    self._send_json(
                        HTTPStatus.OK, backend.apply_preset(str(body.get("name", "")))
                    )
                elif path == "/api/presets/delete":
                    self._send_json(
                        HTTPStatus.OK, backend.delete_preset(str(body.get("name", "")))
                    )
                else:
                    self._send_json(HTTPStatus.NOT_FOUND, {"error": "Not found"})
            except FirewallError as exc:
                self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": str(exc)})
            except ValueError as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            except Exception as exc:
                self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": str(exc)})

    return Handler


def start_http_server(backend: DSBBackend) -> tuple[ThreadingHTTPServer, int]:
    """Start the local 127.0.0.1 HTTP server on an ephemeral port in a daemon thread."""
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(backend))
    port = int(httpd.server_address[1])
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd, port


def _maybe_elevate_windows() -> bool:
    """Attempt UAC self-elevation once on Windows; return True if an elevated child took over."""
    if sys.platform != "win32":
        return False
    if "--no-elevate" in sys.argv or "--elevated" in sys.argv:
        return False
    if os.environ.get("DSB_NO_ELEVATE") or os.environ.get("DSB_ELEVATED"):
        return False
    try:
        if ctypes.windll.shell32.IsUserAnAdmin():  # type: ignore[attr-defined]
            return False
        if getattr(sys, "frozen", False):
            params = "--elevated"
        else:
            params = f'"{Path(__file__).resolve()}" --elevated'
        rc = ctypes.windll.shell32.ShellExecuteW(  # type: ignore[attr-defined]
            None, "runas", sys.executable, params, None, 1
        )
        return rc > 32
    except Exception:
        return False


def _find_chromium_app_browser() -> str | None:
    """Locate Microsoft Edge or Chrome on Windows for standalone --app mode fallback."""
    candidates = [
        Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"))
        / "Microsoft" / "Edge" / "Application" / "msedge.exe",
        Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
        / "Microsoft" / "Edge" / "Application" / "msedge.exe",
        Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
        / "Google" / "Chrome" / "Application" / "chrome.exe",
        Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"))
        / "Google" / "Chrome" / "Application" / "chrome.exe",
        Path(os.environ.get("LOCALAPPDATA", ""))
        / "Google" / "Chrome" / "Application" / "chrome.exe",
    ]
    for path in candidates:
        if path and path.is_file():
            return str(path)
    return shutil.which("msedge") or shutil.which("chrome")


def _launch_windows_gui() -> int:
    """Launch DSB on Windows using pywebview (Edge WebView2) with browser --app fallback."""
    if _maybe_elevate_windows():
        return 0

    backend = DSBBackend()
    httpd, port = start_http_server(backend)
    url = f"http://127.0.0.1:{port}/"

    if backend._active_servers():
        backend.ping_manager.refresh_all(backend._active_servers())

    try:
        try:
            import webview  # type: ignore[import-not-found]

            window = webview.create_window(
                APP_NAME,
                url,
                width=1200,
                height=700,
                min_size=(760, 500),
                background_color="#000000",
            )
            _ = window
            try:
                webview.start(gui="edgechromium")
            except Exception:
                webview.start()
            return 0
        except ImportError:
            browser = _find_chromium_app_browser()
            if browser:
                proc = subprocess.Popen([browser, f"--app={url}", "--window-size=1200,700"])
                proc.wait()
                return 0
            webbrowser.open(url)
            stop_event = threading.Event()
            try:
                stop_event.wait()
            except KeyboardInterrupt:
                pass
            return 0
    finally:
        backend.shutdown()
        httpd.shutdown()
        httpd.server_close()


def _launch_linux_gui() -> int:
    """Configure WebKit for NVIDIA/Wayland and launch the GTK4 desktop window."""
    if os.path.exists("/dev/nvidia0"):
        os.environ.setdefault("WEBKIT_DISABLE_DMABUF_RENDERER", "1")

    import gi

    gi.require_version("Gtk", "4.0")
    gi.require_version("WebKit", "6.0")
    from gi.repository import Gdk, GLib, Gtk, WebKit  # type: ignore[attr-defined]

    GLib.set_prgname("io.dsb.DeadlockServerBlocker")
    GLib.set_application_name(APP_NAME)

    backend = DSBBackend()
    httpd, port = start_http_server(backend)

    # Kick off initial live ping probes right as the window opens
    if backend._active_servers():
        backend.ping_manager.refresh_all(backend._active_servers())

    app = Gtk.Application(application_id="io.dsb.DeadlockServerBlocker")

    def on_activate(gtk_app: Gtk.Application) -> None:
        gtk_settings = Gtk.Settings.get_default()
        if gtk_settings is not None:
            gtk_settings.set_property("gtk-application-prefer-dark-theme", True)

        Gtk.Window.set_default_icon_name("io.dsb.DeadlockServerBlocker")

        win = Gtk.ApplicationWindow(application=gtk_app)
        win.set_title(APP_NAME)
        win.set_icon_name("io.dsb.DeadlockServerBlocker")
        win.set_default_size(1200, 700)
        win.set_size_request(760, 500)

        webview = WebKit.WebView()
        bg_rgba = Gdk.RGBA()
        bg_rgba.parse("#000000")
        webview.set_background_color(bg_rgba)

        settings = webview.get_settings()
        settings.set_enable_smooth_scrolling(True)
        settings.set_enable_developer_extras(False)
        webview.connect("context-menu", lambda *_args: True)

        webview.load_uri(f"http://127.0.0.1:{port}/")
        win.set_child(webview)
        win.present()

    def on_shutdown(_gtk_app: Gtk.Application) -> None:
        backend.shutdown()
        httpd.shutdown()
        httpd.server_close()

    app.connect("activate", on_activate)
    app.connect("shutdown", on_shutdown)
    return app.run(None)


def launch_gui() -> int:
    """Launch Deadlock Server Blocker - DSB for the current desktop OS."""
    if sys.platform == "win32":
        return _launch_windows_gui()
    return _launch_linux_gui()


if __name__ == "__main__":
    raise SystemExit(launch_gui())
