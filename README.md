<p align="center">
  <img src="assets/icon.png" alt="Deadlock Server Blocker - DSB" width="140" />
</p>

<h1 align="center">DSB</h1>
<p align="center"><strong>Deadlock Server Blocker</strong></p>

A minimal, Deadlock-only **Linux & Windows 10/11** desktop server blocker featuring a wrapping obsidian tile grid blended over clean Deadlock skyline artwork, live ping & packet-loss telemetry, and non-destructive firewall blocking.

> [!NOTE]
> **Based on [`FN-FAL113/server-picker-x`](https://github.com/FN-FAL113/server-picker-x)**
> This project is a Deadlock-focused reimagining inspired by **Server Picker X** by FN-FAL113 (GPL-3.0).
>
> **Built with Agentic AI:** This application was designed and built with the help of **Antigravity** (Google DeepMind's agentic AI coding assistant).

---

## Features

- **Cross-platform (Linux & Windows 10/11):**
  - **Linux:** Native GTK4 + WebKitGTK 6.0 window, **UFW-safe `DSB_BLOCK`** `iptables` chain inserted at `INPUT` position 1 ahead of UFW, plus KDE/GNOME password dialog integration (`kdialog` / `zenity`) with `pam_faillock` protection.
  - **Windows 10/11:** Native Edge WebView2 window via `pywebview` (with automatic Edge/Chrome `--app` fallback), UAC elevation prompt, and scoped outbound `DSB_BLOCK_*` Windows Defender Firewall rules via `netsh advfirewall`.
- **Deadlock-only live relay list:** Fetches Valve's live Steam Datagram Relay (SDR) pool for Deadlock (`appid=1422450`) with local cache fallback (`~/.config/deadlock-server-blocker/sdr_cache.json` on Linux, `%APPDATA%\deadlock-server-blocker\sdr_cache.json` on Windows).
- **Minimal black interactive tile UI:**
  - **ON:** Popped-out smoked-glass tiles with a crisp grey/white halo, live RTT ping (`ms`), and packet loss (`%`).
  - **BLOCKED:** Dimmed, recessed tiles with a dark grey outline, bold red `BLOCKED` status, and `100%` drop telemetry.
- **Region & search filtering:** Region dropdown (`All Regions`, `Europe (EU)`, `North America`, `South America`, `Asia`, `Middle East`, `Oceania`, `Africa`) with region-scoped `Block <Region>` / `Unblock <Region>` actions, search bar, regional Cluster toggle, Name/Ping sort, and saved Presets.
- **Non-destructive Reset Firewall:**
  - **Linux:** Removes only `DSB_BLOCK` (and any leftover Deadlock drops in `INPUT`) without flushing UFW.
  - **Windows:** Removes only `DSB_BLOCK_*` rules without running `netsh advfirewall reset`.

---

## Linux Installation & Usage

### Requirements
- `python3`, `iptables`, `sudo`, `util-linux` (`script`), `iputils` (`ping`)
- GTK 4 + WebKitGTK 6.0 Python bindings (`PyGObject`)
- `kdialog` (KDE) or `zenity` (GNOME / other desktops)

**Arch / CachyOS:**
```bash
sudo pacman -S python-gobject gtk4 webkitgtk-6.0 iptables util-linux iputils kdialog
```

**Ubuntu / Debian:**
```bash
sudo apt install python3-gi gir1.2-gtk-4.0 gir1.2-webkit-6.0 iptables util-linux iputils-ping zenity
```

**Fedora:**
```bash
sudo dnf install python3-gobject gtk4 webkitgtk6.0 iptables util-linux iputils kdialog
```

### Install & Launch
```bash
git clone https://github.com/Zyd93/deadlock-server-blocker-DSB.git
cd deadlock-server-blocker-DSB
./install.sh
```

Launch **Deadlock Server Blocker - DSB** from your application menu, or run `~/.local/bin/dsb-gui`. To uninstall launchers and desktop entries, run `./uninstall.sh`.

---

## Windows 10/11 Installation & Usage

### Option A: Prebuilt Executable (Releases / GitHub Actions)
1. Download `DeadlockServerBlocker-DSB.exe` from the repository's **Releases** page (or build artifacts in **Actions**).
2. Double-click `DeadlockServerBlocker-DSB.exe` and accept the UAC Administrator prompt so it can manage `DSB_BLOCK_*` rules in Windows Defender Firewall.

### Option B: Run from Source
1. Install **Python 3.10+** from [python.org](https://www.python.org/downloads/) (check *Add Python to PATH*).
2. Clone the repository and double-click `scripts\run_windows.bat` (or run from PowerShell):
   ```powershell
   git clone https://github.com/Zyd93/deadlock-server-blocker-DSB.git
   cd deadlock-server-blocker-DSB
   .\scripts\run_windows.bat
   ```
   *(Automatically installs `pywebview` if missing and prompts for Administrator UAC.)*

### Build Standalone `.exe` Locally
```powershell
.\scripts\build_windows.ps1
```
Outputs `dist\DeadlockServerBlocker-DSB.exe`.

---

## Running Tests

```bash
python3 -m unittest discover -s tests -v
```

---

## Contributors

- **[@Zyd93](https://github.com/Zyd93)** — Project Creator & Maintainer (concept, UI direction, testing, and Linux/Windows feature design)
- **Antigravity (Google DeepMind)** — Agentic AI contributor (cross-platform architecture, GTK4/WebKit6 & WebView2 UI, UFW-safe `DSB_BLOCK` & Windows Firewall backends, installers, CI workflow, and automated tests)

---

## Credits & License

- **Upstream Inspiration:** Based on [Server Picker X (`FN-FAL113/server-picker-x`)](https://github.com/FN-FAL113/server-picker-x) (GPL-3.0).
- **License:** Distributed under the **GNU General Public License v3.0** — see [LICENSE](LICENSE).
- *Deadlock and Steam Datagram Relay are trademarks/properties of Valve Corporation. This is an unofficial community utility.*
