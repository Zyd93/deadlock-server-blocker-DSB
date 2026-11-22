#!/bin/bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
APP_ID="io.dsb.DeadlockServerBlocker"
BIN_DIR="$HOME/.local/bin"
APPS_DIR="$HOME/.local/share/applications"
ICON_BASE="$HOME/.local/share/icons/hicolor"

missing=()

command -v python3 >/dev/null 2>&1 || missing+=("python3")
command -v iptables >/dev/null 2>&1 || missing+=("iptables")
command -v script >/dev/null 2>&1 || missing+=("util-linux (script)")
command -v ping >/dev/null 2>&1 || missing+=("iputils (ping)")
if ! command -v kdialog >/dev/null 2>&1 && ! command -v zenity >/dev/null 2>&1; then
    missing+=("kdialog or zenity")
fi

if command -v python3 >/dev/null 2>&1; then
    if ! python3 -c 'import gi; gi.require_version("Gtk", "4.0"); gi.require_version("WebKit", "6.0"); from gi.repository import Gtk, WebKit' 2>/dev/null; then
        missing+=("PyGObject + GTK 4 + WebKitGTK 6.0")
    fi
fi

if (( ${#missing[@]} > 0 )); then
    echo "Missing required dependencies:"
    for item in "${missing[@]}"; do
        echo "  - $item"
    done
    echo ""
    echo "Install them with your package manager:"
    echo "  Arch / CachyOS: sudo pacman -S python-gobject gtk4 webkitgtk-6.0 iptables util-linux iputils kdialog"
    echo "  Ubuntu / Debian: sudo apt install python3-gi gir1.2-gtk-4.0 gir1.2-webkit-6.0 iptables util-linux iputils-ping zenity"
    echo "  Fedora: sudo dnf install python3-gobject gtk4 webkitgtk6.0 iptables util-linux iputils kdialog"
    exit 1
fi

chmod 755 "$PROJECT_DIR/scripts/dsb-gui" "$PROJECT_DIR/scripts/dsb-askpass"

mkdir -p "$BIN_DIR" "$APPS_DIR" "$ICON_BASE/256x256/apps"
ln -sf "$PROJECT_DIR/scripts/dsb-gui" "$BIN_DIR/dsb-gui"
ln -sf "$PROJECT_DIR/scripts/dsb-askpass" "$BIN_DIR/dsb-askpass"

ICON_SRC="$PROJECT_DIR/assets/icon.png"
cp "$ICON_SRC" "$ICON_BASE/256x256/apps/${APP_ID}.png"

# Generate smaller hicolor icon sizes when Pillow is available
if python3 -c "import PIL" 2>/dev/null; then
    python3 - "$ICON_SRC" "$ICON_BASE" "$APP_ID" << 'PYEOF'
import sys
from pathlib import Path
from PIL import Image

src = Image.open(sys.argv[1]).convert("RGBA")
icon_base = Path(sys.argv[2])
app_id = sys.argv[3]
for sz in (48, 64, 128):
    out_dir = icon_base / f"{sz}x{sz}" / "apps"
    out_dir.mkdir(parents=True, exist_ok=True)
    src.resize((sz, sz), Image.Resampling.LANCZOS).save(out_dir / f"{app_id}.png", format="PNG")
PYEOF
fi

cat > "$APPS_DIR/${APP_ID}.desktop" << EOF
[Desktop Entry]
Name=Deadlock Server Blocker - DSB
Comment=Minimal Deadlock server relay blocker with UFW-safe packet filtering
Exec=${BIN_DIR}/dsb-gui
Icon=${ICON_BASE}/256x256/apps/${APP_ID}.png
StartupWMClass=${APP_ID}
Terminal=false
Type=Application
Categories=Game;Network;
Keywords=deadlock;dsb;server;blocker;firewall;
EOF
chmod 644 "$APPS_DIR/${APP_ID}.desktop"

if command -v gtk-update-icon-cache >/dev/null 2>&1; then
    gtk-update-icon-cache -f -t "$ICON_BASE" >/dev/null 2>&1 || true
fi
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database "$APPS_DIR" >/dev/null 2>&1 || true
fi
if command -v kbuildsycoca6 >/dev/null 2>&1; then
    kbuildsycoca6 --noincremental >/dev/null 2>&1 || true
fi

echo "Installed Deadlock Server Blocker - DSB!"
echo "Launch from your application menu or run: $BIN_DIR/dsb-gui"
