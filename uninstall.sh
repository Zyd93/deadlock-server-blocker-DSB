#!/bin/bash
set -euo pipefail

APP_ID="io.dsb.DeadlockServerBlocker"
BIN_DIR="$HOME/.local/bin"
APPS_DIR="$HOME/.local/share/applications"
ICON_BASE="$HOME/.local/share/icons/hicolor"

rm -f "$BIN_DIR/dsb-gui" "$BIN_DIR/dsb-askpass"
rm -f "$APPS_DIR/${APP_ID}.desktop"
rm -f "$ICON_BASE"/48x48/apps/"${APP_ID}.png" \
      "$ICON_BASE"/64x64/apps/"${APP_ID}.png" \
      "$ICON_BASE"/128x128/apps/"${APP_ID}.png" \
      "$ICON_BASE"/256x256/apps/"${APP_ID}.png"

if command -v gtk-update-icon-cache >/dev/null 2>&1; then
    gtk-update-icon-cache -f -t "$ICON_BASE" >/dev/null 2>&1 || true
fi
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database "$APPS_DIR" >/dev/null 2>&1 || true
fi
if command -v kbuildsycoca6 >/dev/null 2>&1; then
    kbuildsycoca6 --noincremental >/dev/null 2>&1 || true
fi

echo "Uninstalled Deadlock Server Blocker - DSB launchers and desktop entry."
echo "Note: ~/.config/deadlock-server-blocker was preserved (remove manually if desired)."
