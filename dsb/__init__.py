"""Deadlock Server Blocker - DSB package metadata."""

APP_NAME = "Deadlock Server Blocker - DSB"
SHORT_NAME = "DSB"
VERSION = "1.1.1"


_EXTRA_BIN_DIRS = ("/usr/sbin", "/sbin", "/usr/bin", "/bin")


def find_binary(name: str, fallback: str) -> str:
    """Locate a system binary (PATH plus sbin dirs, e.g. Debian's /usr/sbin/iptables)."""
    import os
    import shutil

    search = os.pathsep.join([os.environ.get("PATH", ""), *_EXTRA_BIN_DIRS])
    return shutil.which(name, path=search) or fallback
