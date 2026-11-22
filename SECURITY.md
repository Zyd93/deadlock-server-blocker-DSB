# Security Policy

## Scope & Design Principles

**Deadlock Server Blocker - DSB** is a firewall management tool — it never injects into Deadlock, reads or alters game memory, or modifies Steam/game files.

Key security boundaries:
- **Isolated firewall rules (`DSB_BLOCK`):**
  - **Linux:** Creates an isolated `DSB_BLOCK` chain inserted at `INPUT` position 1 ahead of UFW. Resetting removes only `DSB_BLOCK` (and legacy Deadlock IPs in `INPUT`) and never flushes UFW or user rules.
  - **Windows:** Creates scoped outbound `DSB_BLOCK_*` rules via `netsh advfirewall`. Resetting deletes only `DSB_BLOCK_*` rules and never runs `netsh advfirewall reset`.
- **Localhost API & CSRF protection:** The UI communicates only with a `127.0.0.1` HTTP server bound to an ephemeral port, and all mutating `POST` requests require a random per-launch `X-DSB-Token` header.
- **Privilege isolation (`pam_faillock` safe):** On Linux, `dsb/firewall.py` only invokes `sudo -n` inside an ephemeral PTY session after `dsb-gui` has validated credentials via `kdialog`/`zenity` and checked `faillock`, preventing silent lockout loops.

## Reporting a Vulnerability

If you discover a security issue (for example, command injection, privilege escalation, or unsafe rule handling):
1. Please use GitHub **Security Advisories** (*Security* tab → *Report a vulnerability*) or open an issue on [GitHub](https://github.com/Zyd93/deadlock-server-blocker-DSB/issues) if advisories are not enabled.
2. Include the affected OS (`Linux` or `Windows`), reproduction steps, and the relevant module (`dsb/firewall.py`, `scripts/dsb-gui`, `dsb/app.py`, etc.).
