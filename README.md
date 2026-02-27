# memory-guard

A self-contained bash daemon that prevents Linux Mint (and other Linux desktops) from running out of memory. It monitors available memory via `/proc/meminfo` and takes graduated action — dropping filesystem caches when memory is low, and killing the largest non-essential user process when memory is critical.

Designed as a lightweight, dependency-free alternative to `earlyoom` or `systemd-oomd` for systems where those aren't available or desired.

## How It Works

The daemon runs a check loop every 10 seconds (configurable) and responds at two thresholds:

**Warning (80% used)** — drops the kernel page cache via `/proc/sys/vm/drop_caches`. This reclaims memory from stale filesystem buffers without affecting any running processes. Cache drops are rate-limited to once per 60 seconds to avoid I/O storms.

**Critical (90% used)** — drops caches first, then if memory is still critical, sends SIGTERM to the largest non-essential user process (by RSS). If the process doesn't exit within 5 seconds, it escalates to SIGKILL. A circuit breaker limits kills to 5 per 5-minute window to prevent runaway destruction of user work.

```
Normal ──── 80% ────── 90% ────── 100%
             │          │
         drop caches  drop caches
                      + kill largest
                        user process
```

## Quick Start

```bash
# Run a single check
sudo ./memory-guard.sh

# Check current memory status
sudo ./memory-guard.sh --status

# Run continuously in the foreground
sudo ./memory-guard.sh --daemon

# Install as a systemd service (starts on boot)
sudo ./memory-guard.sh --install

# Remove the service
sudo ./memory-guard.sh --uninstall
```

## Installation

No dependencies beyond bash 4.4+ and standard GNU coreutils (awk, ps, stat, grep). Copy the script anywhere and run with root privileges.

For persistent use, the `--install` flag handles everything:

```bash
sudo ./memory-guard.sh --install
```

This will:

1. Copy the script to `/usr/local/sbin/memory-guard`
2. Create a hardened systemd unit at `/etc/systemd/system/memory-guard.service`
3. Enable and start the service

Verify it's running:

```bash
systemctl status memory-guard
journalctl -u memory-guard -f
```

Logs are written to `/var/log/memory-guard/memory-guard.log` with automatic rotation at 10 MB.

## Configuration

Edit the variables at the top of the script. After changing values, re-run `--install` to update the installed copy.

| Variable | Default | Description |
|----------|---------|-------------|
| `WARNING_THRESHOLD` | `80` | Memory usage % that triggers cache drop |
| `CRITICAL_THRESHOLD` | `90` | Memory usage % that triggers process kill |
| `CHECK_INTERVAL` | `10` | Seconds between checks in daemon mode |
| `DROP_CACHES_LEVEL` | `1` | 1 = page cache only (recommended), 2 = dentries+inodes, 3 = all |
| `CACHE_DROP_COOLDOWN` | `60` | Minimum seconds between cache drops |
| `MAX_KILLS_PER_WINDOW` | `5` | Max process kills per time window |
| `KILL_WINDOW` | `300` | Time window for circuit breaker (seconds) |
| `KILL_GRACE_SECONDS` | `5` | Seconds to wait for SIGTERM before SIGKILL |
| `MIN_KILLABLE_UID` | `1000` | Minimum process owner UID eligible for killing |

## Process Protection

The daemon uses two layers to decide what can be killed:

**UID filtering** — Only processes owned by regular users (UID ≥ 1000) are considered. All system services, root processes, and daemon users are immune. This is the primary safety mechanism.

**Name filtering** — Processes matching the `PROTECTED_PROCS` regex are also excluded. This covers desktop environment components (Xorg, cinnamon, gnome-shell), audio servers (pulseaudio, pipewire), and networking (NetworkManager). The match is prefix-based, so `systemd` also protects `systemd-logind`, `systemd-resolved`, etc.

### Why root processes are excluded

A deliberate design decision. Automatically killing UID 0 processes risks taking down Xorg, systemd children, or the guard itself. If a root-owned process (runaway `sudo make -j64`, Docker container) is causing the memory pressure, manual intervention is safer than automated killing.

## Security Hardening

The script implements multiple layers of defense appropriate for a privileged daemon:

**Filesystem safety** — Logs are written to a root-owned directory (`/var/log/memory-guard/`, mode 0750) to prevent symlink attacks. The log path is checked for symlinks before every write.

**PID verification** — Before sending any signal, the daemon verifies the target PID still belongs to the expected process name via `/proc/$pid/comm`. This is checked before both SIGTERM and SIGKILL to prevent killing a recycled PID.

**Systemd sandboxing** — The installed service runs with `ProtectSystem=strict`, `ProtectHome=yes`, `NoNewPrivileges=yes`, `MemoryDenyWriteExecute=yes`, and a restricted syscall filter. Capabilities are limited to `CAP_KILL` and `CAP_SYS_ADMIN` (the latter required for `drop_caches`).

**OOM immunity** — The service sets `OOMScoreAdjust=-1000` so the kernel's native OOM killer won't target the daemon, ensuring it survives to do its job.

**Input hardening** — `set -euo pipefail`, `umask 0027`, `LC_ALL=C`, and hardened `PATH`. All configuration values are validated for type and range at startup.

## Daemon Resilience

The daemon loop is designed to survive transient failures without crashing or spiraling:

- Individual check failures are caught and logged without killing the daemon.
- Consecutive errors trigger exponential backoff (up to 6× the check interval) to avoid log flooding.
- The circuit breaker prevents runaway kills if memory stays critical despite intervention.
- Cache drops are rate-limited to once per cooldown period regardless of how frequently thresholds are crossed.

## Architecture Notes

This is a polling-based daemon. The 10-second interval means a sufficiently fast memory leak could exhaust the system between checks. For sub-second response times, Linux's PSI (Pressure Stall Information) interface at `/proc/pressure/memory` can trigger on memory pressure events instantly — but this requires a compiled daemon with `poll()` support, not bash.

For most desktop workloads (browser tabs accumulating, IDE memory leaks, runaway builds), the 10-second interval provides adequate response time. Reduce `CHECK_INTERVAL` to 5 or even 2 seconds for faster response at the cost of slightly higher idle CPU usage.

## Uninstalling

```bash
sudo ./memory-guard.sh --uninstall
```

This stops and disables the service, removes the unit file and installed script, and reloads systemd. Logs at `/var/log/memory-guard/` are preserved — remove them manually if no longer needed.

## License

MIT