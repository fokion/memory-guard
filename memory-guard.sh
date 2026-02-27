#!/bin/bash
#
# memory-guard.sh — Prevent Linux Mint from running out of memory
#
# Monitors available memory and takes graduated action:
#   1. Drops filesystem caches when memory is low
#   2. Kills the largest non-essential process when memory is critical
#
# Usage:
#   sudo ./memory-guard.sh              # run once
#   sudo ./memory-guard.sh --daemon     # run continuously in the background
#
# Install as a systemd service:
#   sudo ./memory-guard.sh --install
#
# Remove the service:
#   sudo ./memory-guard.sh --uninstall
#

set -euo pipefail

# ── PATH hardening ────────────────────────────────────────────────────────────
export PATH="/usr/sbin:/usr/bin:/sbin:/bin"

# ── Locale pinning — ensure predictable awk/grep/stat output ─────────────────
export LC_ALL=C

# ── Umask hardening ───────────────────────────────────────────────────────────
umask 0027

# ── Configuration (edit these) ────────────────────────────────────────────────
WARNING_THRESHOLD=80    # % used — drop caches
CRITICAL_THRESHOLD=90   # % used — kill largest non-essential process
CHECK_INTERVAL=10       # seconds between checks (daemon mode)
LOG_MAX_BYTES=10485760  # 10 MB — rotate when exceeded (keeps one .1 backup)

# 1 = pagecache only (least disruptive)
# 2 = dentries + inodes
# 3 = all (most aggressive — causes dentry/inode re-reads, noticeable on HDDs)
DROP_CACHES_LEVEL=1

# Log directory — root-owned 0750 to eliminate TOCTOU symlink races
LOG_DIR="/var/log/memory-guard"
LOG_FILE="$LOG_DIR/memory-guard.log"

# Protected processes — prefix match (no trailing $) so names like
# systemd-logind, dbus-daemon, sshd-session are covered
PROTECTED_PROCS="^(init|systemd|sshd|Xorg|cinnamon|xfce4|lightdm|login|dbus|polkit|NetworkManager|pulseaudio|pipewire|kernel|gnome-shell|gdm|udev|journald)"

# Minimum UID to consider for killing — system services (UID < 1000) are
# never killed regardless of process name.
# Note: This intentionally excludes root-owned processes (runaway sudo, Docker
# containers, etc.). Automatically killing UID 0 processes risks taking down
# Xorg, systemd children, or the guard itself. If root processes are the
# problem, manual intervention is safer.
MIN_KILLABLE_UID=1000

# Rate-limiting for drop_caches
CACHE_DROP_COOLDOWN=60  # seconds
_last_cache_drop=0

# Kill circuit breaker
MAX_KILLS_PER_WINDOW=5
KILL_WINDOW=300         # 5 minutes
_kill_timestamps=()

# Kill grace period — seconds to wait for SIGTERM before SIGKILL
KILL_GRACE_SECONDS=5

# Daemon error backoff
_MAX_BACKOFF_MULTIPLIER=6  # cap: CHECK_INTERVAL * 6

# ── Configuration validation ─────────────────────────────────────────────────
validate_config() {
    local errors=0
    local var
    for var in WARNING_THRESHOLD CRITICAL_THRESHOLD CHECK_INTERVAL DROP_CACHES_LEVEL; do
        if [[ ! "${!var}" =~ ^[0-9]+$ ]]; then
            echo "ERROR: $var must be a positive integer (got '${!var}')" >&2
            ((errors++)) || true
        fi
    done
    # Abort early if any value is non-numeric — arithmetic comparisons below
    # would cause a bash error before the friendly message prints.
    if [[ "$errors" -gt 0 ]]; then
        exit 1
    fi
    if [[ "$WARNING_THRESHOLD" -lt 1 || "$WARNING_THRESHOLD" -gt 99 ]]; then
        echo "ERROR: WARNING_THRESHOLD must be 1-99 (got $WARNING_THRESHOLD)" >&2
        ((errors++)) || true
    fi
    if [[ "$CRITICAL_THRESHOLD" -le "$WARNING_THRESHOLD" || "$CRITICAL_THRESHOLD" -gt 99 ]]; then
        echo "ERROR: CRITICAL_THRESHOLD must be > WARNING_THRESHOLD and <= 99 (got $CRITICAL_THRESHOLD)" >&2
        ((errors++)) || true
    fi
    if [[ "$CHECK_INTERVAL" -lt 1 ]]; then
        echo "ERROR: CHECK_INTERVAL must be >= 1 (got $CHECK_INTERVAL)" >&2
        ((errors++)) || true
    fi
    if [[ "$DROP_CACHES_LEVEL" -lt 1 || "$DROP_CACHES_LEVEL" -gt 3 ]]; then
        echo "ERROR: DROP_CACHES_LEVEL must be 1, 2, or 3 (got $DROP_CACHES_LEVEL)" >&2
        ((errors++)) || true
    fi
    if [[ "$errors" -gt 0 ]]; then
        exit 1
    fi
}

# ── Helpers ───────────────────────────────────────────────────────────────────
init_log_dir() {
    # Use a dedicated root-owned directory to prevent symlink races.
    # Even if an attacker can predict the log filename, they cannot create
    # symlinks inside a 0750 root-owned directory.
    if [[ ! -d "$LOG_DIR" ]]; then
        mkdir -p "$LOG_DIR"
    fi
    chmod 0750 "$LOG_DIR"
    chown root:adm "$LOG_DIR"

    if [[ -L "$LOG_FILE" ]]; then
        echo "ERROR: Log file $LOG_FILE is a symlink — removing it." >&2
        # Safe: the directory is root:adm 0750, so only root can create entries
        # in the race window between rm and install below.
        rm -f "$LOG_FILE"
    fi

    if [[ ! -f "$LOG_FILE" ]]; then
        install -m 0640 -o root -g adm /dev/null "$LOG_FILE" 2>/dev/null || true
    fi
}

rotate_log() {
    if [[ ! -f "$LOG_FILE" ]]; then
        return
    fi
    local size
    size=$(stat -c%s "$LOG_FILE" 2>/dev/null) || return
    if [[ "$size" -ge "$LOG_MAX_BYTES" ]]; then
        mv -f "$LOG_FILE" "${LOG_FILE}.1"
        install -m 0640 -o root -g adm /dev/null "$LOG_FILE" 2>/dev/null || true
    fi
}

log() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] $1"
    echo "$msg"
    if [[ -f "$LOG_FILE" && ! -L "$LOG_FILE" ]]; then
        rotate_log
        echo "$msg" >> "$LOG_FILE" 2>/dev/null || true
    fi
}

require_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "Error: This script must be run as root (sudo)." >&2
        exit 1
    fi
}

get_memory_usage_pct() {
    local total available
    total=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)
    available=$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo)
    if [[ -z "$total" || "$total" -le 0 ]]; then
        log "ERROR: Could not read MemTotal from /proc/meminfo"
        echo 0
        return
    fi
    if [[ -z "$available" ]]; then
        available=0
    fi
    echo $(( (total - available) * 100 / total ))
}

get_memory_info() {
    awk '
        /^MemTotal:/     {total=$2}
        /^MemAvailable:/ {avail=$2}
        /^SwapTotal:/    {swaptotal=$2}
        /^SwapFree:/     {swapfree=$2}
        END {
            printf "Total: %d MB | Available: %d MB | Swap used: %d/%d MB\n",
                total/1024, avail/1024, (swaptotal-swapfree)/1024, swaptotal/1024
        }
    ' /proc/meminfo
}

# ── Rate-limited cache dropping ──────────────────────────────────────────────
drop_caches() {
    local now
    now=$(date +%s)
    if (( now - _last_cache_drop < CACHE_DROP_COOLDOWN )); then
        log "  Skipping cache drop (cooldown: $((CACHE_DROP_COOLDOWN - (now - _last_cache_drop)))s remaining)"
        return
    fi
    _last_cache_drop=$now

    log "ACTION: Dropping filesystem caches (level $DROP_CACHES_LEVEL)..."
    sync
    echo "$DROP_CACHES_LEVEL" > /proc/sys/vm/drop_caches
    local after
    after=$(get_memory_usage_pct)
    log "  Memory usage after dropping caches: ${after}%"
}

# ── PID verification ─────────────────────────────────────────────────────────
verify_pid() {
    local pid="$1" expected_comm="$2"
    local current_comm
    if [[ ! -d "/proc/$pid" ]]; then
        return 1
    fi
    current_comm=$(< "/proc/$pid/comm" 2>/dev/null) || return 1
    [[ "$current_comm" == "$expected_comm" ]]
}

# Verify process identity and send signal in the tightest possible sequence
# to minimize the TOCTOU window between check and kill.
verified_kill() {
    local pid="$1" comm="$2" signal="$3"
    if kill -0 "$pid" 2>/dev/null && verify_pid "$pid" "$comm"; then
        kill "-$signal" "$pid" 2>/dev/null || true
        return 0
    fi
    return 1
}

# ── Kill circuit breaker ─────────────────────────────────────────────────────
should_allow_kill() {
    local now cutoff i filtered
    now=$(date +%s)
    cutoff=$((now - KILL_WINDOW))

    # Prune timestamps outside the window
    filtered=()
    for i in "${_kill_timestamps[@]+"${_kill_timestamps[@]}"}"; do
        if [[ "$i" -ge "$cutoff" ]]; then
            filtered+=("$i")
        fi
    done
    _kill_timestamps=("${filtered[@]+"${filtered[@]}"}")

    if [[ ${#_kill_timestamps[@]} -ge $MAX_KILLS_PER_WINDOW ]]; then
        log "CIRCUIT BREAKER: Killed $MAX_KILLS_PER_WINDOW processes in ${KILL_WINDOW}s — pausing kills. Manual intervention may be required."
        return 1
    fi
    _kill_timestamps+=("$now")
    return 0
}

# ── Process finder ────────────────────────────────────────────────────────────
find_largest_non_essential_pid() {
    # Uses process substitution (not a pipe) to avoid running the loop in a
    # subshell. Extracts pid (field 1) and rss (last field) via awk so that
    # spaces in the comm column (e.g. kernel worker threads) don't corrupt
    # field parsing.
    local line pid rss proc_uid proc_comm
    while IFS= read -r line; do
        pid=$(awk '{print $1}' <<< "$line")
        rss=$(awk '{print $NF}' <<< "$line")

        [[ "$rss" =~ ^[0-9]+$ ]] || continue
        [[ "$rss" -eq 0 ]] && continue
        [[ "$pid" =~ ^[0-9]+$ ]] || continue
        # PID 0 is the kernel scheduler — never kill it
        [[ "$pid" -eq 0 ]] && continue

        # Skip system-user processes (UID < MIN_KILLABLE_UID)
        proc_uid=$(stat -c %u "/proc/$pid" 2>/dev/null) || continue
        [[ "$proc_uid" -lt "$MIN_KILLABLE_UID" ]] && continue

        # Read full comm from /proc for accurate matching
        proc_comm=$(< "/proc/$pid/comm" 2>/dev/null) || continue

        # Use bash built-in regex instead of echo|grep to avoid:
        # - spawning a subshell per iteration
        # - echo misinterpreting comm names starting with -n/-e as flags
        if [[ ! "$proc_comm" =~ $PROTECTED_PROCS ]]; then
            # Pipe-delimited to prevent spaces in proc_comm from corrupting
            # field parsing when the caller splits this with awk.
            echo "${pid}|${proc_comm}|${rss}"
            return
        fi
    done < <(ps -eo pid,comm,rss --sort=-rss --no-headers)
}

# ── Kill logic ────────────────────────────────────────────────────────────────
kill_largest_process() {
    # Check circuit breaker before proceeding
    if ! should_allow_kill; then
        return 1
    fi

    local info pid comm rss_kb
    info=$(find_largest_non_essential_pid)
    if [[ -z "$info" ]]; then
        log "WARNING: No killable process found."
        return 1
    fi

    pid=$(awk -F'|' '{print $1}' <<< "$info")
    comm=$(awk -F'|' '{print $2}' <<< "$info")
    rss_kb=$(awk -F'|' '{print $3}' <<< "$info")

    # Validate PID is numeric before passing to kill
    if ! [[ "$pid" =~ ^[0-9]+$ ]]; then
        log "ERROR: Invalid PID '$pid' — aborting kill"
        return 1
    fi

    # Verify identity + send SIGTERM in the tightest possible sequence
    if ! verified_kill "$pid" "$comm" 15; then
        log "WARNING: PID $pid is no longer $comm — skipping kill (PID reuse detected)"
        return 1
    fi

    log "ACTION: Killed process $comm (PID $pid, using $((rss_kb / 1024)) MB) with SIGTERM"

    # Poll with 1-second sleeps instead of blocking for the full grace period.
    # This keeps the daemon responsive and exits early if the process dies.
    local waited=0
    while [[ $waited -lt $KILL_GRACE_SECONDS ]]; do
        kill -0 "$pid" 2>/dev/null || break
        sleep 1
        ((waited++)) || true
    done

    # Re-verify identity before SIGKILL to prevent killing a recycled PID
    if kill -0 "$pid" 2>/dev/null; then
        if verified_kill "$pid" "$comm" 9; then
            log "  Process $pid ($comm) didn't exit after ${KILL_GRACE_SECONDS}s, sent SIGKILL"
        else
            log "  PID $pid has been recycled to a different process — not sending SIGKILL"
        fi
    fi
    log "  Memory usage after kill: $(get_memory_usage_pct)%"
}

# ── Main check ────────────────────────────────────────────────────────────────
check_memory() {
    local usage
    usage=$(get_memory_usage_pct)

    if [[ "$usage" -ge "$CRITICAL_THRESHOLD" ]]; then
        log "CRITICAL: Memory at ${usage}% (threshold: ${CRITICAL_THRESHOLD}%) — $(get_memory_info)"
        drop_caches
        usage=$(get_memory_usage_pct)
        if [[ "$usage" -ge "$CRITICAL_THRESHOLD" ]]; then
            kill_largest_process
        fi
    elif [[ "$usage" -ge "$WARNING_THRESHOLD" ]]; then
        log "WARNING: Memory at ${usage}% (threshold: ${WARNING_THRESHOLD}%) — $(get_memory_info)"
        drop_caches
    fi
}

# ── Daemon mode ───────────────────────────────────────────────────────────────
run_daemon() {
    log "memory-guard daemon started (check every ${CHECK_INTERVAL}s, warn=${WARNING_THRESHOLD}%, critical=${CRITICAL_THRESHOLD}%)"
    trap 'log "memory-guard daemon stopped."; exit 0' SIGTERM SIGINT

    local error_count=0
    while true; do
        if check_memory; then
            error_count=0
            sleep "$CHECK_INTERVAL"
        else
            ((error_count++)) || true
            local backoff=$((error_count > _MAX_BACKOFF_MULTIPLIER ? _MAX_BACKOFF_MULTIPLIER : error_count))
            log "ERROR: check_memory failed (consecutive errors: $error_count, sleeping ${backoff}x interval)"
            sleep $((CHECK_INTERVAL * backoff))
        fi
    done
}

# ── Systemd service installer ────────────────────────────────────────────────
install_service() {
    local install_path="/usr/local/sbin/memory-guard"

    install -o root -g root -m 0755 "$0" "$install_path"
    log "Installed script to $install_path"

    # Write unit file to a temp file in the same directory, then atomically
    # rename into place. Same-filesystem mv is atomic (single rename syscall).
    # Do NOT use a separate tmpdir — cross-filesystem mv is copy+delete, not atomic.
    local tmp_unit
    tmp_unit=$(mktemp /etc/systemd/system/.memory-guard.service.XXXXXX)
    # Clean up the temp file on any failure (interrupt, cat/chmod error, etc.)
    trap 'rm -f "$tmp_unit"' ERR

    cat > "$tmp_unit" <<EOF
[Unit]
Description=Memory Guard — OOM prevention daemon
After=multi-user.target

[Service]
Type=simple
ExecStart=$install_path --daemon
Restart=on-failure
RestartSec=5

# Prevent the kernel OOM killer from targeting this daemon — it must survive
# to do its job. earlyoom and systemd-oomd both set this.
OOMScoreAdjust=-1000

# Sandboxing
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
NoNewPrivileges=yes
ReadWritePaths=/var/log/memory-guard

# CAP_SYS_ADMIN is required for writing to /proc/sys/vm/drop_caches.
# CAP_KILL is required for sending signals to user processes.
CapabilityBoundingSet=CAP_KILL CAP_SYS_ADMIN

# Required: drop_caches writes to /proc/sys/vm/drop_caches
ProtectKernelTunables=no
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=~@clock @cpu-emulation @debug @module @mount @raw-io @reboot @swap

# Resource limits — prevent the guard itself from becoming a problem.
# No CPUQuota: during OOM with heavy swap thrashing, CPU is scarce and
# throttling the guard could make it miss its intervention window.
LimitNPROC=10
LimitNOFILE=1024
MemoryMax=50M
EOF

    chmod 0644 "$tmp_unit"
    mv -f "$tmp_unit" /etc/systemd/system/memory-guard.service

    systemctl daemon-reload
    systemctl enable memory-guard.service
    systemctl start memory-guard.service
    log "Installed and started memory-guard.service"
    echo "Service status:"
    systemctl status memory-guard.service --no-pager
}

# ── Systemd service uninstaller ───────────────────────────────────────────────
uninstall_service() {
    local install_path="/usr/local/sbin/memory-guard"
    local unit_file="/etc/systemd/system/memory-guard.service"

    if systemctl is-active --quiet memory-guard.service 2>/dev/null; then
        systemctl stop memory-guard.service
        log "Stopped memory-guard.service"
    fi
    if systemctl is-enabled --quiet memory-guard.service 2>/dev/null; then
        systemctl disable memory-guard.service
        log "Disabled memory-guard.service"
    fi
    if [[ -f "$unit_file" ]]; then
        rm -f "$unit_file"
        log "Removed $unit_file"
    fi
    if [[ -f "$install_path" ]]; then
        rm -f "$install_path"
        log "Removed $install_path"
    fi
    systemctl daemon-reload
    log "memory-guard has been fully uninstalled."
    log "Note: Logs remain at $LOG_DIR — remove manually if no longer needed."
}

# ── Entrypoint ────────────────────────────────────────────────────────────────
require_root
validate_config
init_log_dir

case "${1:-}" in
    --daemon)
        run_daemon
        ;;
    --install)
        install_service
        ;;
    --uninstall)
        uninstall_service
        ;;
    --status)
        echo "Memory: $(get_memory_info)"
        echo "Usage:  $(get_memory_usage_pct)%"
        echo "Thresholds: warning=${WARNING_THRESHOLD}%, critical=${CRITICAL_THRESHOLD}%"
        ;;
    --help|-h)
        echo "Usage: sudo $0 [--daemon|--install|--uninstall|--status|--help]"
        echo ""
        echo "  (no args)     Run a single memory check"
        echo "  --daemon      Run continuously in the foreground"
        echo "  --install     Install as a systemd service (starts on boot)"
        echo "  --uninstall   Stop, disable, and remove the systemd service"
        echo "  --status      Show current memory info"
        echo "  --help        Show this help"
        ;;
    *)
        check_memory || exit $?
        ;;
esac
