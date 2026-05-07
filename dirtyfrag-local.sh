#!/usr/bin/env bash
# dirtyfrag-local.sh — assess and optionally remediate Dirty Frag exposure
# on the local host only. No SSH, no parallelism.
#
# Usage:
#   ./dirtyfrag-local.sh [--assess]
#
#   --assess   Read-only: check vulnerability surface and forensic indicators.
#              Never writes anything. Does not require sudo.
#
#   (no flag)  Remediate: write /etc/modprobe.d/dirtyfrag.conf and unload
#              the three modules. Requires sudo (or run as root).
#
# Env overrides:
#   PATCHED_KERNEL   minimum kernel containing the fix (leave UNSET until errata)
#   DRY_RUN=1        report only; do NOT write conf or rmmod (implied by --assess)
#
# Exit codes:
#   0  fully safe (MITIGATED, PATCHED, or WRONG_OS)
#   1  not fully safe, or forensic indicators present in --assess mode
#   2  usage error

set -uo pipefail

ASSESS=0
if [[ "${1:-}" == "--assess" ]]; then
    ASSESS=1
fi

PATCHED_KERNEL="${PATCHED_KERNEL:-}"
DRY_RUN="${DRY_RUN:-0}"
[[ "$ASSESS" == "1" ]] && DRY_RUN=1

CONF=/etc/modprobe.d/dirtyfrag.conf

# ── Colour helpers ────────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
    RED='\033[0;31m'; YELLOW='\033[0;33m'; GREEN='\033[0;32m'
    CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
else
    RED=''; YELLOW=''; GREEN=''; CYAN=''; BOLD=''; RESET=''
fi

info()  { printf "  ${CYAN}%-20s${RESET} %s\n" "$1" "$2"; }
ok()    { printf "  ${GREEN}%-20s${RESET} %s\n" "$1" "$2"; }
warn()  { printf "  ${YELLOW}%-20s${RESET} %s\n" "$1" "$2"; }
bad()   { printf "  ${RED}%-20s${RESET} %s\n" "$1" "$2"; }
hdr()   { printf "\n${BOLD}%s${RESET}\n" "$1"; }

# ── Privilege helper ──────────────────────────────────────────────────────────
run_sudo() {
    if [[ $EUID -eq 0 ]]; then
        "$@"
    else
        sudo -n "$@"
    fi
}

# ── OS gate ───────────────────────────────────────────────────────────────────
if [[ ! -r /etc/os-release ]]; then
    warn "OS" "cannot read /etc/os-release — skipping OS check"
else
    . /etc/os-release
    case "${ID:-}:${VERSION_ID:-}" in
        rocky:8*|rocky:9*) ;;
        *)
            warn "OS" "${ID:-?}-${VERSION_ID:-?} — not Rocky Linux 8/9; results may vary"
            ;;
    esac
fi

KERNEL=$(uname -r)
hdr "=== Dirty Frag — $([ "$ASSESS" = 1 ] && echo 'assess (read-only)' || echo 'remediation') mode ==="
info "kernel" "$KERNEL"

# ── Patched kernel check ──────────────────────────────────────────────────────
if [[ -n "$PATCHED_KERNEL" ]]; then
    if [[ "$(printf '%s\n%s\n' "$KERNEL" "$PATCHED_KERNEL" | sort -V | head -n1)" \
          == "$PATCHED_KERNEL" ]]; then
        ok "status" "PATCHED — kernel >= $PATCHED_KERNEL"
        exit 0
    fi
fi

# ── Helpers ───────────────────────────────────────────────────────────────────
conf_in_place() {
    [[ -f "$CONF" ]] &&
    grep -qF 'install esp4 /bin/false'  "$CONF" &&
    grep -qF 'install esp6 /bin/false'  "$CONF" &&
    grep -qF 'install rxrpc /bin/false' "$CONF"
}

any_module_loaded() {
    lsmod | awk 'NR>1{print $1}' | grep -qxE 'esp4|esp6|rxrpc'
}

try_unload() {
    run_sudo modprobe -r esp4 esp6 rxrpc 2>/dev/null
    ! any_module_loaded
}

# ── Vulnerability surface ─────────────────────────────────────────────────────
hdr "--- Vulnerability surface ---"

for mod in esp4 esp6 rxrpc; do
    present=no;  modinfo "$mod" &>/dev/null && present=yes
    loaded=no;   lsmod | awk 'NR>1{print $1}' | grep -qx "$mod" && loaded=yes
    blocked=no;  grep -rqF "install ${mod} /bin/false" /etc/modprobe.d/ 2>/dev/null \
                     && blocked=yes

    if   [[ "$present" == no ]];                   then ok  "$mod" "absent from kernel — not exploitable via this module"
    elif [[ "$blocked" == yes && "$loaded" == no ]]; then ok  "$mod" "present, blocked by modprobe.d, not loaded — mitigated"
    elif [[ "$blocked" == yes && "$loaded" == yes ]]; then warn "$mod" "present, blocked by modprobe.d, but still LOADED — reboot needed"
    elif [[ "$loaded"  == yes ]];                  then bad  "$mod" "present and LOADED — vulnerable"
    else                                                warn "$mod" "present, not loaded, not blocked — loadable on demand"
    fi
done

max_ns=$(</proc/sys/user/max_user_namespaces 2>/dev/null || echo 0)
if [[ "$max_ns" -gt 0 ]]; then
    warn "user_namespaces" "enabled (max=$max_ns) — unprivileged exploitation path reachable"
else
    ok   "user_namespaces" "disabled — exploitation requires CAP_NET_ADMIN"
fi

# ── Forensic indicators (--assess mode) ──────────────────────────────────────
FORENSIC_FLAGS=""
if [[ "$ASSESS" == "1" ]]; then
    hdr "--- Forensic indicators (derived from exp.c analysis) ---"

    # 1. /usr/bin/su RPM integrity
    # exp.c: TARGET_PATH "/usr/bin/su", PATCH_OFFSET 0, PAYLOAD_LEN 192
    rpm_out=$(rpm -V shadow-utils 2>/dev/null | grep '/usr/bin/su' || true)
    if [[ -n "$rpm_out" ]]; then
        bad  "su integrity" "FAIL — rpm -V: $rpm_out"
        FORENSIC_FLAGS="${FORENSIC_FLAGS}SU_TAMPERED "
    else
        ok   "su integrity" "rpm -V shadow-utils passes for /usr/bin/su"
    fi

    # 2. ELF header anomaly
    # exp.c: ENTRY_OFFSET 0x78 → e_entry=0x400078; injected stub has e_phnum=1
    if command -v readelf &>/dev/null; then
        su_entry=$(readelf -h /usr/bin/su 2>/dev/null \
                   | awk '/Entry point address/{print $NF}')
        su_phnum=$(readelf -h /usr/bin/su 2>/dev/null \
                   | awk '/Number of program headers/{print $NF}')
        if [[ "$su_entry" == "0x400078" ]] || [[ "${su_phnum:-99}" -le 2 ]]; then
            bad  "su ELF header" "SUSPECT — entry=${su_entry:-?} phnum=${su_phnum:-?} (injected stub signature)"
            FORENSIC_FLAGS="${FORENSIC_FLAGS}SU_ELF_SUSPECT "
        else
            ok   "su ELF header" "normal — entry=${su_entry:-?} phnum=${su_phnum:-?}"
        fi
    else
        warn "su ELF header" "readelf not available — skipping"
    fi

    # 3. Module loads in the last 24h
    # exp.c autoloads esp4/esp6 (xfrm leg) and rxrpc (RxRPC leg)
    mod_count=0
    if command -v journalctl &>/dev/null; then
        mod_count=$(journalctl -k --since "24 hours ago" --no-pager 2>/dev/null \
                    | grep -cE '\b(esp4|esp6|rxrpc)\b' || true)
    else
        mod_count=$(dmesg 2>/dev/null | grep -cE '\b(esp4|esp6|rxrpc)\b' || true)
    fi
    if [[ "$mod_count" -gt 0 ]]; then
        warn "journal mods" "${mod_count} esp4/esp6/rxrpc kernel message(s) in last 24h"
        FORENSIC_FLAGS="${FORENSIC_FLAGS}MODS_IN_JOURNAL(${mod_count}) "
    else
        ok   "journal mods" "no esp4/esp6/rxrpc load events in last 24h"
    fi

    # 4. Root logins today
    # Successful exploit produces a root shell via the overwritten su
    root_count=$(last root 2>/dev/null \
                 | awk -v today="$(date '+%a %b')" \
                       '$1=="root" && $0 ~ today {n++} END {print n+0}')
    if [[ "$root_count" -gt 0 ]]; then
        warn "root logins" "${root_count} root login(s) today (corroborating signal)"
        FORENSIC_FLAGS="${FORENSIC_FLAGS}ROOT_LOGINS(${root_count}) "
    else
        ok   "root logins" "no root logins today"
    fi

    # 5. unshare(CLONE_NEWUSER) syscalls today
    # exp.c: unshare(CLONE_NEWUSER|CLONE_NEWNET) to get CAP_NET_ADMIN for xfrm
    if command -v ausearch &>/dev/null; then
        unshare_count=$(ausearch -sc unshare --start today 2>/dev/null \
                        | grep -c 'type=SYSCALL' || true)
        if [[ "$unshare_count" -gt 0 ]]; then
            warn "audit unshare" "${unshare_count} unshare(CLONE_NEWUSER) syscall(s) today"
            FORENSIC_FLAGS="${FORENSIC_FLAGS}AUDIT_UNSHARE(${unshare_count}) "
        else
            ok   "audit unshare" "no unshare(CLONE_NEWUSER) syscalls today"
        fi
    else
        info "audit unshare" "ausearch not available — install audit package to enable this check"
    fi
fi

# ── Remediation state and action ──────────────────────────────────────────────
hdr "--- Status ---"

FINAL_STATE=""

if conf_in_place; then
    if ! any_module_loaded; then
        ok "mitigation" "MITIGATED — conf in place, modules not loaded"
        FINAL_STATE="MITIGATED"
    else
        if [[ "$DRY_RUN" == "1" ]]; then
            warn "mitigation" "PENDING_REBOOT — conf in place but module(s) still loaded"
            FINAL_STATE="PENDING_REBOOT"
        else
            printf "  Attempting to unload modules... "
            if try_unload; then
                printf "${GREEN}done${RESET}\n"
                ok "mitigation" "MITIGATED — conf in place, modules now unloaded"
                FINAL_STATE="MITIGATED"
            else
                printf "${YELLOW}could not unload (in use)${RESET}\n"
                warn "mitigation" "PENDING_REBOOT — reboot required to unload modules"
                FINAL_STATE="PENDING_REBOOT"
            fi
        fi
    fi
else
    if [[ "$DRY_RUN" == "1" ]]; then
        bad "mitigation" "VULNERABLE — no modprobe.d block in place"
        FINAL_STATE="VULNERABLE"
    else
        printf "  Writing %s... " "$CONF"
        if printf 'install esp4 /bin/false\ninstall esp6 /bin/false\ninstall rxrpc /bin/false\n' \
                | run_sudo tee "$CONF" >/dev/null 2>&1 \
           && conf_in_place; then
            printf "${GREEN}done${RESET}\n"
            printf "  Attempting to unload modules... "
            if try_unload; then
                printf "${GREEN}done${RESET}\n"
                ok "mitigation" "APPLIED — conf written, modules unloaded — fully protected"
                FINAL_STATE="APPLIED"
            else
                printf "${YELLOW}could not unload (in use)${RESET}\n"
                warn "mitigation" "APPLIED_PENDING_REBOOT — conf written; reboot to unload modules"
                FINAL_STATE="APPLIED_PENDING_REBOOT"
            fi
        else
            printf "${RED}FAILED${RESET}\n"
            bad "mitigation" "APPLY_FAILED — could not write $CONF (sudo/NOPASSWD?)"
            FINAL_STATE="APPLY_FAILED"
        fi
    fi
fi

# ── Forensic summary ──────────────────────────────────────────────────────────
if [[ "$ASSESS" == "1" ]]; then
    hdr "--- Forensic summary ---"
    if [[ -n "$FORENSIC_FLAGS" ]]; then
        bad  "SUSPECT" "indicators: ${FORENSIC_FLAGS% }"
        printf "\n  ${RED}${BOLD}This host has forensic indicators consistent with prior exploitation.${RESET}\n"
        printf "  Treat as compromised until investigated. Do not remediate in place.\n"
    else
        ok   "forensic" "CLEAN — no indicators of prior exploitation detected"
        printf "\n  Note: a careful attacker may have cleared wtmp and the RPM database.\n"
        printf "  These checks cover the PoC as published; variants may leave different artifacts.\n"
    fi
fi

echo

# ── Exit code ─────────────────────────────────────────────────────────────────
case "$FINAL_STATE" in
    MITIGATED|PATCHED)
        [[ "$ASSESS" == "1" && -n "$FORENSIC_FLAGS" ]] && exit 1
        exit 0 ;;
    *)
        exit 1 ;;
esac
