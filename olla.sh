#!/bin/bash
#
# Defender Service Enumerator
# Cek service yang running di server + info tambahan buat audit
#

set -u

OUTDIR="."
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT="${OUTDIR}/services_${TIMESTAMP}.txt"

# Warna (kalau bukan piped)
if [ -t 1 ]; then
    RED='\033[0;31m'; YEL='\033[0;33m'; GRN='\033[0;32m'
    CYN='\033[0;36m'; NC='\033[0m'; BOLD='\033[1m'
else
    RED=''; YEL=''; GRN=''; CYN=''; NC=''; BOLD=''
fi

# Fungsi logging: print ke layar + simpan ke report
log() {
    echo -e "$@" | tee -a "$REPORT"
}

header() {
    log "\n${BOLD}${CYN}==== $1 ====${NC}"
}

# Cek root (systemctl kadang perlu akses buat info lengkap, tapi running units bisa dibaca user biasa)
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${YEL}[!] Jalan sebagai non-root. Beberapa info (PID, listening port) mungkin nggak lengkap.${NC}"
fi

log "${BOLD}Service Enumeration Report${NC}"
log "Host     : $(hostname)"
log "Waktu    : $(date)"
log "Kernel   : $(uname -r)"

header "1. RUNNING SERVICES (systemctl)"
systemctl list-units --type=service --state=running --no-pager --no-legend \
    | awk '{print $1}' | tee -a "$REPORT"

header "2. DETAIL: PID, USER, PORT, DAN STATUS"
printf "%-40s %-8s %-12s %-8s %-10s\n" "UNIT" "PID" "USER" "STATUS" "LISTEN_PORT" | tee -a "$REPORT"

# Ambil semua running service unit
units=$(systemctl list-units --type=service --state=running --no-pager --no-legend | awk '{print $1}')

for unit in $units; do
    # PID & user utama (ExecMainPID)
    pid=$(systemctl show -p MainPID --value "$unit" 2>/dev/null)
    user=$(systemctl show -p User --value "$unit" 2>/dev/null)
    [ -z "$user" ] && user="-"    # kalau kosong, biasanya root (default)
    [ "$user" = "root" ] || [ -z "$user" ] && user=$(ps -o user= -p "$pid" 2>/dev/null | tr -d ' ')
    [ -z "$user" ] && user="-"
    status=$(systemctl show -p ActiveState --value "$unit" 2>/dev/null)

    # Port yang dipakai PID ini (kalau PID valid)
    ports="-"
    if [ -n "$pid" ] && [ "$pid" != "0" ]; then
        # Ambil semua listening socket milik PID ini
        p=$(ss -tulnp 2>/dev/null | awk -v pid="$pid" '$0 ~ ("pid=" pid ",") {print $5}' \
            | sed 's/.*://' | sort -u | paste -sd, -)
        [ -n "$p" ] && ports="$p"
    fi

    printf "%-40s %-8s %-12s %-8s %-10s\n" "$unit" "${pid:-0}" "$user" "$status" "$ports" | tee -a "$REPORT"
done

header "3. LISTENING PORTS (ss -tulnp)"
if command -v ss >/dev/null 2>&1; then
    ss -tulnp 2>/dev/null | tee -a "$REPORT"
else
    log "${YEL}[!] 'ss' nggak ada, coba netstat${NC}"
    netstat -tulnp 2>/dev/null | tee -a "$REPORT" || log "${RED}[!] netstat juga nggak ada${NC}"
fi

header "4. SERVICE YANG SEDANG ENABLED (auto-start boot)"
systemctl list-unit-files --type=service --state=enabled --no-pager --no-legend | tee -a "$REPORT"

header "5. PROCESS YANG JALAN DI LUAR SYSTEMD (suspect!)"
# Process yang bukan child systemd / bukan service unit — sering jadi tempat implant
ps -eo pid,ppid,user,comm,args --no-headers | \
    awk '$2 == 1 && $4 != "systemd" {print}' | tee -a "$REPORT"

header "6. FILE .service YANG DI-OVERRIDE / DROP-IN (penting buat deteksi tampering)"
systemctl list-unit-files --type=service --no-pager --no-legend | awk '{print $1}' | while read -r u; do
    dropin=$(systemctl show -p DropInPaths --value "$u" 2>/dev/null)
    if [ -n "$dropin" ]; then
        log "  $u -> $dropin"
    fi
done

header "7. TIMER UNIT YANG AKTIF (sering dipakai persistence)"
systemctl list-timers --all --no-pager 2>/dev/null | tee -a "$REPORT"

log "\n${GRN}[+] Report disimpan: ${REPORT}${NC}"
