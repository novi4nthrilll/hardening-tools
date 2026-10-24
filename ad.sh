#!/usr/bin/env bash
# ad.sh - helper SSH buat A&D (RSCTF). Satu skrip buat semua challenge.
# Versi 2: gateway cuma kasih shell interaktif, jadi semua command dikirim
# lewat stdin + pty (-tt), hasilnya diambil di antara marker unik.
#
# Setup sekali:
#   chmod +x ad.sh
#   export AD_KEY=~/.ssh/id_ed25519
#   ./ad.sh setup 23 24 25           # daftarin id challenge + tulis ~/.ssh/config
#
# Pemakaian:
#   ./ad.sh sh 23                    # shell interaktif
#   ./ad.sh test 23                  # cek koneksi + jalur command
#   ./ad.sh run 23 "ls -la /app"     # jalanin command
#   ./ad.sh all "ps aux"             # di SEMUA challenge terdaftar
#   ./ad.sh get 23 /app ./src23      # download folder/file -> diekstrak ke ./src23/
#   ./ad.sh put 23 ./app.py /app/app.py   # upload (file lama di-backup .bak.<ts>)
#   ./ad.sh backup 23 /app           # backup ke ./backups/23-<waktu>.tar.gz
#   ./ad.sh list
#
# Env (opsional):
#   AD_KEY=~/.ssh/ad_key   AD_HOST=ssh.cosmos.porossec.my.id   AD_PORT=2222
#   TMO=120                timeout per operasi (detik)
#
# Catatan: VPN harus nyala dulu. Private key jangan dishare.

set -u

AD_HOST="${AD_HOST:-ssh.cosmos.porossec.my.id}"
AD_PORT="${AD_PORT:-2222}"
AD_KEY="${AD_KEY:-$HOME/.ssh/ad_key}"
TMO="${TMO:-120}"
STATE="$HOME/.ad_challenges"
CFG="$HOME/.ssh/config"
BEGIN="# >>> ad.sh managed >>>"
END="# <<< ad.sh managed <<<"

die() { echo "ERROR: $*" >&2; exit 1; }

SSH_OPTS=(-p "$AD_PORT" -i "$AD_KEY" -o IdentitiesOnly=yes
          -o IdentityAgent=none
          -o StrictHostKeyChecking=accept-new
          -o ServerAliveInterval=15 -o ServerAliveCountMax=3
          -o ConnectTimeout=10 -o LogLevel=ERROR)

need_key() { [ -f "$AD_KEY" ] || die "private key nggak ada di $AD_KEY (set AD_KEY=/path/ke/key)"; }
need_id()  { [[ "${1:-}" =~ ^[0-9]+$ ]] || die "challenge id harus angka (contoh: 23)"; }
ids() { [ -f "$STATE" ] && cat "$STATE"; }

# rexec <id> <body>  -> cetak stdout dari body; return 1 kalau marker akhir nggak muncul
rexec() {
  local id="$1" body="$2" tok="$$_$RANDOM$RANDOM" raw
  raw="$(
    {
      printf '%s\n' 'exec bash --noprofile --norc 2>/dev/null || exec sh'
      printf '%s\n' 'stty -echo 2>/dev/null'
      # marker ditulis __B""EG__ supaya echo input nggak ikut ke-match
      printf '{ echo __B""EG__%s\n%s\necho __E""ND__%s\n}\n' "$tok" "$body" "$tok"
      printf 'exit\n'
    } | timeout "$TMO" ssh -tt "${SSH_OPTS[@]}" "$1@$AD_HOST" 2>/dev/null | tr -d '\r'
  )"
  case "$raw" in
    *"__END__$tok"*) ;;
    *) return 1 ;;
  esac
  printf '%s\n' "$raw" | awk -v b="__BEG__$tok" -v e="__END__$tok" \
    'index($0,e){f=0; next} f{print; next} index($0,b){f=1}'
}

cmd_setup() {
  [ $# -ge 1 ] || die "pakai: $0 setup <id> [id ...]"
  for i in "$@"; do need_id "$i"; done
  printf '%s\n' "$@" | sort -un > "$STATE"
  mkdir -p "$HOME/.ssh"; chmod 700 "$HOME/.ssh"
  touch "$CFG"; chmod 600 "$CFG"
  sed -i "/$BEGIN/,/$END/d" "$CFG"
  {
    echo "$BEGIN"
    for i in $(ids); do
      cat <<EOF
Host ad$i
    HostName $AD_HOST
    Port $AD_PORT
    User $i
    IdentityFile $AD_KEY
    IdentitiesOnly yes
    IdentityAgent none
    StrictHostKeyChecking accept-new
    ServerAliveInterval 15
    ServerAliveCountMax 3

EOF
    done
    echo "$END"
  } >> "$CFG"
  echo "OK. Terdaftar: $(ids | tr '\n' ' ')"
  echo "Sekarang bisa: ssh ad$(ids | head -1)   atau   $0 sh $(ids | head -1)"
}

cmd_sh() {
  need_key; need_id "${1:-}"
  exec ssh "${SSH_OPTS[@]}" "$1@$AD_HOST"
}

cmd_test() {
  need_key; need_id "${1:-}"
  local out
  if out="$(rexec "$1" 'echo EXEC_OK; id; ls -la /app')"; then
    echo "$out"; echo "=> jalur command jalan."
  else
    die "gagal/timeout. Cek VPN, key, dan id challenge ($1). Coba: $0 sh $1"
  fi
}

cmd_run() {
  need_key; need_id "${1:-}"; local id="$1"; shift
  [ $# -ge 1 ] || die "pakai: $0 run <id> \"command\""
  rexec "$id" "$*" || die "command gagal/timeout di challenge $id"
}

cmd_all() {
  need_key
  [ $# -ge 1 ] || die "pakai: $0 all \"command\""
  [ -f "$STATE" ] || die "belum ada id terdaftar. Jalanin: $0 setup 23 24 ..."
  for i in $(ids); do
    echo "===== challenge $i ====="
    rexec "$i" "$*" || echo "(gagal di $i)"
  done
}

# tarik <remote_path> sebagai tar.gz (base64) -> file lokal $3
fetch_tgz() {
  local id="$1" body="$2" out="$3" data
  data="$(rexec "$id" "$body")" || return 1
  data="$(printf '%s' "$data" | tr -d '[:space:]')"
  [ -n "$data" ] || return 1
  printf '%s' "$data" | base64 -d > "$out" 2>/dev/null || return 1
  [ -s "$out" ] && tar -tzf "$out" >/dev/null 2>&1
}

cmd_get() {
  need_key; need_id "${1:-}"
  [ $# -eq 3 ] || die "pakai: $0 get <id> <remote_path> <local_dir>"
  local id="$1" remote="$2" dst="$3" tmp
  tmp="$(mktemp)"
  if ! fetch_tgz "$id" "if [ -e '$remote' ]; then tar -czf - -C \"\$(dirname '$remote')\" \"\$(basename '$remote')\" 2>/dev/null | base64 -w0; fi; echo" "$tmp" \
     || [ "$(tar -tzf "$tmp" 2>/dev/null | wc -l)" -lt 1 ]; then
    rm -f "$tmp"; die "download GAGAL (path salah/kosong/timeout). Coba: $0 test $id"
  fi
  mkdir -p "$dst"; tar -xzf "$tmp" -C "$dst"; rm -f "$tmp"
  echo "OK: $id:$remote -> $dst/"
}

cmd_backup() {
  need_key; need_id "${1:-}"
  [ $# -eq 2 ] || die "pakai: $0 backup <id> <remote_dir>"
  local id="$1" remote="$2" out="backups/$1-$(date +%Y%m%d-%H%M%S).tar.gz"
  mkdir -p backups
  if ! fetch_tgz "$id" "if [ -d '$remote' ]; then tar -czf - -C '$remote' . 2>/dev/null | base64 -w0; fi; echo" "$out" \
     || [ "$(tar -tzf "$out" 2>/dev/null | wc -l)" -lt 1 ]; then
    rm -f "$out"; die "backup GAGAL (folder '$remote' nggak ada/kosong/timeout). Coba: $0 test $id"
  fi
  echo "OK: $out ($(du -h "$out" | cut -f1), $(tar -tzf "$out" | wc -l) entri)"
}

cmd_put() {
  need_key; need_id "${1:-}"
  [ $# -eq 3 ] || die "pakai: $0 put <id> <local_file> <remote_path>"
  local id="$1" src="$2" remote="$3" b64 sum out body
  [ -f "$src" ] || die "file lokal '$src' nggak ada"
  b64="$(base64 -w76 "$src")"
  sum="$(sha256sum < "$src" | cut -d' ' -f1)"
  read -r -d '' body <<EOF
cat > /tmp/.ad_up.b64 <<'ADEOF'
$b64
ADEOF
if [ -f '$remote' ]; then cp -a '$remote' "$remote.bak.\$(date +%s)"; fi
base64 -d /tmp/.ad_up.b64 > '$remote' && rm -f /tmp/.ad_up.b64
echo "SUM=\$(sha256sum < '$remote' | cut -d' ' -f1)"
EOF
  out="$(rexec "$id" "$body")" || die "upload gagal/timeout"
  if printf '%s\n' "$out" | grep -q "SUM=$sum"; then
    echo "OK: $src -> $id:$remote (sha256 cocok; file lama di-backup .bak.<ts>)"
  else
    die "upload GAGAL: checksum nggak cocok. Output: $out"
  fi
}

case "${1:-}" in
  setup)  shift; cmd_setup "$@" ;;
  sh)     shift; cmd_sh "$@" ;;
  test)   shift; cmd_test "$@" ;;
  run)    shift; cmd_run "$@" ;;
  all)    shift; cmd_all "$@" ;;
  get)    shift; cmd_get "$@" ;;
  put)    shift; cmd_put "$@" ;;
  backup) shift; cmd_backup "$@" ;;
  list)   ids ;;
  *)      sed -n '2,29p' "$0" ;;
esac
