#!/bin/sh
# sbom-inventory 에이전트 (Linux, 읽기 전용, POSIX sh + awk 만 사용 / jq·python 불필요)
#   - dpkg(Debian/Ubuntu), rpm(RHEL/Rocky/SUSE), apk(Alpine) 패키지 목록
#   - 결과: $OUT_DIR/<hostname>.json (+ .sha256)
# 배포 예: Ansible `script` 모듈, cron(@daily), systemd timer
#   OUT_DIR=/mnt/sbom ./collect-linux.sh       # NFS/SMB 마운트 경로
#   ./collect-linux.sh | ssh collector 'cat > /srv/sbom/$(hostname).json'  (OUT_DIR=- 이면 stdout)
set -eu
OUT_DIR="${OUT_DIR:-/var/lib/sbom-inventory}"

host=$(hostname -s 2>/dev/null || hostname)
fqdn=$(hostname -f 2>/dev/null || echo "")
. /etc/os-release 2>/dev/null || true
os_name="${PRETTY_NAME:-$(uname -s)}"
os_ver="${VERSION_ID:-$(uname -r)}"
distro="${ID:-}"
serial=$(cat /sys/class/dmi/id/product_serial 2>/dev/null || echo "")   # root 필요
macs=$(cat /sys/class/net/*/address 2>/dev/null | grep -v '^00:00:00:00:00:00$' | sort -u | tr '\n' ' ')
ips=$( (hostname -I 2>/dev/null || ip -o addr show 2>/dev/null | awk '{print $4}' | cut -d/ -f1) | tr '\n' ' ')

# 패키지 목록을 "source<TAB>name<TAB>version<TAB>arch<TAB>vendor" 로 출력
list_pkgs() {
  if command -v dpkg-query >/dev/null 2>&1; then
    dpkg-query -W -f='dpkg\t${Package}\t${Version}\t${Architecture}\t${Maintainer}\t${db:Status-Abbrev}\n' 2>/dev/null \
      | awk -F'\t' '$6 ~ /^ii/ {print $1"\t"$2"\t"$3"\t"$4"\t"$5}'
  fi
  if command -v rpm >/dev/null 2>&1; then
    rpm -qa --qf 'rpm\t%{NAME}\t%{EPOCH}:%{VERSION}-%{RELEASE}\t%{ARCH}\t%{VENDOR}\n' 2>/dev/null \
      | sed 's/\t(none):/\t/'
  fi
  if command -v apk >/dev/null 2>&1; then
    apk info -v 2>/dev/null | sed -E 's/^(.+)-([0-9][^-]*-r[0-9]+)$/apk\t\1\t\2\t\t/'
  fi
}

json=$(list_pkgs | awk -F'\t' \
  -v host="$host" -v fqdn="$fqdn" -v os="$os_name" -v osv="$os_ver" -v distro="$distro" \
  -v serial="$serial" -v macs="$macs" -v ips="$ips" -v ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)" '
function esc(s) { gsub(/\\/, "\\\\", s); gsub(/"/, "\\\"", s); gsub(/\t/, " ", s); gsub(/[\001-\037]/, "", s); return s }
function arr(s,   n, a, i, o) { n = split(s, a, " "); o = ""; for (i = 1; i <= n; i++) if (a[i] != "") o = o (o == "" ? "" : ",") "\"" esc(a[i]) "\""; return "[" o "]" }
BEGIN { printf "{\"schema\":\"sbom-inventory-agent/1\",\"collected_at\":\"%s\",", ts
        printf "\"host\":{\"hostname\":\"%s\",\"fqdn\":\"%s\",\"serial\":\"%s\",\"os\":\"%s\",\"os_version\":\"%s\",\"distro_id\":\"%s\",\"macs\":%s,\"ips\":%s},\"packages\":[", esc(host), esc(fqdn), esc(serial), esc(os), esc(osv), esc(distro), arr(macs), arr(ips)
        first = 1 }
NF >= 3 && $2 != "" {
  printf "%s{\"source\":\"%s\",\"name\":\"%s\",\"version\":\"%s\",\"arch\":\"%s\",\"vendor\":\"%s\"}", (first ? "" : ","), esc($1), esc($2), esc($3), esc($4), esc($5)
  first = 0 }
END { print "]}" }')

if [ "$OUT_DIR" = "-" ]; then
  printf '%s\n' "$json"
  exit 0
fi
mkdir -p "$OUT_DIR"
out="$OUT_DIR/$host.json"
printf '%s\n' "$json" > "$out.tmp" && mv -f "$out.tmp" "$out"
( cd "$OUT_DIR" && sha256sum "$host.json" > "$host.json.sha256" )
echo "OK -> $out"
