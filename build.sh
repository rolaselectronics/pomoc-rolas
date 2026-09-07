#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "$0")" && pwd)"
out="$project_dir/dist"
generated_header="$project_dir/src/build_secrets.h"
password="${ROLAS_ACCESS_PASSWORD:-TU_WPISZ_HASLO}"

if [[ "$password" == "TU_WPISZ_HASLO" ]]; then
  echo "Ustaw ROLAS_ACCESS_PASSWORD przed budowaniem wersji produkcyjnej." >&2
  exit 2
fi
if [[ ! "$password" =~ ^[A-Za-z0-9._@%+=!-]{1,8}$ ]]; then
  echo "Haslo musi miec od 1 do 8 znakow ASCII: litery, cyfry lub ._@%+=!-" >&2
  exit 2
fi

zig_bin="${ZIG:-zig}"
command -v "$zig_bin" >/dev/null
command -v openssl >/dev/null

securevnc_b64="$(printf '%s' "$password" | base64 | tr -d '\r\n')"
uvnc_data_hex="$({ printf '%s' "$password"; printf '%*s' "$((8-${#password}))" '' | tr ' ' '\0'; } \
  | openssl enc -des-ecb -K e84ad660c4721ae0 -nopad -nosalt -provider legacy \
  | od -An -tx1 | tr -d ' \r\n' | tr '[:lower:]' '[:upper:]')"
# WritePrivateProfileStruct stores eight encrypted bytes followed by a one-byte
# additive checksum. UltraVNC reads passwords with GetPrivateProfileStruct, so
# a plain 16-character DES hex value is rejected as an unset password.
uvnc_checksum="$(printf '%s' "$uvnc_data_hex" \
  | sed 's/../0x&\n/g' \
  | awk '{sum += $1} END {printf "%02X", sum % 256}')"
uvnc_hex="${uvnc_data_hex}${uvnc_checksum}"

cleanup() {
  rm -f "$generated_header"
}
trap cleanup EXIT

printf '#define ROLAS_SECUREVNC_PASSPHRASE_B64 "%s"\n' "$securevnc_b64" > "$generated_header"
printf '#define ROLAS_UVNC_PASSWORD_HEX "%s"\n' "$uvnc_hex" >> "$generated_header"

mkdir -p "$out"
cd "$project_dir/src"
"$zig_bin" cc -target x86-windows-gnu -O2 \
  main.c resources.rc -o "$out/Pomoc-Rolas-1.1.1.exe" \
  -Wl,--subsystem,windows -lgdi32 -ladvapi32 -lshell32

cd "$out"
sha256sum Pomoc-Rolas-1.1.1.exe > SHA256SUMS.txt
