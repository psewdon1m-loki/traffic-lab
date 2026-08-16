#!/usr/bin/env bash
set -Eeuo pipefail

INSTALL_ROOT="${TLAB_INSTALL_ROOT:-/opt/tlab}"
BIN_PATH="${TLAB_BIN_PATH:-/usr/local/bin/tlab}"
ARCHIVE=""
RELEASE_URL=""
INSTALL_PACKAGES=1

usage() {
  cat <<'EOF'
Usage: bootstrap.sh [--archive FILE | --url URL] [--no-packages]

Installs a self-contained Loki Traffic Lab release. Run as root, for example:
  sudo bash bootstrap.sh --archive LokiTrafficLab-linux-x64.tar.gz
  curl -fsSL URL/bootstrap.sh | sudo bash -s -- --url URL/LokiTrafficLab-linux-x64.tar.gz
EOF
}

while (($#)); do
  case "$1" in
    --archive) [[ $# -ge 2 ]] || { echo '--archive requires a file.' >&2; exit 2; }; ARCHIVE="$2"; shift 2 ;;
    --url) [[ $# -ge 2 ]] || { echo '--url requires a URL.' >&2; exit 2; }; RELEASE_URL="$2"; shift 2 ;;
    --no-packages) INSTALL_PACKAGES=0; shift ;;
    --help|-h) usage; exit 0 ;;
    *) printf 'Unknown option: %s\n' "$1" >&2; usage >&2; exit 2 ;;
  esac
done

if (( EUID != 0 )); then
  echo 'Bootstrap must run as root. Use sudo bash bootstrap.sh ...' >&2
  exit 2
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" 2>/dev/null && pwd -P || pwd -P)"
WORK_DIR="$(mktemp -d -t tlab-bootstrap.XXXXXXXX)"
cleanup() { [[ -z "${WORK_DIR:-}" || ! -d "$WORK_DIR" ]] || rm -rf -- "$WORK_DIR"; }
trap cleanup EXIT

if [[ -n "$ARCHIVE" && -n "$RELEASE_URL" ]]; then
  echo 'Use either --archive or --url, not both.' >&2
  exit 2
fi
if [[ -n "$RELEASE_URL" ]]; then
  ARCHIVE="$WORK_DIR/release.tar.gz"
  if command -v curl >/dev/null 2>&1; then
    curl -fL --retry 3 "$RELEASE_URL" -o "$ARCHIVE"
    curl -fL --retry 3 "$RELEASE_URL.sha256" -o "$ARCHIVE.sha256"
  elif command -v wget >/dev/null 2>&1; then
    wget -O "$ARCHIVE" "$RELEASE_URL"
    wget -O "$ARCHIVE.sha256" "$RELEASE_URL.sha256"
  else echo 'curl or wget is required to download --url.' >&2; exit 2
  fi
elif [[ -z "$ARCHIVE" ]]; then
  candidates=("$SCRIPT_DIR"/LokiTrafficLab-linux-x64-*.tar.gz "$SCRIPT_DIR/releases"/LokiTrafficLab-linux-x64-*.tar.gz)
  for candidate in "${candidates[@]}"; do
    [[ ! -f "$candidate" ]] || { ARCHIVE="$candidate"; break; }
  done
fi
[[ -n "$ARCHIVE" && -f "$ARCHIVE" ]] || { echo 'Release archive not found. Pass --archive or --url.' >&2; exit 2; }
ARCHIVE="$(cd -- "$(dirname -- "$ARCHIVE")" && printf '%s/%s\n' "$PWD" "$(basename -- "$ARCHIVE")")"

[[ -f "$ARCHIVE.sha256" ]] || { printf 'Required release checksum is missing: %s\n' "$ARCHIVE.sha256" >&2; exit 1; }
expected="$(awk '{print tolower($1); exit}' "$ARCHIVE.sha256")"
actual="$(sha256sum "$ARCHIVE" | awk '{print tolower($1)}')"
[[ "$expected" =~ ^[0-9a-f]{64}$ && "$expected" == "$actual" ]] || { echo 'Release SHA-256 verification failed.' >&2; exit 1; }
echo 'Release SHA-256 verified.'

if (( INSTALL_PACKAGES )) && command -v apt-get >/dev/null 2>&1; then
  packages=(ca-certificates libicu-dev libnuma1)
  command -v ip >/dev/null 2>&1 && command -v ss >/dev/null 2>&1 || packages+=(iproute2)
  command -v ping >/dev/null 2>&1 || packages+=(iputils-ping)
  command -v traceroute >/dev/null 2>&1 || packages+=(traceroute)
  command -v iw >/dev/null 2>&1 || packages+=(iw)
  command -v tcpdump >/dev/null 2>&1 || packages+=(tcpdump)
  command -v setsid >/dev/null 2>&1 || packages+=(util-linux)
  if ((${#packages[@]})); then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y --no-install-recommends "${packages[@]}"
  fi
fi

EXTRACT_DIR="$WORK_DIR/extracted"
mkdir -p -- "$EXTRACT_DIR"
while IFS= read -r member; do
  [[ "$member" != /* && ! "$member" =~ (^|/)\.\.(/|$) ]] || { printf 'Unsafe archive member: %s\n' "$member" >&2; exit 1; }
done < <(tar -tzf "$ARCHIVE")
tar -xzf "$ARCHIVE" -C "$EXTRACT_DIR"
required=(LokiTrafficLab xray libmsquic.so.2 tlab connections.txt.example README.txt THIRD-PARTY-NOTICES.txt manifest.json)
for file in "${required[@]}"; do [[ -f "$EXTRACT_DIR/$file" ]] || { printf 'Invalid release: missing %s\n' "$file" >&2; exit 1; }; done

release_id="$(sha256sum "$ARCHIVE" | cut -c1-16)"
release_dir="$INSTALL_ROOT/releases/$release_id"
install -d -m 0755 "$INSTALL_ROOT/releases"
if [[ -e "$release_dir" ]]; then
  [[ -d "$release_dir" && -f "$release_dir/manifest.json" ]] || { echo 'Existing release path is invalid; refusing to overwrite it.' >&2; exit 1; }
  echo "Exact release already exists; reusing immutable directory: $release_dir"
else
  install -d -m 0755 "$release_dir"
  install -m 0755 "$EXTRACT_DIR/LokiTrafficLab" "$release_dir/LokiTrafficLab"
  install -m 0755 "$EXTRACT_DIR/xray" "$release_dir/xray"
  install -m 0644 "$EXTRACT_DIR/libmsquic.so.2" "$release_dir/libmsquic.so.2"
  install -m 0755 "$EXTRACT_DIR/tlab" "$release_dir/tlab"
  install -m 0644 "$EXTRACT_DIR/connections.txt.example" "$release_dir/connections.txt.example"
  [[ ! -f "$EXTRACT_DIR/test-plan.example.json" ]] || install -m 0644 "$EXTRACT_DIR/test-plan.example.json" "$release_dir/test-plan.example.json"
  install -m 0644 "$EXTRACT_DIR/README.txt" "$release_dir/README.txt"
  install -m 0644 "$EXTRACT_DIR/THIRD-PARTY-NOTICES.txt" "$release_dir/THIRD-PARTY-NOTICES.txt"
  install -m 0644 "$EXTRACT_DIR/manifest.json" "$release_dir/manifest.json"
fi
current_tmp="$INSTALL_ROOT/.current.$release_id.$$"
ln -s "releases/$release_id" "$current_tmp"
mv -Tf "$current_tmp" "$INSTALL_ROOT/current"
install -m 0755 "$EXTRACT_DIR/tlab" "$BIN_PATH"

target_user="${SUDO_USER:-root}"
target_home="$(getent passwd "$target_user" | cut -d: -f6)"
[[ -n "$target_home" ]] || target_home="/root"
config_dir="$target_home/.config/tlab"
install -d -m 0700 -o "$target_user" -g "$(id -gn "$target_user")" "$config_dir"
if [[ ! -e "$config_dir/connections.txt" ]]; then
  install -m 0600 -o "$target_user" -g "$(id -gn "$target_user")" "$EXTRACT_DIR/connections.txt.example" "$config_dir/connections.txt"
fi

echo "Loki Traffic Lab installed: $release_dir"
echo "Command: $BIN_PATH"
echo "Connections: $config_dir/connections.txt"
echo 'UFW was not disabled, flushed or modified.'
echo 'Next: add VLESS URIs to the connections file, then run `tlab start` (normal) or `tlab extended`.'
