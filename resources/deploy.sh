#!/bin/sh
# Build and install calipers on the FreeBSD host it should run on. Run as
# root from the repository checkout.
#
#   resources/deploy.sh                  build (deploy profile), install, restart
#   resources/deploy.sh --binary PATH    install a prebuilt binary instead
#   resources/deploy.sh --no-restart     install only
#
# Installs:
#   /usr/local/bin/calipers              replaced atomically
#   /usr/local/etc/rc.d/calipers         rc.d script
#   /usr/local/etc/calipers.toml         only if it doesn't exist yet
#
# The new binary validates the existing configuration before the service is
# restarted, so a config the new version rejects leaves the old one running.
set -eu

PREFIX="${PREFIX:-/usr/local}"
binary=""
restart=1

while [ $# -gt 0 ]; do
	case "$1" in
	--binary) binary="$2"; shift 2 ;;
	--no-restart) restart=0; shift ;;
	-h|--help) sed -n '2,16p' "$0"; exit 0 ;;
	*) echo "unknown option: $1" >&2; exit 2 ;;
	esac
done

if [ "$(id -u)" -ne 0 ]; then
	echo "run as root" >&2
	exit 1
fi

repo="$(cd "$(dirname "$0")/.." && pwd)"

if [ -z "$binary" ]; then
	echo "==> building (cargo build --profile deploy)"
	(cd "$repo" && cargo build --profile deploy --locked)
	binary="$repo/target/deploy/calipers"
fi
[ -x "$binary" ] || { echo "$binary is not an executable" >&2; exit 1; }

config="$PREFIX/etc/calipers.toml"
if [ ! -e "$config" ]; then
	echo "==> installing example config to $config (edit it!)"
	install -m 0644 "$repo/resources/calipers.toml" "$config"
fi

echo "==> checking $config with the new binary"
"$binary" --config "$config" --check-config

echo "==> installing $PREFIX/bin/calipers and $PREFIX/etc/rc.d/calipers"
install -m 0755 "$binary" "$PREFIX/bin/calipers.new"
mv -f "$PREFIX/bin/calipers.new" "$PREFIX/bin/calipers"
install -m 0555 "$repo/resources/rc.d/calipers" "$PREFIX/etc/rc.d/calipers"

if ! sysrc -n calipers_enable 2>/dev/null | grep -qi '^yes$'; then
	echo "==> calipers is not enabled; run: sysrc calipers_enable=YES && service calipers start"
	exit 0
fi

if [ "$restart" -eq 1 ]; then
	echo "==> restarting calipers"
	service calipers restart
	sleep 1
	service calipers status
fi
