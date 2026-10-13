#!/usr/bin/env bash
# Manage the FreeBSD 15.1 Firecracker test VM (acj/freebsd-firecracker).
#
#   vm.sh start    download images (once), boot the VM, wait for SSH
#   vm.sh stop     shut the VM down
#   vm.sh ssh ...  run a command in the VM (or open a shell)
#   vm.sh reset    stop and discard the root disk (next start uses a fresh image)
#
# Requires tap0 (172.16.0.1/24) owned by the current user; see ../README.adoc.
set -euo pipefail

RELEASE="${FC_RELEASE:-v0.12.0}"
BASE_URL="https://github.com/acj/freebsd-firecracker/releases/download/$RELEASE"
STATE="${XDG_CACHE_HOME:-$HOME/.cache}/calipers-firecracker/$RELEASE"
DISK_SIZE="${FC_DISK_SIZE:-8G}"
VCPUS="${FC_VCPUS:-4}"
MEM_MIB="${FC_MEM_MIB:-4096}"
TAP_DEV="${FC_TAP:-tap0}"
GUEST_IP=172.16.0.2
# The guest derives its IP from this MAC; it must match GUEST_IP.
GUEST_MAC="06:00:AC:10:00:02"

SSH_OPTS=(-i "$STATE/freebsd.id_rsa" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
          -o LogLevel=ERROR -o ConnectTimeout=3)

fetch() {
    mkdir -p "$STATE"
    local f
    for f in firecracker freebsd-kern.bin freebsd-rootfs.bin.xz freebsd.id_rsa; do
        [[ -e "$STATE/$f" || ( $f == freebsd-rootfs.bin.xz && -e "$STATE/rootfs.pristine" ) ]] && continue
        echo "downloading $f"
        curl -fsSL -o "$STATE/$f.part" "$BASE_URL/$f"
        mv "$STATE/$f.part" "$STATE/$f"
    done
    chmod 600 "$STATE/freebsd.id_rsa"
    chmod +x "$STATE/firecracker"
    if [[ ! -e "$STATE/rootfs.pristine" ]]; then
        xz -T0 -d -c "$STATE/freebsd-rootfs.bin.xz" > "$STATE/rootfs.pristine"
        rm "$STATE/freebsd-rootfs.bin.xz"
    fi
    if [[ ! -e "$STATE/rootfs.bin" ]]; then
        cp --sparse=always "$STATE/rootfs.pristine" "$STATE/rootfs.bin"
        truncate -s "$DISK_SIZE" "$STATE/rootfs.bin"
    fi
}

# The patched kernel needs the host TSC frequency to avoid boot panics.
tsc_hz() {
    local mhz
    mhz="$( { dmesg 2>/dev/null || journalctl -k -b 2>/dev/null; } |
        sed -n 's/.*Refined TSC clocksource calibration: \([0-9.]*\) MHz.*/\1/p' | tail -1)"
    [[ -n "$mhz" ]] && awk "BEGIN{printf \"%d\", $mhz*1000000}"
}

running() {
    [[ -e "$STATE/firecracker.pid" ]] && kill -0 "$(cat "$STATE/firecracker.pid")" 2>/dev/null
}

start() {
    if running; then echo "already running"; return; fi
    ip link show "$TAP_DEV" >/dev/null 2>&1 || { echo "$TAP_DEV missing; see README.adoc" >&2; exit 1; }
    fetch

    local args="vfs.root.mountfrom=ufs:/dev/vtbd0" hz
    hz="$(tsc_hz)" && args="$args machdep.tsc_freq=$hz"

    cat > "$STATE/vmconfig.json" <<EOF
{
  "boot-source": { "kernel_image_path": "$STATE/freebsd-kern.bin", "boot_args": "$args" },
  "drives": [
    { "drive_id": "rootfs", "path_on_host": "$STATE/rootfs.bin", "is_root_device": true, "is_read_only": false }
  ],
  "network-interfaces": [
    { "iface_id": "eth0", "guest_mac": "$GUEST_MAC", "host_dev_name": "$TAP_DEV" }
  ],
  "machine-config": { "vcpu_count": $VCPUS, "mem_size_mib": $MEM_MIB, "smt": false }
}
EOF
    rm -f "$STATE/firecracker.sock"
    nohup "$STATE/firecracker" --api-sock "$STATE/firecracker.sock" --config-file "$STATE/vmconfig.json" \
        > "$STATE/console.log" 2>&1 &
    echo $! > "$STATE/firecracker.pid"

    echo -n "waiting for SSH"
    for _ in $(seq 60); do
        if ssh "${SSH_OPTS[@]}" root@$GUEST_IP true 2>/dev/null; then
            echo " ok ($GUEST_IP)"
            # First boot on an enlarged disk: grow the root filesystem.
            ssh "${SSH_OPTS[@]}" root@$GUEST_IP 'growfs -y / >/dev/null 2>&1 || true'
            return
        fi
        running || { echo; echo "firecracker exited; see $STATE/console.log" >&2; tail -20 "$STATE/console.log" >&2; exit 1; }
        echo -n .
        sleep 2
    done
    echo; echo "timed out; see $STATE/console.log" >&2
    exit 1
}

stop() {
    running || { echo "not running"; return; }
    ssh "${SSH_OPTS[@]}" root@$GUEST_IP 'shutdown -p now' >/dev/null 2>&1 || true
    local pid; pid="$(cat "$STATE/firecracker.pid")"
    for _ in $(seq 15); do kill -0 "$pid" 2>/dev/null || break; sleep 1; done
    kill "$pid" 2>/dev/null || true
    rm -f "$STATE/firecracker.pid" "$STATE/firecracker.sock"
    echo "stopped"
}

case "${1:-}" in
    start) start ;;
    stop) stop ;;
    ssh) shift; exec ssh "${SSH_OPTS[@]}" root@$GUEST_IP "$@" ;;
    reset) stop; rm -f "$STATE/rootfs.bin"; echo "root disk discarded" ;;
    *) sed -n '2,9p' "$0"; exit 2 ;;
esac
