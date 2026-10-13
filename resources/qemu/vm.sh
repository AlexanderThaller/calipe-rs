#!/usr/bin/env bash
# Manage a FreeBSD 15.1 QEMU/KVM test VM with ZFS root (official
# BASIC-CLOUDINIT-zfs image). Unlike the Firecracker VM this runs the GENERIC
# kernel, so stock modules like zfs.ko work. Needs no root: user-mode
# networking with SSH forwarded to 127.0.0.1:2222 and calipers' 9273 to 9275.
#
#   vm.sh start    download the image (once), boot, wait for SSH
#   vm.sh stop     shut the VM down
#   vm.sh ssh ...  run a command in the VM as root (or open a shell)
#   vm.sh scp ...  scp with the VM's key; refer to the VM as vm:/path
#   vm.sh reset    stop and discard all changes (next start is a fresh image)
set -euo pipefail

VERSION="${QEMU_FREEBSD_VERSION:-15.1}"
IMAGE="FreeBSD-$VERSION-RELEASE-amd64-BASIC-CLOUDINIT-zfs.qcow2"
URL="https://download.freebsd.org/releases/VM-IMAGES/$VERSION-RELEASE/amd64/Latest/$IMAGE.xz"
STATE="${XDG_CACHE_HOME:-$HOME/.cache}/calipers-qemu/$VERSION"
VCPUS="${QEMU_VCPUS:-4}"
MEM_MIB="${QEMU_MEM_MIB:-4096}"
SSH_PORT="${QEMU_SSH_PORT:-2222}"
METRICS_PORT="${QEMU_METRICS_PORT:-9275}"

SSH_OPTS=(-i "$STATE/id_ed25519" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
          -o LogLevel=ERROR -o ConnectTimeout=3)

prepare() {
    mkdir -p "$STATE"
    if [[ ! -e "$STATE/$IMAGE" ]]; then
        echo "downloading $IMAGE.xz"
        curl -fSL --progress-bar -o "$STATE/$IMAGE.xz.part" "$URL"
        mv "$STATE/$IMAGE.xz.part" "$STATE/$IMAGE.xz"
        xz -T0 -d "$STATE/$IMAGE.xz"
    fi
    [[ -e "$STATE/id_ed25519" ]] || ssh-keygen -q -t ed25519 -N "" -C calipers-qemu -f "$STATE/id_ed25519"
    if [[ ! -e "$STATE/overlay.qcow2" ]]; then
        # Copy-on-write overlay: reset just deletes it.
        qemu-img create -q -f qcow2 -b "$STATE/$IMAGE" -F qcow2 "$STATE/overlay.qcow2" 20G
    fi
    if [[ ! -e "$STATE/seed.iso" ]]; then
        local seed="$STATE/seed"
        mkdir -p "$seed"
        printf 'instance-id: calipers-qemu\nlocal-hostname: freebsd-zfs\n' > "$seed/meta-data"
        cat > "$seed/user-data" <<EOF
#cloud-config
ssh_authorized_keys:
  - $(cat "$STATE/id_ed25519.pub")
runcmd:
  - mkdir -p /root/.ssh && cp /home/freebsd/.ssh/authorized_keys /root/.ssh/ && chmod 600 /root/.ssh/authorized_keys
  - echo "PermitRootLogin prohibit-password" >> /etc/ssh/sshd_config && service sshd restart
EOF
        xorriso -as mkisofs -quiet -V cidata -J -r -o "$STATE/seed.iso" "$seed" 2>/dev/null
    fi
}

running() {
    [[ -e "$STATE/qemu.pid" ]] && kill -0 "$(cat "$STATE/qemu.pid")" 2>/dev/null
}

vm_ssh() {
    ssh "${SSH_OPTS[@]}" -p "$SSH_PORT" root@127.0.0.1 "$@"
}

start() {
    if running; then echo "already running"; return; fi
    prepare
    qemu-system-x86_64 -enable-kvm -cpu host -smp "$VCPUS" -m "$MEM_MIB" \
        -drive file="$STATE/overlay.qcow2",if=virtio,format=qcow2 \
        -drive file="$STATE/seed.iso",media=cdrom \
        -nic "user,model=virtio-net-pci,hostfwd=tcp:127.0.0.1:$SSH_PORT-:22,hostfwd=tcp:127.0.0.1:$METRICS_PORT-:9273" \
        -display none -serial "file:$STATE/console.log" \
        -daemonize -pidfile "$STATE/qemu.pid"

    echo -n "waiting for SSH"
    for _ in $(seq 120); do
        if vm_ssh true 2>/dev/null; then echo " ok (127.0.0.1:$SSH_PORT)"; return; fi
        running || { echo; echo "qemu exited; see $STATE/console.log" >&2; exit 1; }
        echo -n .
        sleep 2
    done
    echo; echo "timed out; see $STATE/console.log" >&2
    exit 1
}

stop() {
    running || { echo "not running"; return; }
    vm_ssh 'shutdown -p now' >/dev/null 2>&1 || true
    local pid; pid="$(cat "$STATE/qemu.pid")"
    for _ in $(seq 30); do kill -0 "$pid" 2>/dev/null || break; sleep 1; done
    kill "$pid" 2>/dev/null || true
    rm -f "$STATE/qemu.pid"
    echo "stopped"
}

case "${1:-}" in
    start) start ;;
    stop) stop ;;
    ssh) shift; vm_ssh "$@" ;;
    scp) shift; exec scp "${SSH_OPTS[@]}" -P "$SSH_PORT" "${@//vm:/root@127.0.0.1:}" ;;
    reset) stop; rm -f "$STATE/overlay.qcow2"; echo "VM disk discarded" ;;
    *) sed -n '2,12p' "$0"; exit 2 ;;
esac
