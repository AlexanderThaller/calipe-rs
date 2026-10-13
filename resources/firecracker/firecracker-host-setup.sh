#!/usr/bin/env bash
# One-time (per boot) host setup so an unprivileged user can run the
# freebsd-firecracker VM with internet access. Run with sudo.
#
# The guest image has a fixed IP 172.16.0.2 (derived from MAC 06:00:AC:10:00:02),
# so the host side of the tap device must be 172.16.0.1/24.
set -euo pipefail

TAP_DEV="${TAP_DEV:-tap0}"
TAP_IP="${TAP_IP:-172.16.0.1/24}"
VM_USER="${VM_USER:-${SUDO_USER:?run via sudo or set VM_USER}}"
# Interface carrying the default route (br0 on this host).
UPLINK="${UPLINK:-$(ip -o route show default | awk '{print $5; exit}')}"

# Tap device owned by the VM user, so firecracker doesn't need root.
ip link del "$TAP_DEV" 2>/dev/null || true
ip tuntap add dev "$TAP_DEV" mode tap user "$VM_USER"
ip addr add "$TAP_IP" dev "$TAP_DEV"
ip link set dev "$TAP_DEV" up

sysctl -q -w net.ipv4.ip_forward=1

# NAT guest traffic out of the uplink (idempotent: delete before insert).
iptables -t nat -D POSTROUTING -s 172.16.0.0/24 -o "$UPLINK" -j MASQUERADE 2>/dev/null || true
iptables -t nat -A POSTROUTING -s 172.16.0.0/24 -o "$UPLINK" -j MASQUERADE

# Docker sets the FORWARD policy to DROP; DOCKER-USER is the supported place
# for our rules. Fall back to FORWARD when Docker isn't running.
CHAIN=FORWARD
iptables -n -L DOCKER-USER >/dev/null 2>&1 && CHAIN=DOCKER-USER
for rule in "-i $TAP_DEV -o $UPLINK -j ACCEPT" \
            "-i $UPLINK -o $TAP_DEV -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"; do
    # shellcheck disable=SC2086
    iptables -D "$CHAIN" $rule 2>/dev/null || true
    # shellcheck disable=SC2086
    iptables -I "$CHAIN" 1 $rule
done

echo "OK: $TAP_DEV ($TAP_IP) owned by $VM_USER, NAT via $UPLINK, forward rules in $CHAIN"
