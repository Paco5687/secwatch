#!/usr/bin/env bash
# Create a Debian LXC on Proxmox VE and install secwatch inside it.
#
#   Run this ON THE PVE HOST as root:
#     bash -c "$(curl -fsSL https://raw.githubusercontent.com/Paco5687/secwatch/main/deploy/proxmox-lxc.sh)"
#
# It's a thin, readable helper (not affiliated with the community-scripts project).
# Review it first — it creates a container and runs secwatch's installer inside.
#
# Override any default via env, e.g.:  CTID=141 RAM=1024 DISK=6 BRIDGE=vmbr1 bash proxmox-lxc.sh
set -euo pipefail

CTID="${CTID:-$(pvesh get /cluster/nextid)}"
HOSTNAME="${HOSTNAME:-secwatch}"
DISK="${DISK:-4}"                 # GB
CORES="${CORES:-1}"
RAM="${RAM:-512}"                 # MB
BRIDGE="${BRIDGE:-vmbr0}"
STORAGE="${STORAGE:-local-lvm}"   # where the rootfs lives
TEMPLATE_STORAGE="${TEMPLATE_STORAGE:-local}"
TEMPLATE="${TEMPLATE:-debian-12-standard_12.7-1_amd64.tar.zst}"
UNPRIVILEGED="${UNPRIVILEGED:-1}"

command -v pct >/dev/null || { echo "This must run on a Proxmox VE host (pct not found)." >&2; exit 1; }

echo "→ secwatch LXC:  CTID=$CTID  host=$HOSTNAME  ${CORES}core/${RAM}MB/${DISK}GB  net=$BRIDGE(dhcp)"

# Make sure the template is present.
if ! pveam list "$TEMPLATE_STORAGE" | grep -q "$TEMPLATE"; then
  echo "→ downloading template $TEMPLATE …"
  pveam update >/dev/null 2>&1 || true
  pveam download "$TEMPLATE_STORAGE" "$TEMPLATE"
fi

pct create "$CTID" "$TEMPLATE_STORAGE:vztmpl/$TEMPLATE" \
  --hostname "$HOSTNAME" --cores "$CORES" --memory "$RAM" \
  --rootfs "$STORAGE:$DISK" --net0 "name=eth0,bridge=$BRIDGE,ip=dhcp" \
  --features nesting=1 --unprivileged "$UNPRIVILEGED" --onboot 1

pct start "$CTID"
echo "→ waiting for network …"; sleep 6

pct exec "$CTID" -- bash -c "apt-get update -qq && apt-get install -y -qq curl ca-certificates >/dev/null"
# Install secwatch (generates an admin password, starts the systemd service).
pct exec "$CTID" -- bash -c "curl -fsSL https://raw.githubusercontent.com/Paco5687/secwatch/main/install.sh | sh"

IP=$(pct exec "$CTID" -- hostname -I 2>/dev/null | awk '{print $1}')
echo
echo "==================================================================="
echo "✅ secwatch LXC $CTID is up.  Open  http://${IP:-<container-ip>}:8931/"
echo "   (the installer printed the generated admin password above)"
echo "   Enter it later with:  pct enter $CTID"
echo "==================================================================="
