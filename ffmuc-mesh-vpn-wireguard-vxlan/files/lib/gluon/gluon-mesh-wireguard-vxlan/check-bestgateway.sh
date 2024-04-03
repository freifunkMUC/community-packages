#!/bin/busybox sh

# fail fast and abort early
set -eu
# set -o pipefail # TODO: pipefail needs more rework in the script

if { set -C; true 2>/dev/null >/var/lock/checkuplink2.lock; }; then
	trap "rm -f /var/lock/checkuplink2.lock" EXIT
else
	echo "Lock file exists... exiting"
	exit
fi

source /lib/gluon/gluon-mesh-wireguard-vxlan/functions.sh
init_vars

use_api_best_gw

logger -p info "$PEER_HOST $PEER_PORT $PEER_PUBLICKEY $PEER_LINKADDRESS $PEER_SWITCH"

CURRENT_PEER_PUBLICKEY=$(wg show wg_mesh_vpn peers)

if [ "$PEER_SWITCH" = "True" ]; then
    if [ "$CURRENT_PEER_PUBLICKEY" = "$PEER_PUBLICKEY" ]; then
        logger -p info "Switch: $PEER_SWITCH; One the best GW($PEER_HOST) at the moment $CURRENT_PEER_PUBLICKEY / $PEER_PUBLICKEY"
    else
        logger -p info "Connect to best GW($PEER_HOST) ;)"
        # remove wg_mesh_vpn
        ip link del wg_mesh_vpn
    fi
else
    if [ "$CURRENT_PEER_PUBLICKEY" = "$PEER_PUBLICKEY" ]; then
        logger -p info "Switch $PEER_SWITCH; One the best GW($PEER_HOST) at the moment $CURRENT_PEER_PUBLICKEY / $PEER_PUBLICKEY"
    else
        logger -p info "Not on the best GW($PEER_HOST) but no Switch for you"
    fi
fi
