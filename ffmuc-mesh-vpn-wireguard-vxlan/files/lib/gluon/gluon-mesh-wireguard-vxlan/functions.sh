
get_site_string() {
	local path="$1"

	lua <<EOF
local site = require 'gluon.site'
print(site.${path}())
EOF
}

get_site_bool() {
	local path="$1"

	lua <<EOF
local site = require 'gluon.site'
if site.${path}() then
    print("true")
else
	print("false")
end
EOF
}

interface_linklocal() {
	# We generate a predictable v6 address
	local macaddr oldIFS
	macaddr="$(uci get wireguard.mesh_vpn.privatekey | wg pubkey | md5sum | sed 's/^\(..\)\(..\)\(..\)\(..\)\(..\).*$/02:\1:\2:\3:\4:\5/')"
	oldIFS="$IFS"
	IFS=':'
	# shellcheck disable=SC2086 # we need to split macaddr here using IFS
	set -- $macaddr
	IFS="$oldIFS"
	echo "fe80::${1}${2}:${3}ff:fe${4}:${5}${6}"
}

clean_port() {
	echo "$1" | sed -r 's/:[0-9]+$|\[|\]//g'
}

extract_port() {
    echo "$1" | awk -F: '{print $NF}'
}

combine_ip_port() {
    local ip="$1"
    local port="$2"

    # Add brackets in case the IP is an IPv6
    case $ip in
        *":"*)
            ip="[${ip}]"
            ;;
    esac

    echo "$ip:$port"
}

resolve_host() {
	local gateway="$1"
	# Check if we have a default route for v6 if not fallback to v4
	if ip -6 route show table 1 | grep -q 'default via'
	then
		local ipv6
		ipv6="$(gluon-wan nslookup "$gateway" | grep 'Address:\? [0-9]' | grep -oE '([a-f0-9:]+:+)+[a-f0-9]+')"
		echo "$ipv6"
	else
		local ipv4
		ipv4="$(gluon-wan nslookup "$gateway" | grep 'Address:\? [0-9]' | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b')"
		echo "$ipv4"
	fi
}

force_wan_connection() {
	LD_PRELOAD=libpacketmark.so LIBPACKETMARK_MARK=1 gluon-wan "$@"
}

is_loadbalancing_enabled() {
	local lb_default
	local lb_overwrite
	lb_default=$(get_site_string mesh_vpn.wireguard.loadbalancing)

	if [[ $lb_default == "on" ]]; then
		return 0 # true
	elif [[ $lb_default == "off" ]]; then
		return 1 # false
	fi

	# check if an overwrite was specified
	if lb_overwrite=$(uci -q get wireguard.mesh_vpn.loadbalancing); then
		logger -p info -t checkuplink "Loadbalancing overwrite detected: ${lb_overwrite}"
		if [[ $lb_overwrite == "1" ]]; then
			return 0 # true
		elif [[ $lb_overwrite == "0" ]]; then
			return 1 # false
		fi
	fi

	if [[ $lb_default == "on-by-default" ]]; then
		return 0 # true
	elif [[ $lb_default == "off-by-default" ]]; then
		return 1 # false
	fi

	logger -p err -t checkuplink "Invalid loadbalancing parameter '${lb_default}', assuming 'off'"
	return 0
}

get_wgkex_data(){
	local version user_agent
	version="$1"
	WGKEX_BROKER="$PROTO://$WGKEX_BROKER_BASE_PATH/api/$version/wg/key/exchange"
	user_agent=$(lua /lib/gluon/gluon-mesh-wireguard-vxlan/get-user-agent-infos.lua)

	logger -p info -t checkuplink "Contacting wgkex broker $WGKEX_BROKER"

	if ! WGKEX_DATA=$(force_wan_connection wget -q -U "$user_agent"  -O- --post-data='{"domain": "'"$SEGMENT"'","public_key": "'"$PUBLICKEY"'"}' "$WGKEX_BROKER"); then
		logger -p err -t checkuplink "Contacting wgkex broker failed, response: $WGKEX_DATA"
	else
		logger -p info -t checkuplink "Got data from wgkex broker: $WGKEX_DATA"
		echo "$WGKEX_DATA"
	fi
}

use_api_v1(){
	WGKEX_DATA=$(get_wgkex_data v1)

	# Parse the returned JSON in a Lua script
	if ! data=$(lua /lib/gluon/gluon-mesh-wireguard-vxlan/parse-wgkex-response.lua "$WGKEX_DATA" "v1"); then
		logger -p err -t checkuplink "Parsing wgkex v1 broker data failed"
		return 1
	fi

	# Get the number of configured peers and randomly select one
	NUMBER_OF_PEERS=$(uci -q show wireguard | grep -E -ce "peer_[0-9]+.endpoint")

	# Do not use awk's srand() as it only uses second-precision for the initial seed that leads to many routers getting the same "random" number
	# /dev/urandom + busybox' hexdump will provide sufficently "good" random numbers on a router with at least "-n 4"
	PEER=$(( $(hexdump -n 4 -e '"%u"' </dev/urandom) % NUMBER_OF_PEERS + 1 ))

	logger -p info -t checkuplink "Selected peer $PEER"
	export PEER_HOSTPORT="$(uci get wireguard.peer_"$PEER".endpoint)"
	export PEER_HOST="$(clean_port "$PEER_HOSTPORT")"
	export PEER_ADDRESS="$(resolve_host "$PEER_HOST")"
	export PEER_PORT="$(extract_port "$PEER_HOSTPORT")"
	export PEER_ENDPOINT="$(combine_ip_port "$PEER_ADDRESS" "$PEER_PORT")"

	export PEER_PUBLICKEY="$(uci get wireguard.peer_"$PEER".publickey)"
	export PEER_LINKADDRESS="$(uci get wireguard.peer_"$PEER".link_address)"
}

use_api_v2() {
	WGKEX_DATA=$(get_wgkex_data v2)

	# Parse the returned JSON in a Lua script, returning the endpoint address, port, pubkey and first allowed IP, separated by newlines
	if ! data=$(lua /lib/gluon/gluon-mesh-wireguard-vxlan/parse-wgkex-response.lua "$WGKEX_DATA" "v2"); then
		logger -p err -t checkuplink "Parsing wgkex v2 broker data failed"
		logger -p info -t checkuplink "Falling back to API v1"
		use_api_v1
		return
	fi

	logger -p debug -t checkuplink "Successfully parsed wgkex v2 broker data"
	export PEER_HOST="$(echo "$data" | sed -n 1p)"
	export PEER_PORT="$(echo "$data" | sed -n 2p)"
	export PEER_PUBLICKEY="$(echo "$data" | sed -n 3p)"
	export PEER_LINKADDRESS=$(echo "$data" | sed -n 4p)

	export PEER_ADDRESS="$(resolve_host "$PEER_HOST")"
	export PEER_ENDPOINT="$(combine_ip_port "$PEER_ADDRESS" "$PEER_PORT")"
}

use_api_best_gw() {
	WGKEX_DATA=$(get_wgkex_data v2)

	# Parse the returned JSON in a Lua script, returning the endpoint address, port, pubkey, first allowed IP and peer switch, separated by newlines
	if ! data=$(lua /lib/gluon/gluon-mesh-wireguard-vxlan/parse-wgkex-response.lua "$WGKEX_DATA" "best-gw"); then
		logger -p err -t checkuplink "Parsing wgkex wg broker data failed"
		return
	fi

	logger -p debug -t checkuplink "Successfully parsed wgkex gw broker data "
	export PEER_HOST="$(echo "$data" | sed -n 1p)"
	export PEER_PORT="$(echo "$data" | sed -n 2p)"
	export PEER_PUBLICKEY="$(echo "$data" | sed -n 3p)"
	export PEER_LINKADDRESS=$(echo "$data" | sed -n 4p)
    export PEER_SWITCH=$(echo "$data" | sed -n 5p)

	export PEER_ADDRESS="$(resolve_host "$PEER_HOST")"
	export PEER_ENDPOINT="$(combine_ip_port "$PEER_ADDRESS" "$PEER_PORT")"
}

is_connected() {
	if wget "http://[$(wg  | grep fe80 | awk '{split($3,A,"/")};{print A[1]}')%$MESH_VPN_IFACE]/"  --timeout=5 -O/dev/null -q
	then
		GWMAC=$(batctl gwl | awk '/[*]/{print $2}')
		if batctl ping -c 5 "$GWMAC" > /dev/null 2>&1
		then
			return 0 # true
		fi
	fi
	return 1 # false
}

set_PROTO() {
    # Push public key to broker and receive gateway data, test for https and use if supported
    ret=0
    wget -q "https://[::1]" || ret=$?
    # returns Network Failure =4 if https exists
    # and Generic Error =1 if no ssl lib available
    if [ "$ret" -eq 1 ]; then
        export PROTO=http
    else
        export PROTO=https
    fi
}

init_vars() {
    set_PROTO
    # Remove API path suffix if still present in config
    export WGKEX_BROKER_BASE_PATH="$(get_site_string mesh_vpn.wireguard.broker | sed 's|/api/v1/wg/key/exchange||')"

    export PUBLICKEY=$(uci get wireguard.mesh_vpn.privatekey | wg pubkey)
    export SEGMENT=$(uci get gluon.core.domain)
    export MESH_VPN_IFACE=$(get_site_string mesh_vpn.wireguard.iface)
}
