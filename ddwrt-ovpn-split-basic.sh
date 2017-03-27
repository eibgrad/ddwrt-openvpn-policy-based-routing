#!/bin/sh
export DEBUG= # uncomment/comment to enable/disable debug mode

#         name: ddwrt-ovpn-split-basic.sh
#      version: 0.1.4 (beta), 26-mar-2017, by eibgrad
#      purpose: redirect specific traffic over the WAN|VPN
#  script type: jffs script called from startup script
# instructions:
#   1. add/modify rules for rerouting purposes
#   2. copy modified script to /jffs (or external storage, e.g., usb)
#   3. make script executable:
#        chmod +x /jffs/ddwrt-ovpn-split-basic.sh
#   4. call this script from the startup script:
#        /jffs/ddwrt-ovpn-split-basic.sh
#   5. optional: to set/lockdown the default gateway to WAN/ISP and use
#      rules to reroute to VPN, add the following to the openvpn client
#      additional config field:
#        route-noexec
#   6. disable policy based routing (services->vpn->openvpn client)
#   7. enable syslogd (services->services->system log)
#   8. reboot router
#  limitations:
#    - this script is NOT compatible w/ policy based routing in the
#      openvpn client gui
#    - rules are limited to source ip/network/interface and destination
#      ip/network; split tunneling within any given source or destination
#      (protocol, port, etc.) is NOT supported
#    - rules do NOT support domain names (e.g., google.com)

# WARNING: do NOT skip steps #6 or #7 or it won't work!

OVPN_DIR="/tmp/ovpn_split"
OVPN_SPLIT="$OVPN_DIR/ovpn-split.sh"
OVPN_MONITOR="$OVPN_DIR/ovpn-monitor.sh"

mkdir -p $OVPN_DIR

# ----------------------------- BEGIN OVPN_SPLIT ----------------------------- #
cat << "EOF" > $OVPN_SPLIT
#!/bin/sh
DEBUG=
(
[ ${DEBUG+x} ] && set -x

add_rules() {

# ----------------------------------- FYI ------------------------------------ #
# * the order of rules doesn't matter (there is no order of precedence)
# * if any rule matches, those packets bypass the current default gateway
# ---------------------------------------------------------------------------- #

# ------------------------------- BEGIN RULES -------------------------------- #

# specify source ip(s)/network(s)/interface(s) to be rerouted
add_rule iif br1 # guest network
add_rule from 192.168.1.7 # mary's pc
#add_rule from 192.168.1.14
add_rule from 192.168.2.0/24 # iot network

# specify destination ip(s)/network(s) to be rerouted
add_rule to 4.79.142.0/24 # grc.com
add_rule to 172.217.6.142 # maps.google.com

# specify source + destination to be rerouted
add_rule iif br2 to 121.121.121.121
add_rule from 192.168.1.14 to 104.25.112.26 # ipchicken.com
add_rule from 192.168.1.14 to 104.25.113.26 # ipchicken.com
#add_rule from 192.168.1.113 to 45.79.3.202 # infobyip.com
add_rule from 192.168.1.10 to 122.122.122.122
add_rule from 192.168.2.0/24 to 133.133.133.0/24

# -------------------------------- END RULES --------------------------------- #
:;}

# route openvpn dns server(s) through tunnel
ROUTE_DNS_THRU_VPN= # uncomment/comment to enable/disable

# ---------------------- DO NOT CHANGE BELOW THIS LINE ----------------------- #

OVPN_CONF="/tmp/openvpncl/openvpn.conf"
OVPN_ROUTE_UP="/tmp/openvpncl/route-up.sh"
OVPN_ROUTE_DOWN="/tmp/openvpncl/route-down.sh"

ENV_VARS="$OVPN_DIR/env_vars"

# make environment variables persistent across openvpn events
[ "$script_type" == "route-up" ] && env > $ENV_VARS

env_get() { echo $(egrep -m1 "^$1=" $ENV_VARS | cut -d = -f2); }

TID="200" # valid values: 1-255
WAN_GW="$(env_get route_net_gateway)"
VPN_GW="$(env_get route_vpn_gateway)"

add_rule() { ip rule add table $TID "$@"; }

handle_openvpn_routes() {
    local op="$([ "$script_type" == "route-up" ] && echo add || echo del)"

    # route-noexec directive requires client to handle routes
    if egrep -q '^[[:space:]]*route-noexec' $OVPN_CONF; then
        local i=0

        # search for openvpn routes
        while :; do
            i=$((i + 1))
            local network="$(env_get route_network_$i)"

            [ $network ] || break

            local netmask="$(env_get route_netmask_$i)"
            local gateway="$(env_get route_gateway_$i)"

            [ $netmask ] || netmask="255.255.255.255"

            # add/delete host/network route
            route $op -net $network netmask $netmask gw $gateway
        done
    fi

    # route openvpn dns servers through the tunnel
    if [ ${ROUTE_DNS_THRU_VPN+x} ]; then
        awk '/dhcp-option DNS/{print $3}' $ENV_VARS \
          | while read ip; do
                ip route $op $ip via $VPN_GW
            done
    fi
}

up() {
    [ ${DEBUG+x} ] && cat $ENV_VARS

    # call dd-wrt route-up script
    $OVPN_ROUTE_UP

    # special handler for openvpn routes
    handle_openvpn_routes

    # copy main routing table to alternate (exclude all default gateways)
    ip route show | egrep -v '^default |^0.0.0.0/1 |^128.0.0.0/1 ' \
      | while read route; do
            ip route add $route table $TID
        done

    if [ "$(env_get redirect_gateway)" == "1" ]; then
        # add WAN as default gateway to alternate routing table
        ip route add default via $WAN_GW table $TID
    else
        # add VPN as default gateway to alternate routing table
        ip route add default via $VPN_GW table $TID
    fi

    # force routing system to recognize changes
    ip route flush cache

    # start split tunnel
    add_rules
}

down() {
    # stop split tunnel
    while ip rule del from 0/0 to 0/0 table $TID 2> /dev/null
        do :; done

    # delete alternate routing table
    ip route flush table $TID

    # special handler for openvpn routes
    handle_openvpn_routes

    # force routing system to recognize changes
    ip route flush cache

    # cleanup
    rm -f $ENV_VARS

    # call dd-wrt route-pre-down script
    $OVPN_ROUTE_DOWN
}

main() {
    # reject cli invocation; script only applicable to routed (tun) tunnels
    [[ -t 0 || "$(env_get dev_type)" != "tun" ]] && return 1

    # trap event-driven callbacks by openvpn and take appropriate action(s)
    case "$script_type" in
              "route-up")   up "$@";;
        "route-pre-down") down "$@";;
                       *) echo "WARNING: unexpected invocation: $script_type";;
    esac

    return 0
}

main "$@"

) 2>&1 | logger -t $(basename $0)[$$]
EOF
sed -i "s:\$OVPN_DIR:$OVPN_DIR:" $OVPN_SPLIT
[ ${DEBUG+x} ] || sed -ri 's/^DEBUG=/#DEBUG=/' $OVPN_SPLIT
chmod +x $OVPN_SPLIT
# ------------------------------ END OVPN_SPLIT ------------------------------ #

# create symbolic links for script
ln -sf $OVPN_SPLIT $OVPN_DIR/route-up
ln -sf $OVPN_SPLIT $OVPN_DIR/route-pre-down

# ---------------------------- BEGIN OVPN_MONITOR ---------------------------- #
cat << "EOF" > $OVPN_MONITOR
#!/bin/sh
DEBUG=
(
[ ${DEBUG+x} ] && set -x

# uncomment/comment to enable/disable the following options
#ONE_PASS= # one pass only; do NOT run continously in background
#DEL_PERSIST_TUN= # may help w/ "N RESOLVE" problems
#DEL_MTU_DISC= # http://svn.dd-wrt.com/ticket/5718
#TOUCH_DNSMASQ= # http://svn.dd-wrt.com/ticket/5697

# ---------------------- DO NOT CHANGE BELOW THIS LINE ----------------------- #

OVPN_CONF="/tmp/openvpncl/openvpn.conf"
OVPN_PID="/tmp/var/run/openvpncl.pid"

SLEEP=10

curr_pid=""

config_add() { egrep -q "^$1$" $OVPN_CONF || echo "$1" >> $OVPN_CONF; }
config_rep() { sed -ri "s/^$1$/$2/" $OVPN_CONF; }
config_del() { sed -ri "/^$1/d" $OVPN_CONF; } # lazy match

# wait for syslog to come up
while [ ! -e /var/log/messages ]; do sleep $SLEEP; done

# wait for initial openvpn client connection to be established
while ! grep -qi '[i]nitialization sequence completed' /var/log/messages
    do sleep $SLEEP; done

# policy based routing must be disabled (ip rules conflict)
if [ $(nvram get openvpncl_route) ]; then
    echo "fatal error: policy based routing must be disabled"
    echo "exiting on fatal error; correct and reboot"
    exit
fi

# monitor openvpn client start/stop
while :; do
    # wait for openvpn client to (re)start, then kill it
    while ! pidof openvpn > /dev/null 2>&1; do sleep $SLEEP; done
    while ! killall openvpn; do sleep $SLEEP; done
    while   pidof openvpn > /dev/null 2>&1; do sleep $SLEEP; done

    # make adjustments to openvpn config file
    [ ${DEL_PERSIST_TUN+x} ] && config_del persist-tun
    [ ${DEL_MTU_DISC+x}    ] && config_del mtu-disc

    # restart openvpn client w/ our configuration changes
    if ! openvpn --config $OVPN_CONF \
                 --route-up $OVPN_DIR/route-up \
                 --route-pre-down $OVPN_DIR/route-pre-down \
                 --daemon; then
        continue
    fi

    # http://svn.dd-wrt.com/ticket/5697
    [ ${TOUCH_DNSMASQ+x} ] && touch /tmp/resolv.dnsmasq

    # optional: limit to one pass
    [ ${ONE_PASS+x} ] && { echo "done"; exit; }

    # save the new process id
    while [ "$(cat $OVPN_PID)" == "$curr_pid" ]
        do sleep $((SLEEP / 2)); done
    curr_pid="$(cat $OVPN_PID)"

    # wait for openvpn client to stop/restart (process id will change)
    while [ "$(pidof openvpn)" == "$curr_pid" ]
        do sleep $((SLEEP * 2)); done
done

echo "done"
) 2>&1 | logger -t $(basename $0)[$$]
EOF
sed -i "s:\$OVPN_DIR:$OVPN_DIR:" $OVPN_MONITOR
[ ${DEBUG+x} ] || sed -ri 's/^DEBUG=/#DEBUG=/' $OVPN_MONITOR
chmod +x $OVPN_MONITOR
# ----------------------------- END OVPN_MONITOR ----------------------------- #

# start the monitor
nohup $OVPN_MONITOR > /dev/null 2>&1 &