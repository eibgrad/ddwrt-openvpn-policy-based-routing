#!/bin/sh
export DEBUG= # uncomment/comment to enable/disable debug mode

#         name: ddwrt-ovpn-split-basic.sh
#      version: 1.0.0, 15-jan-2018, by eibgrad
#      purpose: redirect specific traffic over the WAN|VPN
#  script type: jffs script called from startup script
# instructions:
#   1. add/modify rules to/in script for rerouting purposes; alternatively,
#      rules may be imported from filesystem using extension .rule:
#        /jffs/myrules.rule
#        /jffs/myrules2.rule
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
#    - this script is NOT compatible w/ dd-wrt policy based routing
#    - rules are limited to source ip/network/interface and destination
#      ip/network; split tunneling within any given source or destination
#      (protocol, port, etc.) is NOT supported
#    - rules do NOT support domain names (e.g., google.com)

# WARNING: do NOT skip steps #6 or #7 or it won't work!

WORK_DIR="/tmp/ovpn_split"
OVPN_SPLIT="$WORK_DIR/ovpn-split.sh"
OVPN_MONITOR="$WORK_DIR/ovpn-monitor.sh"

mkdir -p $WORK_DIR

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
# ------------------------------ BEGIN OPTIONS ------------------------------- #

# include user-defined rules
INCLUDE_USER_DEFINED_RULES= # uncomment/comment to enable/disable

# route openvpn dns server(s) through tunnel
ROUTE_DNS_THRU_VPN= # uncomment/comment to enable/disable

# ------------------------------- END OPTIONS -------------------------------- #

# ---------------------- DO NOT CHANGE BELOW THIS LINE ----------------------- #

IMPORT_DIR="$(dirname $0)"
IMPORT_RULE_EXT="rule"
IMPORT_RULE_FILESPEC="$IMPORT_DIR/*.$IMPORT_RULE_EXT"

OVPN_DIR="/tmp/openvpncl"
OVPN_CONF="$OVPN_DIR/openvpn.conf"
OVPN_ROUTE_UP="$OVPN_DIR/route-up.sh"
OVPN_ROUTE_DOWN="$OVPN_DIR/route-down.sh"

ENV_VARS="$WORK_DIR/env_vars"
ADDED_ROUTES="$WORK_DIR/added_routes"

# initialize work files
if [ "$script_type" == "route-up" ]; then
    # make environment variables persistent across openvpn events
    env > $ENV_VARS

    > $ADDED_ROUTES
fi

env_get() { echo $(grep -Em1 "^$1=" $ENV_VARS | cut -d = -f2); }

TID="200" # valid values: 1-255
WAN_GW="$(env_get route_net_gateway)"
VPN_GW="$(env_get route_vpn_gateway)"

add_rule() {
    ip rule del table $TID "$@" 2> /dev/null
    ip rule add table $TID "$@"
}

up() {
    [ ${DEBUG+x} ] && cat $ENV_VARS

    # call dd-wrt route-up script
    $OVPN_ROUTE_UP

    # bug fix: http://svn.dd-wrt.com/ticket/5697
    touch /tmp/resolv.dnsmasq

    # route-noexec directive requires client to handle routes
    if grep -Eq '^[[:space:]]*route-noexec' $OVPN_CONF; then
        local i=1

        # search for openvpn routes
        while :; do
            local network="$(env_get route_network_$i)"

            [ "$network" ] || break

            local netmask="$(env_get route_netmask_$i)"
            local gateway="$(env_get route_gateway_$i)"

            [ "$netmask" ] || netmask="255.255.255.255"

            # add host/network route
            if route add -net $network netmask $netmask gw $gateway; then
                echo "route del -net $network netmask $netmask gw $gateway" \
                    >> $ADDED_ROUTES
            fi

            i=$((i + 1))
        done
    fi

    # route openvpn dns servers through the tunnel
    if [ ${ROUTE_DNS_THRU_VPN+x} ]; then
        awk '/dhcp-option DNS/{print $3}' $ENV_VARS \
          | while read ip; do
                if ip route add $ip via $VPN_GW; then
                    echo "ip route del $ip via $VPN_GW" >> $ADDED_ROUTES
                fi
            done
    fi

    # copy main routing table to alternate (exclude all default gateways)
    ip route show | grep -Ev '^default |^0.0.0.0/1 |^128.0.0.0/1 ' \
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
    if [ ${INCLUDE_USER_DEFINED_RULES+x} ]; then
        local files="$(echo $IMPORT_RULE_FILESPEC)"

        if [ "$files" != "$IMPORT_RULE_FILESPEC" ]; then
            # import (source) rules from filesystem
            for file in $files; do . $file; done
        else
            # use embedded rules
            add_rules
        fi
    fi
}

down() {
    # stop split tunnel
    while ip rule del from 0/0 to 0/0 table $TID 2> /dev/null
        do :; done

    # remove added routes
    while read route; do $route; done < $ADDED_ROUTES

    # delete alternate routing table
    ip route flush table $TID

    # force routing system to recognize changes
    ip route flush cache

    # cleanup
    rm -f $ENV_VARS $ADDED_ROUTES

    # call dd-wrt route-pre-down script
    $OVPN_ROUTE_DOWN
}

main() {
    # reject cli invocation; script only applicable to routed (tun) tunnels
    [[ -t 0 || "$(env_get dev_type)" != "tun" ]] && return 1

    # trap event-driven callbacks by openvpn and take appropriate action(s)
    case "$script_type" in
              "route-up")   up;;
        "route-pre-down") down;;
                       *) echo "WARNING: unexpected invocation: $script_type";;
    esac

    return 0
}

main

) 2>&1 | logger -t $(basename $0)[$$]
EOF
sed -i \
    -e "s:\$WORK_DIR:$WORK_DIR:g" \
    -e "s:\$(dirname \$0):$(dirname $0):g" $OVPN_SPLIT
[ ${DEBUG+x} ] || sed -ri 's/^DEBUG=/#DEBUG=/g' $OVPN_SPLIT
chmod +x $OVPN_SPLIT
# ------------------------------ END OVPN_SPLIT ------------------------------ #

# create symbolic links for script
ln -sf $OVPN_SPLIT $WORK_DIR/route-up
ln -sf $OVPN_SPLIT $WORK_DIR/route-pre-down

# ---------------------------- BEGIN OVPN_MONITOR ---------------------------- #
cat << "EOF" > $OVPN_MONITOR
#!/bin/sh
DEBUG=
(
[ ${DEBUG+x} ] && set -x

# one pass only; do NOT run continously in background
#ONE_PASS= # uncomment/comment to enable/disable

# http://www.dd-wrt.com/phpBB2/viewtopic.php?t=307445
CONFIG_SECURE_FIREWALL= # uncomment/comment to enable/disable

# replace dd-wrt nat loopback w/ compatible implementation
CONFIG_NAT_LOOPBACK= # uncomment/comment to enable/disable

# may help w/ "N RESOLVE" and soft-restart problems
#DEL_PERSIST_TUN= # uncomment/comment to enable/disable

# http://svn.dd-wrt.com/ticket/5718
#DEL_MTU_DISC= # uncomment/comment to enable/disable

# ---------------------- DO NOT CHANGE BELOW THIS LINE ----------------------- #

OVPN_CONF="/tmp/openvpncl/openvpn.conf"
OVPN_PID="/tmp/var/run/openvpncl.pid"

SLEEP=10

curr_pid=""

configure_secure_firewall() {
    _ipt() {
        # precede insert/append w/ deletion to avoid dups
        while iptables ${@/-[IA]/-D} 2> /dev/null; do :; done
        iptables $@
    }

    # allow inbound traffic over the tunnel
    _ipt -I INPUT -i tun0 -j ACCEPT

    # deny new inbound connections over the tunnel
    _ipt -I INPUT -i tun0 -m state --state NEW -j DROP
    _ipt -I FORWARD -i tun0 -m state --state NEW -j DROP

    if [ "$(nvram get openvpncl_nat)" == "1" ]; then
        # nat all outbound traffic over the tunnel
        _ipt -t nat -I POSTROUTING -o tun0 -j MASQUERADE
    fi
}

config_add() { grep -Eq "^$1$" $OVPN_CONF || echo "$1" >> $OVPN_CONF; }
config_rep() { sed -ri "s/^$1$/$2/" $OVPN_CONF; }
config_del() { sed -ri "/^$1/d" $OVPN_CONF; } # lazy match

# wait for syslog to come up
while [ ! -e /var/log/messages ]; do sleep $SLEEP; done

# wait for initial openvpn client connection to be established
while ! grep -qi '[i]nitialization sequence completed' /var/log/messages
    do sleep $SLEEP; done

# policy based routing must be disabled (ip rules conflict)
if [ "$(nvram get openvpncl_route)" ]; then
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
    [ ${CONFIG_SECURE_FIREWALL+x} ] && config_add 'dev tun0'
    [ ${DEL_PERSIST_TUN+x} ] && config_del persist-tun
    [ ${DEL_MTU_DISC+x} ] && config_del mtu-disc

    # restart openvpn client w/ our configuration changes
    if ! openvpn --config $OVPN_CONF \
                 --route-up $WORK_DIR/route-up \
                 --route-pre-down $WORK_DIR/route-pre-down \
                 --daemon; then
        continue
    fi

    # optional: http://www.dd-wrt.com/phpBB2/viewtopic.php?t=307445
    [ ${CONFIG_SECURE_FIREWALL+x} ] && configure_secure_firewall

    # optional: limit to one pass
    [ ${ONE_PASS+x} ] && { echo "done"; exit; }

    # wait for change in process id, then save it
    while [ "$(cat $OVPN_PID)" == "$curr_pid" ]
        do sleep $((SLEEP / 2)); done
    curr_pid="$(cat $OVPN_PID)"

    # wait for openvpn client to stop/restart (process id will change)
    while [ "$(pidof openvpn)" == "$curr_pid" ]
        do sleep $((SLEEP * 2)); done
done
) 2>&1 | logger -t $(basename $0)[$$]
EOF
sed -i "s:\$WORK_DIR:$WORK_DIR:g" $OVPN_MONITOR
[ ${DEBUG+x} ] || sed -ri 's/^DEBUG=/#DEBUG=/g' $OVPN_MONITOR
chmod +x $OVPN_MONITOR
# ----------------------------- END OVPN_MONITOR ----------------------------- #

# start the monitor
nohup $OVPN_MONITOR > /dev/null 2>&1 &
