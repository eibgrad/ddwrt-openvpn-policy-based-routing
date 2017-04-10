#!/bin/sh
export DEBUG= # uncomment/comment to enable/disable debug mode

#         name: ddwrt-ovpn-split-advanced.sh
#      version: 0.1.6 (beta), 09-apr-2017, by eibgrad
#      purpose: redirect specific traffic over the WAN|VPN
#  script type: jffs script called from startup script
# instructions:
#   1. add/modify rules to/in script for rerouting purposes; alternatively,
#      rules may be imported from filesystem using extension .rule:
#        /jffs/myrules.rule
#        /jffs/myrules2.rule
#   2. copy modified script to /jffs (or external storage, e.g., usb)
#   3. make script executable:
#        chmod +x /jffs/ddwrt-ovpn-split-advanced.sh
#   4. call this script from the startup script:
#        /jffs/ddwrt-ovpn-split-advanced.sh
#   5. optional: to set/lockdown the default gateway to WAN/ISP and use
#      rules to reroute to VPN, add the following to the openvpn client
#      additional config field:
#        route-noexec
#   6. disable policy based routing (services->vpn->openvpn client)
#   7. disable nat loopback (security->firewall, "filter wan nat redirection"
#      must be checked)
#   8. disable qos (nat/qos->qos)
#   9. enable syslogd (services->services->system log)
#  10. reboot router
#  limitations:
#    - this script is NOT compatible w/ policy based routing in the
#      openvpn client gui
#    - this script is NOT compatible w/ nat loopback
#    - this script is NOT compatible w/ qos

# WARNING: do NOT skip steps #6 thru #9 or it won't work!

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
# * remote access is already enabled; no additional rules are necessary
# ---------------------------------------------------------------------------- #

# ------------------------------- BEGIN RULES -------------------------------- #
add_rule -s 192.168.1.10
add_rule -p tcp -s 192.168.1.112 --dport 80
add_rule -p tcp -s 192.168.1.122 --dport 3000:3100
add_rule -i br1 # guest network
add_rule -i br2 # iot network
add_rule -d amazon.com # domain names NOT recommended
# -------------------------------- END RULES --------------------------------- #
:;}

# include user-defined rules
INCLUDE_USER_DEFINED_RULES= # uncomment/comment to enable/disable

# route openvpn dns server(s) through tunnel
ROUTE_DNS_THRU_VPN= # uncomment/comment to enable/disable

# ---------------------- DO NOT CHANGE BELOW THIS LINE ----------------------- #

IMPORT_DIR="$(dirname $0)"
IMPORT_RULE_EXT="rule"
IMPORT_RULE_FILESPEC="$IMPORT_DIR/*$IMPORT_RULE_EXT"

OVPN_DIR="/tmp/openvpncl"
OVPN_CONF="$OVPN_DIR/openvpn.conf"
OVPN_ROUTE_UP="$OVPN_DIR/route-up.sh"
OVPN_ROUTE_DOWN="$OVPN_DIR/route-down.sh"

ENV_VARS="$WORK_DIR/env_vars"
RPF_VARS="$WORK_DIR/rpf_vars"
ADDED_ROUTES="$WORK_DIR/added_routes"

# initialize work files
if [ "$script_type" == "route-up" ]; then
    # make environment variables persistent across openvpn events
    env > $ENV_VARS

    > $RPF_VARS
    > $ADDED_ROUTES
fi

env_get() { echo $(grep -Em1 "^$1=" $ENV_VARS | cut -d = -f2); }

TID="200" # valid values: 1-255
WAN_GW="$(env_get route_net_gateway)"
WAN_IF="$(route -n | awk '/^0.0.0.0/{wif=$NF} END {print wif}')"
VPN_GW="$(env_get route_vpn_gateway)"
VPN_IF="$(env_get dev)"

FW_CHAIN="ovpn_split"
FW_MARK=1

IPT_MAN="iptables -t mangle"
IPT_MARK_MATCHED="-j MARK --set-mark $FW_MARK"
IPT_MARK_NOMATCH="-j MARK --set-mark $((FW_MARK + 1))"

add_rule() {
    $IPT_MAN -D $FW_CHAIN "$@" $IPT_MARK_MATCHED 2> /dev/null
    $IPT_MAN -A $FW_CHAIN "$@" $IPT_MARK_MATCHED
}

install_nf_modules() {
    for i in $(cat /lib/modules/*/modules.dep | \
            grep -Eo '^.*/(ipt|xt)_[^:]*'); do
        insmod $i && echo "module added: $i"
    done
}

up() {
    [ ${DEBUG+x} ] && cat $ENV_VARS

    # call dd-wrt route-up script
    $OVPN_ROUTE_UP

    # bug fix: http://svn.dd-wrt.com/ticket/5697
    touch /tmp/resolv.dnsmasq

    # add chain for user-defined rules
    $IPT_MAN -N $FW_CHAIN
    $IPT_MAN -A PREROUTING -j $FW_CHAIN

    # initialize chain for user-defined rules
    $IPT_MAN -A $FW_CHAIN -j CONNMARK --restore-mark
    $IPT_MAN -A $FW_CHAIN -m mark ! --mark 0 -j RETURN

    # add rule for remote access over WAN or VPN
    if [ "$(env_get redirect_gateway)" == "1" ]; then
        # enable all remote access over the WAN
        add_rule -i $WAN_IF
    else
        # enable all remote access over the VPN
        add_rule -i $VPN_IF
    fi

    # add user-defined rules to chain
    if [ ${INCLUDE_USER_DEFINED_RULES+x} ]; then
        local files="$(echo $IMPORT_RULE_FILESPEC)"

        if [ "$files" != "$IMPORT_RULE_FILESPEC" ]; then
            # import rules from filesystem
            for file in $files; do . $file; done
        else
            # use embedded rules
            add_rules
        fi
    fi

    # finalize chain for user-defined rules
    $IPT_MAN -A $FW_CHAIN -m mark ! --mark $FW_MARK $IPT_MARK_NOMATCH
    $IPT_MAN -A $FW_CHAIN -j CONNMARK --save-mark

    # add rules (router only)
    $IPT_MAN -A OUTPUT -j CONNMARK --restore-mark

    # clear marks (not available on all builds)
    [ -e /proc/net/clear_marks ] && echo 1 > /proc/net/clear_marks

    # route-noexec directive requires client to handle routes
    if grep -Eq '^[[:space:]]*route-noexec' $OVPN_CONF; then
        local i=0

        # search for openvpn routes
        while :; do
            i=$((i + 1))
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

    # disable reverse path filtering
    for rpf in /proc/sys/net/ipv4/conf/*/rp_filter; do
        echo "echo $(cat $rpf) > $rpf" >> $RPF_VARS
        echo 0 > $rpf
    done

    # start split tunnel
    ip rule add fwmark $FW_MARK table $TID
}

down() {
    # stop split tunnel
    while ip rule del fwmark $FW_MARK table $TID 2> /dev/null
        do :; done

    # enable reverse path filtering
    while read rpf; do $rpf; done < $RPF_VARS

    # remove added routes
    while read route; do $route; done < $ADDED_ROUTES

    # remove rules
    while $IPT_MAN -D PREROUTING -j $FW_CHAIN 2> /dev/null
        do :; done
    $IPT_MAN -F $FW_CHAIN
    $IPT_MAN -X $FW_CHAIN
    $IPT_MAN -D OUTPUT -j CONNMARK --restore-mark

    # clear marks (not available on all builds)
    [ -e /proc/net/clear_marks ] && echo 1 > /proc/net/clear_marks

    # delete alternate routing table
    ip route flush table $TID

    # force routing system to recognize changes
    ip route flush cache

    # cleanup work files
    rm -f $ENV_VARS $RPF_VARS $ADDED_ROUTES

    # call dd-wrt route-pre-down script
    $OVPN_ROUTE_DOWN
}

main() {
    # reject cli invocation; script only applicable to routed (tun) tunnels
    [[ -t 0 || "$(env_get dev_type)" != "tun" ]] && return 1

    # install additional netfilter modules
    install_nf_modules

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

# uncomment/comment to enable/disable the following options
#ONE_PASS= # one pass only; do NOT run continously in background
CONFIG_SECURE_FIREWALL= # http://www.dd-wrt.com/phpBB2/viewtopic.php?t=307445
CONFIG_NAT_LOOPBACK= # replaces dd-wrt nat loopback
#DEL_PERSIST_TUN= # may help w/ "N RESOLVE" problems
#DEL_MTU_DISC= # http://svn.dd-wrt.com/ticket/5718

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

configure_nat_loopback() {
    local i=""

    # search for local ip networks
    while :; do
        local lan_ip="$(nvram get lan${i}_ipaddr)"

        [ $lan_ip ] || break

        local lan_net="$lan_ip/$(nvram get lan${i}_netmask)"
        local lan_if="$(nvram get lan${i}_ifname)"

        # source nat any local ip network routed back into its own network
        iptables -t nat -D POSTROUTING -s $lan_net -o $lan_if -d $lan_net \
            -j SNAT --to $lan_ip 2> /dev/null
        iptables -t nat -A POSTROUTING -s $lan_net -o $lan_if -d $lan_net \
            -j SNAT --to $lan_ip

        [ ! $i ] && i=1 || i=$((i + 1))
    done
}

config_add() { grep -Eq "^$1$" $OVPN_CONF || echo "$1" >> $OVPN_CONF; }
config_rep() { sed -ri "s/^$1$/$2/" $OVPN_CONF; }
config_del() { sed -ri "/^$1/d" $OVPN_CONF; } # note: lazy match

# wait for syslog to come up
while [ ! -e /var/log/messages ]; do sleep $SLEEP; done

# wait for initial openvpn client connection to be established
while ! grep -qi '[i]nitialization sequence completed' /var/log/messages
    do sleep $SLEEP; done

err_found=false

# policy based routing must be disabled (ip rules conflict)
if [ "$(nvram get openvpncl_route)" ]; then
    echo "fatal error: policy based routing must be disabled"
    err_found=true
fi

# nat loopback must be disabled (packet marking conflict)
if [ "$(nvram get block_loopback)" == "0" ]; then
    echo "fatal error: nat loopback must be disabled"
    err_found=true
fi

# qos must be disabled (packet marking conflict)
if [ "$(nvram get wshaper_enable)" == "1" ]; then
    echo "fatal error: qos must be disabled"
    err_found=true
fi

# quit if we fail to meet any prerequisites
if [[ $err_found == true ]]; then
    echo "exiting on fatal error(s); correct and reboot"
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

    # optional: enable nat loopback (no packet marking conflicts)
    [ ${CONFIG_NAT_LOOPBACK+x} ] && configure_nat_loopback

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
