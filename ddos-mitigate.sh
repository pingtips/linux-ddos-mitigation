#!/bin/bash

CHAIN="pingtips"
DROP_CHAIN="pingtips_drop"
INTERFACE="$2"
WHITELIST_SET="whitelist_ips"
BLOCKED_SET="blocked_ips"
TABLE="raw"

if [ "$1" == "on" ]; then
    # Create ipsets if they don't exist
    ipset create $WHITELIST_SET hash:ip -exist 
    ipset create $BLOCKED_SET hash:ip timeout 600 -exist 

    # Create chains if they don't exist
    iptables -t $TABLE -N $CHAIN 2>/dev/null 
    iptables -t $TABLE -N $DROP_CHAIN 2>/dev/null

    # Clear existing rules
    iptables -t $TABLE -F $CHAIN
    iptables -t $TABLE -F $DROP_CHAIN
    iptables -t $TABLE -D PREROUTING -i "$INTERFACE" -p tcp --syn -j $CHAIN 2>/dev/null

    # Add rule to allow traffic from whitelist
    iptables -t $TABLE -A $CHAIN -m set --match-set $WHITELIST_SET src -j ACCEPT

    # Populate whitelist with currently logged-in admin IPs
    w | grep -oE '[[:digit:]]{1,3}\.[[:digit:]]{1,3}\.[[:digit:]]{1,3}\.[[:digit:]]{1,3}' | while read IP; do
        ipset add $WHITELIST_SET "$IP" -exist 
    done

    # Add rule to block traffic from blocked set
    iptables -t $TABLE -A $CHAIN -m set --match-set $BLOCKED_SET src -j DROP

    # Hashlimit rules
    iptables -t $TABLE -A $CHAIN -m hashlimit --hashlimit-name port_limit \
        --hashlimit-above 10/sec --hashlimit-burst 50 --hashlimit-mode srcport \
        -p tcp --syn -j $DROP_CHAIN
    iptables -t $TABLE -A $CHAIN -m hashlimit --hashlimit-name ip_limit \
        --hashlimit-above 10/sec --hashlimit-burst 50 --hashlimit-mode srcip \
        -p tcp --syn -j $DROP_CHAIN
    iptables -t $TABLE -A $CHAIN -m hashlimit --hashlimit-name net_limit \
        --hashlimit-above 20/sec --hashlimit-burst 100 --hashlimit-mode srcip \
        --hashlimit-srcmask 24 -p tcp --syn -j DROP

    # Drop chain rules
    iptables -t $TABLE -A $DROP_CHAIN -j LOG --log-prefix "Blocked by hashlimit: " --log-level 4
    iptables -t $TABLE -A $DROP_CHAIN -j SET --add-set $BLOCKED_SET src
    iptables -t $TABLE -A $DROP_CHAIN -j DROP

    # Attach to PREROUTING chain
    iptables -t $TABLE -A PREROUTING -i "$INTERFACE" -p tcp --syn -j $CHAIN
    iptables -L -n -v -t raw

elif [ "$1" == "off" ]; then
    # Remove chain and rules
    iptables -t $TABLE -D PREROUTING -i "$INTERFACE" -p tcp --syn -j $CHAIN 2>/dev/null
    iptables -t $TABLE -F $CHAIN 2>/dev/null
    iptables -t $TABLE -X $CHAIN 2>/dev/null
    iptables -t $TABLE -F $DROP_CHAIN 2>/dev/null
    iptables -t $TABLE -X $DROP_CHAIN 2>/dev/null

    # Flush ipsets
    ipset destroy $WHITELIST_SET 2>/dev/null
    ipset destroy $BLOCKED_SET 2>/dev/null 
    iptables -L -n -v -t raw
fi

