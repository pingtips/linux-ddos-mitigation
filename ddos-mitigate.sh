#!/bin/bash
#
# linux-ddos-mitigation — host-level SYN-flood mitigation for a single Linux box.
#
# Rate-limits inbound TCP SYN per source IP and per /24 in iptables raw/PREROUTING,
# auto-blocking offenders into a TTL'd ipset. Drops happen before conntrack, so a
# flood never fills the connection table.
#
# Scope: ONE Linux server. This is NOT a substitute for upstream/volumetric
# filtering — if an attack saturates your uplink, the box never sees the packets.
#
# Usage:
#   sudo ./ddos-mitigate.sh on  <interface>
#   sudo ./ddos-mitigate.sh off <interface>

set -u

ACTION="${1:-}"
INTERFACE="${2:-}"

CHAIN="pingtips"
DROP_CHAIN="pingtips_drop"
WHITELIST_SET="whitelist_ips"
CLOUDFLARE_SET="cloudflare_ips"
BLOCKED_SET="blocked_ips"
TABLE="raw"
BLOCK_TIMEOUT=600   # seconds an offending IP stays blocked before auto-expiry
CF_IPV4_URL="https://www.cloudflare.com/ips-v4"

# Cloudflare IPv4 ranges. Used as a fallback if the URL fetch fails.
# If your site is behind Cloudflare, all traffic comes from these ranges, so
# without this whitelist the rate limit would block Cloudflare and kill the site.
# Update from $CF_IPV4_URL when Cloudflare changes them.
CF_IPV4_FALLBACK="
173.245.48.0/20
103.21.244.0/22
103.22.200.0/22
103.31.4.0/22
141.101.64.0/18
108.162.192.0/18
190.93.240.0/20
188.114.96.0/20
197.234.240.0/22
198.41.128.0/17
162.158.0.0/15
104.16.0.0/13
104.24.0.0/14
172.64.0.0/13
131.0.72.0/22
"

# --- guards ----------------------------------------------------------------
if [ "$(id -u)" -ne 0 ]; then
    echo "Error: must be run as root (needs iptables/ipset)." >&2
    exit 1
fi

for cmd in iptables ipset; do
    command -v "$cmd" >/dev/null 2>&1 || {
        echo "Error: '$cmd' not found. Install it first (e.g. apt-get install ipset)." >&2
        exit 1
    }
done

if [ "$ACTION" != "on" ] && [ "$ACTION" != "off" ]; then
    echo "Usage: $0 {on|off} <interface>" >&2
    exit 1
fi

if [ -z "$INTERFACE" ]; then
    echo "Error: no interface given. Example: $0 $ACTION eth0" >&2
    exit 1
fi

# --- enable ----------------------------------------------------------------
if [ "$ACTION" == "on" ]; then
    # ipsets: whitelist (never blocked) + blocklist (auto-expiring)
    ipset create "$WHITELIST_SET"  hash:ip  -exist
    ipset create "$CLOUDFLARE_SET" hash:net -exist
    ipset create "$BLOCKED_SET"    hash:ip  timeout "$BLOCK_TIMEOUT" -exist

    # Load Cloudflare ranges. If you sit behind Cloudflare, every request comes
    # from these nets, so they must never be rate-limited. Fetch the live list,
    # fall back to the built-in one if there is no network or curl.
    CF_RANGES=""
    if command -v curl >/dev/null 2>&1; then
        CF_RANGES="$(curl -fsS "$CF_IPV4_URL" 2>/dev/null)"
    fi
    [ -z "$CF_RANGES" ] && CF_RANGES="$CF_IPV4_FALLBACK"
    echo "$CF_RANGES" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}' | while read -r NET; do
        ipset add "$CLOUDFLARE_SET" "$NET" -exist
    done

    # Dedicated chains so we don't pollute existing rules
    iptables -t "$TABLE" -N "$CHAIN"      2>/dev/null
    iptables -t "$TABLE" -N "$DROP_CHAIN" 2>/dev/null
    iptables -t "$TABLE" -F "$CHAIN"
    iptables -t "$TABLE" -F "$DROP_CHAIN"

    # Detach any previous hook before rebuilding (idempotent re-runs)
    iptables -t "$TABLE" -D PREROUTING -i "$INTERFACE" -p tcp --syn -j "$CHAIN" 2>/dev/null

    # Auto-whitelist currently logged-in admin IPs so you don't lock yourself out
    w -h | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u | while read -r IP; do
        ipset add "$WHITELIST_SET" "$IP" -exist
    done

    # Rule order matters:
    # 1. Whitelisted admin IPs: accept, no checks
    iptables -t "$TABLE" -A "$CHAIN" -m set --match-set "$WHITELIST_SET" src -j ACCEPT
    # 2. Cloudflare ranges: accept (if behind Cloudflare, all traffic is here)
    iptables -t "$TABLE" -A "$CHAIN" -m set --match-set "$CLOUDFLARE_SET" src -j ACCEPT
    # 3. Known offenders: drop immediately (cheap O(1) ipset lookup)
    iptables -t "$TABLE" -A "$CHAIN" -m set --match-set "$BLOCKED_SET" src -j DROP
    # 4. Per-IP SYN rate limit -> offender handling
    iptables -t "$TABLE" -A "$CHAIN" \
        -m hashlimit --hashlimit-name syn_ip \
        --hashlimit-above 10/sec --hashlimit-burst 50 \
        --hashlimit-mode srcip -j "$DROP_CHAIN"
    # 5. Per-/24 SYN rate limit (catches subnet-rotating sources)
    iptables -t "$TABLE" -A "$CHAIN" \
        -m hashlimit --hashlimit-name syn_net \
        --hashlimit-above 20/sec --hashlimit-burst 100 \
        --hashlimit-mode srcip --hashlimit-srcmask 24 -j "$DROP_CHAIN"

    # Offender handling: log (rate-limited), add to blocklist with TTL, drop
    iptables -t "$TABLE" -A "$DROP_CHAIN" \
        -m limit --limit 10/min --limit-burst 20 \
        -j LOG --log-prefix "Blocked by hashlimit: " --log-level 4
    iptables -t "$TABLE" -A "$DROP_CHAIN" -j SET --add-set "$BLOCKED_SET" src
    iptables -t "$TABLE" -A "$DROP_CHAIN" -j DROP

    # Hook into PREROUTING (TCP SYN on the public interface only)
    iptables -t "$TABLE" -A PREROUTING -i "$INTERFACE" -p tcp --syn -j "$CHAIN"

    echo "Protection ENABLED on $INTERFACE (block timeout ${BLOCK_TIMEOUT}s)."
    iptables -L -n -v -t "$TABLE"

# --- disable ---------------------------------------------------------------
elif [ "$ACTION" == "off" ]; then
    iptables -t "$TABLE" -D PREROUTING -i "$INTERFACE" -p tcp --syn -j "$CHAIN" 2>/dev/null
    iptables -t "$TABLE" -F "$CHAIN"      2>/dev/null
    iptables -t "$TABLE" -X "$CHAIN"      2>/dev/null
    iptables -t "$TABLE" -F "$DROP_CHAIN" 2>/dev/null
    iptables -t "$TABLE" -X "$DROP_CHAIN" 2>/dev/null
    ipset destroy "$WHITELIST_SET"  2>/dev/null
    ipset destroy "$CLOUDFLARE_SET" 2>/dev/null
    ipset destroy "$BLOCKED_SET"    2>/dev/null

    echo "Protection DISABLED on $INTERFACE."
    iptables -L -n -v -t "$TABLE"
fi
