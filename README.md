# linux-ddos-mitigation

SYN-flood mitigation for a single Linux box. Uses `iptables` (`raw`/`PREROUTING`)
and `ipset`. No external services, no appliances.

It rate-limits inbound TCP SYN per source IP and per `/24`. When a source goes over
the limit, its IP goes into an `ipset` blocklist with a TTL. Entries expire on their
own, so no cron and no cleanup. Drops happen in the `raw` table, before conntrack, so
a flood does not fill the connection-tracking table.

## Scope

This protects one server against SYN/connection-rate attacks when you still have
bandwidth left. It does not replace upstream filtering.

- Volumetric floods that fill your uplink: the packets choke the pipe before
  `iptables` sees them. You need upstream/provider filtering for that.
- Distributed low-rate attacks: 10k bots at 2 SYN/s each will not trip a per-IP
  limit. Different layer, different tool.

It is the quick version for when one host is under a SYN flood and you need it to stop.

## Requirements

- `iptables` and `ipset` (`apt-get install ipset` on Debian/Ubuntu)
- `xt_set` / `ip_set` kernel modules (default on most distros)
- root

## Usage

```bash
# Enable on the public interface
sudo ./ddos-mitigate.sh on eth0

# Disable and clean up (removes chains + ipsets)
sudo ./ddos-mitigate.sh off eth0
```

What it does:

- creates `whitelist_ips` (never blocked) and `blocked_ips` (expires after 600s,
  set `BLOCK_TIMEOUT` to change it)
- builds its own `pingtips` / `pingtips_drop` chains, so it does not touch existing
  rules
- whitelists IPs from current login sessions (`w`) so you don't lock yourself out

Add your own IP by hand to be safe:

```bash
sudo ipset add whitelist_ips YOUR_IP
```

## How it works

Rules in the `pingtips` chain, in order:

1. whitelist → `ACCEPT`
2. already in `blocked_ips` → `DROP`
3. per-IP SYN over `10/sec` (burst 50) → offender handling
4. per-`/24` SYN over `20/sec` (burst 100) → offender handling

Offender handling (`pingtips_drop`): rate-limited `LOG`, add source to `blocked_ips`
with TTL, then `DROP`. After that, rule 2 drops the IP directly until it expires.

## Test it

Two boxes (or two VMs). One target, one attacker.

```bash
# Target: enable and watch
sudo ./ddos-mitigate.sh on eth0
watch -n1 'sudo ipset -L blocked_ips'
sudo journalctl -kf | grep "Blocked by hashlimit"

# Attacker: 1000 SYN/s at port 80
sudo hping3 --flood -S -p 80 TARGET_IP
```

The attacker IP shows up in `blocked_ips` with a countdown, syslog logs
`Blocked by hashlimit:`, and the drop-chain counters go up
(`sudo iptables -L -n -v -t raw`). Stop the flood and the IP drops off the set when
the timeout ends.

## Tuning

- `BLOCK_TIMEOUT` (top of the script): 600s default. Use 3600 for real attacks, 60
  for testing.
- Thresholds: change `--hashlimit-above` / `--hashlimit-burst` to fit your normal
  traffic. The `/24` rule uses higher numbers because it sums up to 256 addresses.

## License

See [LICENSE](LICENSE).
