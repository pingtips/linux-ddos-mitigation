# linux-ddos-mitigation

Host-level SYN-flood mitigation for a **single Linux box**, using `iptables`
(`raw`/`PREROUTING`) and `ipset`. No external services, no appliances — just tools
already on the machine.

The idea: rate-limit inbound TCP SYN packets per source IP (and per `/24`), and when
a source crosses the threshold, drop it into a TTL'd `ipset` blocklist. Entries expire
on their own, so there's no cron job and no manual cleanup. Drops happen in the `raw`
table, **before conntrack**, so a flood never fills the connection-tracking table.

## Scope (read this first)

This protects one server against connection-rate / SYN-flood style attacks where you
still have bandwidth headroom. It is **not** a substitute for upstream filtering:

- ❌ **Volumetric floods** that saturate your uplink — the packets are already choking
  the pipe before `iptables` ever sees them. You need upstream/provider-level filtering
  for that.
- ❌ **Distributed low-rate attacks** — 10k bots each sending 2 SYN/s won't trip a
  per-IP threshold. Different layer, different tool.

It's the quick, no-dependencies version: good enough for a surprise flood at 3 AM when
you just need to stop the bleeding on one host.

## Requirements

- Linux with `iptables` and `ipset` (`apt-get install ipset` on Debian/Ubuntu)
- `xt_set` / `ip_set` kernel modules (shipped with most distros)
- root

## Usage

```bash
# Enable on your public interface
sudo ./ddos-mitigate.sh on eth0

# Disable and clean up (removes chains + ipsets)
sudo ./ddos-mitigate.sh off eth0
```

The script:

- creates two ipsets — a `whitelist_ips` (never blocked) and a `blocked_ips`
  (auto-expiring after 600s, tunable via `BLOCK_TIMEOUT`),
- builds dedicated `pingtips` / `pingtips_drop` chains so it doesn't touch your
  existing rules,
- auto-whitelists IPs from currently logged-in sessions (`w`) so you don't lock
  yourself out — but add your own IP explicitly to be safe:

```bash
sudo ipset add whitelist_ips YOUR_IP
```

## How it works

Rule order inside the `pingtips` chain:

1. **Whitelist** → `ACCEPT` (no checks, no limits)
2. **Already-blocked** (`blocked_ips`) → `DROP` (cheap O(1) lookup)
3. **Per-IP SYN rate** above `10/sec` (burst 50) → offender handling
4. **Per-/24 SYN rate** above `20/sec` (burst 100) → offender handling
   (catches attackers rotating through a subnet)

Offender handling (`pingtips_drop` chain): rate-limited `LOG`, add source to
`blocked_ips` (with TTL), then `DROP`. Once an IP is in the set, rule 2 drops it
directly until the entry expires.

## Test it

Two boxes (or two VMs on the same network). One target, one attacker.

```bash
# On the target — enable and watch
sudo ./ddos-mitigate.sh on eth0
watch -n1 'sudo ipset -L blocked_ips'
sudo journalctl -kf | grep "Blocked by hashlimit"

# On the attacker — blast 1000 SYN/s at port 80
sudo hping3 --flood -S -p 80 TARGET_IP
```

Within a few seconds the attacker's IP appears in `blocked_ips` with a countdown,
syslog shows `Blocked by hashlimit:` entries, and the drop-chain packet counters
climb (`sudo iptables -L -n -v -t raw`). Stop the flood, wait for the timeout — the
IP drops off the set on its own.

## Tuning

- `BLOCK_TIMEOUT` (top of the script): 600s is a sane default. Bump to 3600 for real
  attacks, drop to 60 for testing.
- Thresholds: adjust `--hashlimit-above` / `--hashlimit-burst` to match what's normal
  for your traffic. The `/24` rule uses higher numbers because it aggregates up to 256
  addresses.

## License

See [LICENSE](LICENSE).
