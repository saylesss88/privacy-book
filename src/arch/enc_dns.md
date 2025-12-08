---
title: Encrypted DNS on Arch
date: 2025-12-05
author: saylesss88
collection: "blog"
tags: ["arch", "security"]
draft: false
---

# Encrypted DNS ArchLinux with dnscrypt-proxy & dnsmasq

<details>
<summary> ✔️ Click to Expand Table of Contents</summary>

<!-- toc -->

</details>

> ❗ NOTE: There are many other ways for someone monitoring your traffic to see
> what domain you looked up via DNS that it's effectiveness is questionable
> without also using Tor or a VPN. Encrypted DNS will not help you hide any of
> your browsing activity.

```bash
sudo pacman -S dnscrypt-proxy
```

> NOTE: udp is required for dnscrypt protocol, keep this in mind when
> configuring your servers if your output chain is a default drop.

- [Arch Wiki dnscrypt-proxy](https://wiki.archlinux.org/title/Dnscrypt-proxy)

- [dnscrypt-proxy Wiki](https://github.com/DNSCrypt/dnscrypt-proxy/wiki/Configuration)

- [DNS Privacy and Security](https://wiki.archlinux.org/title/Domain_name_resolution#Privacy_and_security)

Edit `/etc/dnscrypt-proxy/dnscrypt-proxy.toml` to add your chosen resolvers etc.

For example, to setup ODoH you could do the following:

<details>
<summary>

✔️ Click to Expand example `dnscrypt-proxy.toml` that is set up with dnsmasq as
the local resolver.

</summary>

> ❗️ This isn't the whole file, only the parts that were changed.

```toml
# DNSCRYPT servers to be forwarded to anon-relays
# server_names = ['quad9-dnscrypt-ip6-nofilter-pri', 'quad9-dnscrypt-ip4-nofilter-pri', 'quad9-dnscrypt-ip6-nofilter-ecs-pri' ]
# ODoH servers to be forwarded to odoh-relays
server_names = [ 'odoh-cloudflare', 'odoh-snowstorm' ]

listen_addresses = ['127.0.0.1:53', '[::1]:53']

max_clients = 250

# Use servers reachable over IPv4
ipv4_servers = true

# Use servers reachable over IPv6 -- Do not enable if you don't have IPv6 connectivity
ipv6_servers = true

# Use servers implementing the DNSCrypt protocol
dnscrypt_servers = true

# Use servers implementing the DNS-over-HTTPS protocol
doh_servers = false

# Use servers implementing the Oblivious DoH protocol
odoh_servers = true

## Require servers defined by remote sources to satisfy specific properties

# Server must support DNS security extensions (DNSSEC)
require_dnssec = true

# Server must not log user queries (declarative)
require_nolog = true

# Server must not enforce its own blocklist (for parental control, ads blocking...)
require_nofilter = true

bootstrap_resolvers = ['9.9.9.11:53', '1.1.1.1:53']

fallback_resolvers = ['1.0.0.1:53', '9.9.9.9:53']

ignore_system_dns = true


[sources]

### An example of a remote source from https://github.com/DNSCrypt/dnscrypt-resolvers

# These are just lists of resolvers to choose from

[sources.public-resolvers]
urls = [
  'https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/public-resolvers.md',
  'https://download.dnscrypt.info/resolvers-list/v3/public-resolvers.md',
]
cache_file = '/var/cache/dnscrypt-proxy/public-resolvers.md'
minisign_key = 'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3'
refresh_delay = 73
prefix = ''

### Anonymized DNS relays

[sources.relays]
urls = [
  'https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/relays.md',
  'https://download.dnscrypt.info/resolvers-list/v3/relays.md',
]
cache_file = '/var/cache/dnscrypt-proxy/relays.md'
minisign_key = 'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3'
refresh_delay = 73
prefix = ''

### ODoH (Oblivious DoH) servers and relays

[sources.odoh-servers]
  urls = ['https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/odoh-servers.md', 'https://download.dnscrypt.info/resolvers-list/v3/odoh-servers.md']
  cache_file = '/var/cache/dnscrypt-proxy/odoh-servers.md'
  minisign_key = 'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3'
  refresh_delay = 73
  prefix = ''
[sources.odoh-relays]
  urls = ['https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/odoh-relays.md', 'https://download.dnscrypt.info/resolvers-list/v3/odoh-relays.md']
  cache_file = '/var/cache/dnscrypt-proxy/odoh-relays.md'
  minisign_key = 'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3'
  refresh_delay = 73
  prefix = ''

### Quad9

[sources.quad9-resolvers]
  urls = ['https://quad9.net/dnscrypt/quad9-resolvers.md', 'https://raw.githubusercontent.com/Quad9DNS/dnscrypt-settings/main/dnscrypt/quad9-resolvers.md']
  minisign_key = 'RWTp2E4t64BrL651lEiDLNon+DqzPG4jhZ97pfdNkcq1VDdocLKvl5FW'
  cache_file = '/var/cache/dnscrypt-proxy/quad9-resolvers.md'
  prefix = 'quad9-'

[anonymized_dns]

# ODoH Server/ODoH Relay settings
routes = [
    { server_name='odoh-snowstorm', via=['odohrelay-crypto-sx'] },
    { server_name='odoh-cloudflare', via=['odohrelay-crypto-sx'] }
]

# DNSCRYPT Server/Anon-Relay Settings
# routes = [
#   { server_name='quad9-dnscrypt-ip6-nofilter-pri', via=['anon-cs-berlin', 'anon-cs-dus6'] },
#   { server_name='quad9-dnscrypt-ip4-nofilter-pri', via=['sdns://gREzNy4xMjAuMjE3Ljc1OjQ0Mw'] },
#   { server_name='quad9-dnscrypt-ip6-nofilter-ecs-pri', via=['anon-cs-de', 'anon-cs-norway6'] }
# ]


## Skip resolvers incompatible with anonymization instead of using them directly
skip_incompatible = true
```

The only
[ODoH relay](https://github.com/DNSCrypt/dnscrypt-resolvers/blob/master/v3/odoh-relays.md)
listed is `odohrelay-crypto-sx` so both ODoH servers are routed through the same
relay.

The commented out `server_names` and `routes` are for Anonymous relays, which
are different from oblivious relays and servers. Check the
[relays.md](https://github.com/DNSCrypt/dnscrypt-resolvers/blob/master/v3/relays.md)
for different anon relays.

Resources:

<details>
<summary> ✔️ Click to Expand Resources </summary>

- [public-resolvers v3](https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/public-resolvers.md)

- [dnscrypt public-servers](https://dnscrypt.info/public-servers/)

- [Oblivious DoH](https://github.com/DNSCrypt/dnscrypt-proxy/wiki/Oblivious-DoH)

- [List of public ODoH servers](https://github.com/DNSCrypt/dnscrypt-resolvers/blob/master/v3/odoh-servers.md)

- [List of public ODoH relays](https://github.com/DNSCrypt/dnscrypt-resolvers/blob/master/v3/odoh-relays.md)

- [List of quad9-resolvers](https://raw.githubusercontent.com/Quad9DNS/dnscrypt-settings/main/dnscrypt/quad9-resolvers.md)

- [dnscry.pt](https://www.dnscry.pt/)

</details>

</details>

Modify `/etc/resolv.conf`:

```conf
nameserver ::1
nameserver 127.0.0.1
options edns0
```

Stop it from being overwritten:

```bash
sudo chattr +i /etc/resolv.conf
```

Disable any services bound to port 53

```bash
ss -lp 'sport = :domain'
```

```bash
sudo systemctl stop systemd-resolved
sudo systemctl disable systemd-resolved
```

Enable `dnscrypt-proxy`:

```bash
sudo systemctl enable dnscrypt-proxy
```

`libvirtd` is another service that utilizes `dnsmasq` which uses port 53 and
conflicts with this setup. Since dnscrypt-proxy uses port 53 by default, it
makes using it with `libvirtd` difficult.

---

## dnsmasq as a local DNS server

Edit the `listen_addresses` in `/etc/dnscrypt-proxy/dnscrypt-proxy.toml`:

```toml
listen_addresses = ['127.0.0.1:5353', '[::1]:5353']
```

Edit `/etc/dnsmasq.conf`:

```conf
listen-address=127.0.0.1,::1
server=127.0.0.1#5353
server=::1#5353
```

```bash
sudo systemctl enable dnsmasq
```

```bash
sudo systemctl restart dnsmasq
sudo systemctl restart dnscrypt-proxy
```

**How it Works**

We've created a two-step process for your DNS queries. Instead of your computer
directly asking a DNS server for a website's IP address, it now sends the
request to dnsmasq first.

1. We configured dnsmasq to listen on 127.0.0.1 (our local machine). This means
   that all DNS queries from our system are sent to dnsmasq.

2. We told dnsmasq to use dnscrypt-proxy as its upstream DNS server with
   `server=127.0.0.1#5353`. So, dnsmasq gets the DNS request and immediately
   forwards it to dnscrypt-proxy, which is listening on port 5353.

3. dnscrypt-proxy then takes the forwarded request, encrypts it, and sends it to
   a secure DNS resolver on the internet. It receives the IP address back,
   decrypts it, and sends it back to dnsmasq.

4. Finally, dnsmasq receives the IP address from dnscrypt-proxy and sends it
   back to the program that made the original request (e.g., the browser).

## Add Blocklists

- [dnscrypt-proxy Filters](https://github.com/DNSCrypt/dnscrypt-proxy/wiki/Filters)

Configure filter list sources in
`/usr/share/dnscrypt-proxy/utils/generate-domains-blocklist/domains-blocklist.conf`:

> ❗️ NOTE: Do a bit of research, all of these aren't required and will slow down
> your queries. You can also setup an allowlist for exceptions.

```conf
# NextDNS CNAME cloaking list
https://raw.githubusercontent.com/nextdns/cname-cloaking-blocklist/master/domains

# AdGuard Simplified Domain Names filter
https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt

# OISD Big list
https://big.oisd.nl/domainswild

# HaGeZi Multi PRO
https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro-onlydomains.txt

# HaGeZi Threat Intelligence Feeds
https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif-onlydomains.txt
```

```bash
sudo mkdir -p /etc/dnscrypt-proxy-blocklist
sudo cp -r /usr/share/dnscrypt-proxy/utils/generate-domains-blocklist/* /etc/dnscrypt-proxy-blocklist/
```

Save
[generate-domains-blocklist.py](https://raw.githubusercontent.com/DNSCrypt/dnscrypt-proxy/master/utils/generate-domains-blocklist/generate-domains-blocklist.py)
to `/usr/share/dnscrypt-proxy/utils/generate-domains-blocklist`

```bash
cd /etc/dnscrypt-proxy-blocklist
sudo python3 generate-domains-blocklist.py -o blocklist.txt
```

Create a service to download & combine filter lists:
`/etc/systemd/system/dnscrypt-filterlist-update.service`:

```.service
[Unit]
Description=DNSCrypt Filterlist Update

[Service]
Type=oneshot
ExecStart=/etc/dnscrypt-proxy-blocklist/generate-domains-blocklist -a /etc/dnscrypt-proxy-blocklist/domains-allowlist.txt -o /etc/dnscrypt-proxy-blocklist/blocklist.txt
ExecStartPost=/usr/bin/sleep 2
ExecStartPost=/usr/bin/systemctl restart dnscrypt-proxy.service
```

Create a timer to run at boot & every 5 hours.
`/etc/systemd/system/dnscrypt-filterlist-update.timer`:

```.timer
[Unit]
Description=Run filterlist update 15min after boot and every 5h

[Timer]
OnBootSec=15min
OnUnitActiveSec=5h

[Install]
WantedBy=timers.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable dnscrypt-filterlist-update.timer
```

Configure dnscrypt-proxy to use the blocklist:

`/etc/dnscrypt-proxy/dnscrypt-proxy.toml`:

```toml
blocked_names_file = "/usr/share/dnscrypt-proxy/utils/generate-domains-blocklist/blocklist.txt"
log_file = '/var/log/dnscrypt-proxy/blocked-names.log'
```

For an allow list, you create a list of names you want to allow to bypass your
blocklist:

```toml
allowed_names_file = "/usr/share/dnscrypt-proxy/utils/generate-domains-blocklist/allowed-names.txt"
log_file = "/var/log/dnscrypt-proxy/allowed-names.log"
```

Restart the service:

```bash
sudo systemctl restart dnscrypt-proxy
```

Reboot.

Verify blocklist works against an address listed in `blocklist.txt`:

```bash
dig dm.csl.academy @127.0.0.1 -p 53
```

Output:

```bash
;; ANSWER SECTION:
dm.csl.academy.         10      IN      HINFO   "This query has been locally blocked" "by dnscrypt-proxy"
```

## Testing

I tested in Firefox by ensuring that in `Settings -> Privacy & Security` the DNS
over HTTPS was set to `Status: Off`, Enable DNS over HTTPS using: `Off` Use your
default DNS resolver.

Then go to `https://dnsleaktest.com` and perform an Extended Test. If you used
the above configuration with Quad9's resolvers, you should see all WoodyNet ISPs
listed in Germany. If not, something is wrong and you have a DNS leak.

I have noticed dnsleaktest having issues lately, `https://ipleak.net` works for
this as well.

## Enable MAC Randomization

```bash
sudo mkdir -p /etc/NetworkManager/conf.d
sudo hx /etc/NetworkManager/conf.d/20-mac-randomization.conf
```

Add the following for randomization (use `stable` for consistent per-network
MACs; change to `random` if preferred)

```conf
[device]
wifi.scan-rand-mac-address=yes

[connection]
wifi.cloned-mac-address=random
ethernet.cloned-mac-address=random
```

- `wifi.scan-rand-mac-address=yes`: Enables randomization during Wi-Fi scans
  (default, but explicit for clarity).

- `wifi.cloned-mac-address=stable` / `ethernet.cloned-mac-address=stable`:
  Applies to Wi-Fi and Ethernet connections.

**Verify MAC Randomization**

Check your interface (e.g., `wlp3s0` for Wi-Fi, find with `ip link`)

```bash
ip link show wlp3s0 | grep link/ether
```

```bash
nmcli connection down "YourSSID"
nmcli connection up "YourSSID"
```

Check MAC again:

```bash
cat /sys/class/net/wlp3s0/address
```

```bash
sudo systemctl status dnscrypt-proxy dnsmasq
```

```bash
nslookup example.com
```

---

**Enable dnsmasq caching**

`/etc/NetworkManager/dnsmasq.d/cache.conf`:

```conf
cache-size=1000
```

---

This may help with IPv6 connectivity, add the following to
`/etc/NetworkManager/dnsmasq.d/ipv6-listen.conf`:

```bash
listen-address=::1
```

---

**Enable DNSSEC validation**:

`/etc/NetworkManager/dnsmasq.d/dnssec.conf`:

```conf
conf-file=/usr/share/dnsmasq/trust-anchors.conf
dnssec
```

## Enable Privacy Extensions

Add this to `/etc/sysctl.d/40-ipv6.conf`:

```conf
# Enable IPv6 Privacy Extensions
net.ipv6.conf.all.use_tempaddr = 2
net.ipv6.conf.default.use_tempaddr = 2
net.ipv6.conf.nic.use_tempaddr = 2
```

```bash
# find nic
ip link
net.ipv6.conf.wlp3s0.use_tempaddr = 2
```

```bash
sudo sysctl --system
```

`/etc/NetworkManager/conf.d/ip6-privacy.conf`:

```conf
[connection]
ipv6.ip6-privacy=2
```
