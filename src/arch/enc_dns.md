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

- [Arch Wiki dnscrypt-proxy](https://wiki.archlinux.org/title/Dnscrypt-proxy)

- [dnscrypt-proxy Wiki](https://github.com/DNSCrypt/dnscrypt-proxy/wiki/Configuration)

- [DNS Privacy and Security](https://wiki.archlinux.org/title/Domain_name_resolution#Privacy_and_security)

Edit `/etc/dnscrypt-proxy/dnscrypt-proxy.toml` to add your chosen resolvers etc.

For example, to use Quad9's resolvers with oDoH:

<details>
<summary>

✔️ Click to Expand example `dnscrypt-proxy.toml` that is set up with dnsmasq as
the local resolver.

</summary>

```toml
server_names = ['quad9-dnscrypt-ip6-filter-pri', 'quad9-dnscrypt-ip4-filter-pri', 'mullvad-adblock-doh' ]

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
require_nofilter = false

bootstrap_resolvers = ['9.9.9.11:53', '1.1.1.1:53']

fallback_resolvers = ['1.0.0.1:53', '9.9.9.9:53']

ignore_system_dns = true


[sources]

### An example of a remote source from https://github.com/DNSCrypt/dnscrypt-resolvers

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

routes = [
  { server_name='quad9-dnscrypt-ip6-filter-pri', via=['anon-cs-berlin', 'anon-cs-dus6'] },
  { server_name='quad9-dnscrypt-ip4-filter-pri', via=['sdns://gREzNy4xMjAuMjE3Ljc1OjQ0Mw'] },
  { server_name='mullvad-adblock-doh', via=['anon-cs-de', 'anon-cs-norway6'] }
]

## Skip resolvers incompatible with anonymization instead of using them directly
skip_incompatible = true
```

Check the
[relays.md](https://github.com/DNSCrypt/dnscrypt-resolvers/blob/master/v3/relays.md)
for different anon relays.

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

## Testing

I tested in Firefox by ensuring that in `Settings -> Privacy & Security` the DNS
over HTTPS was set to `Status: Off`, Enable DNS over HTTPS using: `Off` Use your
default DNS resolver.

Then go to `https://dnsleaktest.com` and perform an Extended Test. If you used
the above configuration with Quad9's resolvers, you should see all WoodyNet ISPs
listed in Germany. If not, something is wrong and you have a DNS leak.

I have noticed dnsleaktest having issues lately, `https://ipleak.net` works for
this as well.
