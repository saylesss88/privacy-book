# Encrypted DNS ArchLinux with dnscrypt-proxy & dnsmasq

```bash
sudo pacman -S dnscrypt-proxy
```

- [Arch Wiki dnscrypt-proxy](https://wiki.archlinux.org/title/Dnscrypt-proxy)

Edit `/etc/dnscrypt-proxy/dnscrypt-proxy.toml` to add your chosen resolvers etc.

For example, to use Quad9's resolvers:

<details>
<summary>
✔️ Click to Expand example `dnscrypt-proxy.toml` that is set up with dnsmasq
as the local resolver.
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
odoh_servers = false

## Require servers defined by remote sources to satisfy specific properties

# Server must support DNS security extensions (DNSSEC)
require_dnssec = true

# Server must not log user queries (declarative)
require_nolog = true

# Server must not enforce its own blocklist (for parental control, ads blocking...)
require_nofilter = false

# Server names to avoid even if they match all criteria
disabled_server_names = []

force_tcp = false

http3 = false

http3_probe = false

timeout = 5000

keepalive = 30

log_file = '/var/log/dnscrypt-proxy/dnscrypt-proxy.log'

use_syslog = true

# Maximum log files size in MB - Set to 0 for unlimited.
log_files_max_size = 10

# How long to keep backup files, in days
log_files_max_age = 7

# Maximum log files backups to keep (or 0 to keep all backups)
log_files_max_backups = 1

cert_refresh_delay = 240

## TL;DR: put valid standard resolver addresses here. Your actual queries will
## not be sent there. If you're using DNSCrypt or Anonymized DNS and your
## lists are up to date, these resolvers will not even be used.

bootstrap_resolvers = ['9.9.9.11:53', '1.1.1.1:53']

fallback_resolvers = ['1.0.0.1:53', '9.9.9.9:53']

ignore_system_dns = true

netprobe_timeout = 60

netprobe_address = '9.9.9.9:53'

block_ipv6 = false

## Immediately respond to A and AAAA queries for host names without a domain name
## This also prevents "dotless domain names" from being resolved upstream.

block_unqualified = true

## Immediately respond to queries for local zones instead of leaking them to
## upstream resolvers (always causing errors or timeouts).

block_undelegated = true

## TTL for synthetic responses sent when a request has been blocked (due to
## IPv6 or blocklists).

reject_ttl = 10

## Enable a DNS cache to reduce latency and outgoing traffic

cache = true

## Cache size

cache_size = 4096

## Minimum TTL for cached entries

cache_min_ttl = 2400

## Maximum TTL for cached entries

cache_max_ttl = 86400

## Minimum TTL for negatively cached entries

cache_neg_min_ttl = 60

## Maximum TTL for negatively cached entries

cache_neg_max_ttl = 600


[query_log]

## Path to the query log file (absolute, or relative to the same directory as the config file)
## Can be set to /dev/stdout in order to log to the standard output.

# file = '/var/log/dnscrypt-proxy/query.log'


## Query log format (currently supported: tsv and ltsv)

format = 'tsv'


## Do not log these query types, to reduce verbosity. Keep empty to log everything.

# ignored_qtypes = ['DNSKEY', 'NS']


###############################################################################
#                        Suspicious queries logging                            #
###############################################################################

[nx_log]

## Log queries for nonexistent zones
## These queries can reveal the presence of malware, broken/obsolete applications,
## and devices signaling their presence to 3rd parties.

## Path to the query log file (absolute, or relative to the same directory as the config file)

# file = '/var/log/dnscrypt-proxy/nx.log'


## Query log format (currently supported: tsv and ltsv)

format = 'tsv'

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

### Quad9

[sources.quad9-resolvers]
  urls = ['https://quad9.net/dnscrypt/quad9-resolvers.md', 'https://raw.githubusercontent.com/Quad9DNS/dnscrypt-settings/main/dnscrypt/quad9-resolvers.md']
  minisign_key = 'RWTp2E4t64BrL651lEiDLNon+DqzPG4jhZ97pfdNkcq1VDdocLKvl5FW'
  cache_file = '/var/cache/dnscrypt-proxy/quad9-resolvers.md'
  prefix = 'quad9-'

[broken_implementations]

fragments_blocked = [
  'cisco',
  'cisco-ipv6',
  'cisco-familyshield',
  'cisco-familyshield-ipv6',
  'cisco-sandbox',
  'cleanbrowsing-adult',
  'cleanbrowsing-adult-ipv6',
  'cleanbrowsing-family',
  'cleanbrowsing-family-ipv6',
  'cleanbrowsing-security',
  'cleanbrowsing-security-ipv6',
]


###############################################################################
#                Certificate-based client authentication for DoH               #
###############################################################################

[doh_client_x509_auth]

## Use an X509 certificate to authenticate yourself when connecting to DoH servers.
## This is only useful if you are operating your own, private DoH server(s).
## 'creds' maps servers to certificates, and supports multiple entries.
## If you are not using the standard root CA, an optional "root_ca"
## property set to the path to a root CRT file can be added to a server entry.

# creds = [
#    { server_name='*', client_cert='client.crt', client_key='client.key' }
# ]


###############################################################################
#                          Anonymized DNS                                      #
###############################################################################

[anonymized_dns]

skip_incompatible = false


## If public server certificates for a non-conformant server cannot be
## retrieved via a relay, try getting them directly. Actual queries
## will then always go through relays.

# direct_cert_fallback = false


###############################################################################
#                                 DNS64                                        #
###############################################################################


[ip_encryption]

## Encrypt client IP addresses in plugin logs using IPCrypt
## This provides privacy for client IP addresses while maintaining
## the ability to distinguish between different clients in logs

## Encryption algorithm (default: "none")
## - "none": No encryption (default)
## - "ipcrypt-deterministic": Deterministic encryption (same IP always encrypts to same value) - requires 16-byte key
## - "ipcrypt-nd": Non-deterministic encryption with 8-byte tweak - requires 16-byte key
## - "ipcrypt-ndx": Non-deterministic encryption with 16-byte tweak (extended) - requires 32-byte key

algorithm = "none"

## Encryption key in hexadecimal format (required if algorithm is not "none")
## Key size depends on algorithm:
## - ipcrypt-deterministic: 32 hex chars (16 bytes) - Generate with: openssl rand -hex 16
## - ipcrypt-nd: 32 hex chars (16 bytes) - Generate with: openssl rand -hex 16
## - ipcrypt-ndx: 64 hex chars (32 bytes) - Generate with: openssl rand -hex 32
## Example for deterministic/nd: key = "1234567890abcdef1234567890abcdef"
## Example for ndx: key = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
## IMPORTANT: Keep this key secret

key = ""


###############################################################################
#                            Monitoring UI                                     #
###############################################################################

[monitoring_ui]

## Enable the monitoring UI
enabled = false

## Listen address for the monitoring UI
listen_address = "127.0.0.1:8080"

## Optional username and password for basic authentication
## To disable authentication, set username to an empty string: username = ""
## If both username and password are empty, no authentication is required
username = "admin"
password = "changeme"

## Optional TLS certificate and key for HTTPS
## If both are empty, HTTP will be used
tls_certificate = ""
tls_key = ""

## Enable query logging in the monitoring UI
## This will show recent queries in the UI
enable_query_log = true

## Privacy level for the monitoring UI
## 0: show all details including client IPs
## 1: anonymize client IPs (default)
## 2: aggregate data only (no individual queries or domains shown)
privacy_level = 1

## Maximum number of recent query log entries to keep in memory
## Helps control memory usage on high-traffic servers
## Default: 100
# max_query_log_entries = 100

## Maximum memory usage in MB for recent query logs
## Automatic cleanup when limit is exceeded
## Default: 1
# max_memory_mb = 1

## Enable Prometheus metrics endpoint
## Default: false
# prometheus_enabled = false

## Path for Prometheus metrics endpoint
## Default: /metrics
# prometheus_path = "/metrics"


###############################################################################
#                            Static entries                                    #
###############################################################################

[static]

## Optional, local, static list of additional servers
## Mostly useful for testing your own servers.

# [static.myserver]
#   stamp = 'sdns://AQcAAAAAAAAAAAAQMi5kbnNjcnlwdC1jZXJ0Lg'
```

</details>

Modify `resolv.conf`:

```conf
#/etc/resolv.conf
nameserver ::1
nameserver 127.0.0.1
options edns0
```

Disable any services bound to port 53

```bash
ss -lp 'sport = :domain'
```

```bash
sudo systemctl stop systemd-resolved
sudo systemctl disable systemd-resolved
```

`libvirtd` is another service that utilizes `dnsmasq` which uses port 53 and
conflicts with this setup. Since dnscrypt-proxy uses port 53 by default, it
makes using it with `libvirtd` difficult.

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
over HTTPS was set to `Status: Off`, Enable DNS over HTTPS using:
`Default Protection`.

Then go to `https://dnsleaktest.com` and perform an Extended Test. If you used
the above configuration with Quad9's resolvers, you should see all WoodyNet ISPs
listed. If not, something is wrong and you have a DNS leak.
