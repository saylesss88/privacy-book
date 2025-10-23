# Hardening Networking

NetworkManagers global config is `/etc/NetworkManager/NetworkManager.conf`.
Additional config files can be placed in `/etc/NetworkManager/conf.d`.

After editing a config file, apply the changes with:

```bash
sudo nmcli general reload
```

```bash
sudo usermod -aG network $USER
```

## Investigate sockets

Display all TCP Sockets with service names:

```bash
ss -at
```

Display all TCP Sockets with port numbers:

```bash
ss -atn
```

Display all UDP Sockets:

```bash
ss -au
```

## Configure NetworkManager to use Quad9s DoT

Create `/etc/NetworkManager/system-connections/Wi-Fi.nmconnection`:

```.nmconnection
[connection]
dns-over-tls=2

[ipv4]
dns=9.9.9.9#dns.quad9.net;149.112.112.112#dns.quad9.net;
ignore-auto-dns=true

[ipv6]
dns=2620:fe::fe#dns.quad9.net;2620:fe::9#dns.quad9.net;
ignore-auto-dns=true
```

```bash
sudo systemctl restart NetworkManager
```

**Wi-Fi MAC randomization**

Add the following to `/etc/NetworkManager/conf.d/wifi_rand_mac.conf`:

```conf
[device-mac-randomization]
# "yes" is already the default for scanning
wifi.scan-rand-mac-address=yes

[connection-mac-randomization]
# Randomize MAC for every ethernet connection
ethernet.cloned-mac-address=random
# Generate a random MAC every time you connect to a wifi network
wifi.cloned-mac-address=random
```

**Unique DUID per connection**

Create `/etc/NetworkManager/conf.d/duid.conf`:

```conf
[connection]
ipv6.dhcp-duid=stable-uuid
```

## MAC Address spoofing

This section demonstrates how to spoof your Media Access Control (MAC) address.

**Manual MAC randomization with macchanger**

Find your device interface and check your current MAC address:

```bash
# find interface
ip add
sudo iplink show wlp3s0
```

The address following `"link/ether"` is your MAC, bring it down so we can change
it:

```bash
sudo ip link set dev wlp3s0 down
# or
# sudo ifconfig wlp3s0 down
```

Install the `macchanger` package and run:

```bash
sudo macchanger -a wlp3s0
```

- `-a`, `--another`: Set random vendor MAC of the same kind.

- `-r`, `--random`: Set fully random MAC.

**Automatically with systemd & macchanger**

systemd unit setting a random address while preserving the original NIC vendor
bytes.

Create `/etc/systemd/system/macspoof@.service`:

```macspoof@.service
[Unit]
Description=macchanger on %I
Wants=network-pre.target
Before=network-pre.target
BindsTo=sys-subsystem-net-devices-%i.device
After=sys-subsystem-net-devices-%i.device

[Service]
ExecStart=/usr/bin/macchanger -e %I
Type=oneshot

[Install]
WantedBy=multi-user.target
```

- You can use `-r` to randomize everything but it's important that the vendor
  bytes actually match something and aren't just random numbers so it's less
  recommended.

- The `@.service` pattern allows per-interface instantiation like
  `macspoof@wlp3s0.service`.

- The `%I` variable automatically resolves to your interface name.

- You only need to append your interface name when enabling the service.

```bash
sudo systemctl enable macspoof@wlp3s0.service
```

## Resources

- [KickSecure MAC_address](https://www.kicksecure.com/wiki/MAC_Address)

- [Arch Wiki MAC address spoofing](https://wiki.archlinux.org/title/MAC_address_spoofing)

- [Linux Network Admin Guide](https://tldp.org/LDP/nag2/index.html)

- [Arch Wiki NetworkManager](https://wiki.archlinux.org/title/NetworkManager)
