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

## Resources

- [Linux Network Admin Guide](https://tldp.org/LDP/nag2/index.html)

- [Arch Wiki NetworkManager](https://wiki.archlinux.org/title/NetworkManager)
