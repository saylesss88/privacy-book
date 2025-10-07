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
