# Hardening Arch Linux

This guide started with using grub, here I include a section on switching to
systemd-boot as it's more minimal and has a smaller attack surface.

## Switching to systemd-boot from GRUB

Ensure the EFI partition is mounted at `/boot` or `/efi`:

```bash
mount | grep efi
```

```bash
sudo pacman -Rs grub
```

Remove leftover GRUB files:

```bash
sudo rm -r /boot/EFI/grub
```

### Install systemd-boot

```bash
sudo bootctl install
```

Configure systemd-boot in `/boot/loader/loader.conf`:

```conf
default arch.conf
timeout 4
editor no
console-mode max
```

Create the boot entry:

```bash
sudo blkid /dev/nvme0n1p2
```

For the following step, ensure that you use the correct `vmlinuz` and
`initramfs` for your kernel.

Take note of these names for use in `arch.conf`:

```bash
ls /boot/vmlinuz-*
ls /boot/initramfs-*
```

If you're on an Intel machine, replace `amd-ucode` with `intel-ucode`

Create a `/boot/loader/entries/arch.conf` with the following:

```conf
title   Arch Linux
linux   /vmlinuz-linux-zen
initrd  /amd-ucode.img
initrd  /initramfs-linux-zen.img
options cryptdevice=UUID=bdeed105-a1be-40b9-895c-5f7e9f6a19c3:cryptroot root=/dev/mapper/cryptroot rw quiet loglevel=3
```

Ensure the `/etc/mkinitcpio.conf` has `encrypt` before the `filesystems` hook:

```conf
HOOKS=(base udev autodetect microcode modconf kms keyboard keymap consolefont block encrypt filesystems fsck)
```

Regenerate initramfs:

```bash
sudo mkinitcpio -P
```

Update `systemd-boot` if needed:

```bash
sudo bootctl update
```

Ensure your images are listed:

```bash
sudo bootctl list
```

Reboot

---

## Hardening the Kernel

You can use the `linux-hardened` kernel to have a kernel that prioritizes
security over anything else:

```bash
sudo pacman -S linux-hardened linux-hardened-headers
```

Edit your `/etc/default/grub`:

```bash
GRUB_DEFAULT=saved
GRUB_SAVEDEFAULT=true
GRUB_DISABLE_SUBMENU=y
```

- This enables you to choose from the available kernels at boot and stays on the
  kernel you chose last.

Make grub aware of the new kernel:

```bash
sudo grub-mkconfig -o /boot/grub/grub.cfg
```

Generate the initramfs:

```bash
sudo mkinitcpio -p linux-hardened
```

Reboot and choose `linux-hardened`.

---

## Hardening your current Kernel

Sometimes `linux-hardened` just won't work on your system without some serious
digging. You can harden your current kernel, or even better would be to harden
the Long-Term Support (LTS) kernel.

Create a file `/etc/sysctl.d/99-custom.conf`, since files are read in
lexicographical order this file will be read last, allowing it to override any
settings from earlier files.

To check if a parameter is already set:

```bash
sysctl fs.protected_symlinks
sysctl -a | grep fs.protected
```

To list all parameters:

```bash
sysctl -a > params.txt
```

- `1` typically means enable

- `0` typically means disable

Example, both of these were the default in the zen-kernel:

```bash
# 99-custom.conf
# prevent hardlink misuse
fs.protected_hardlinks = 1
# prevent symlink misuse
fs.protected_symlinks = 1
```

Apply the changes immediately:

```bash
sudo sysctl --system
```

```bash
sudo pacman -S kernel-hardening-checker
```

While in the same directory as the `params.txt` that we created earlier, run:

```bash
kernel-hardening-checker -l /proc/cmdline -c /proc/config.gz -s ./params.txt
```

Only the warnings listed with `| sysctl |` can be edited with the above method.

Example `99-custom.conf` with some settings to prevent breakage:

<details>
<summary> ✔️ Click to Expand `99-custom.conf` example </summary>

> ❗️ NOTE: Always do your own research, many of these settings come from
> recommendations from the kernel-hardening-checker as well as
> [madaidans insecurities Linux Hardening guid](https://madaidans-insecurities.github.io/guides/linux-hardening.html).

```conf
fs.suid_dumpable = 0

# Fix "FAIL: 0", recommended is 2
net.core.bpf_jit_harden = 2

# Fix "FAIL: 10000", recommended is 100
kernel.oops_limit = 100

# Fix "FAIL: 0", recommended is 100
kernel.warn_limit = 100


 # Kernel self-protection
# SysRq exposes a lot of potentially dangerous debugging functionality to unprivileged users
# 4 makes it so a user can only use the secure attention key. A value of 0 would disable completely
kernel.sysrq = 4

# Fix "FAIL: 2", recommended is 3
kernel.perf_event_paranoid = 3

# Fix "FAIL: 1", recommended is 0
dev.tty.ldisc_autoload = 1

# Fix "FAIL: 0", recommended is 2
kernel.kptr_restrict = 2

kernel.dmesg_restrict = 1

# Fix "FAIL: 61175", recommended is 0
user.max_user_namespaces = 15000

# Fix "FAIL: 0", recommended is 1
kernel.kexec_load_disabled = 1

# Fix "FAIL: 2", recommended is 1
kernel.unprivileged_bpf_disabled = 1

# Fix "FAIL: 1", recommended is 0
vm.unprivileged_userfaultfd = 0

# Fix "FAIL: 0", recommended is 1
kernel.modules_disabled = 0

# Fix "FAIL: 0", recommended is 2
# restricts access to async I/O and prevents spawning new shells
kernel.io_uring_disabled = 0

# Fix "FAIL: 16", recommended is 0
kernel.sysrq = 0

# Fix "FAIL: 1", recommended is 2
fs.protected_fifos = 2

# Fix "FAIL: 1", recommended is 2
fs.protected_regular = 2

# Fix "FAIL: 2", recommended is 0
fs.suid_dumpable = 0

# Fix "FAIL: 1", recommended is 3
kernel.yama.ptrace_scope = 2

# Fix "FAIL: 28", recommended is 32
vm.mmap_rnd_bits = 32

# Fix "FAIL: 8", recommended is 16
vm.mmap_rnd_compat_bits = 16

# Network
# protect against SYN flood attacks (denial of service attack)
net.ipv4.tcp_syncookies = 1
# protection against TIME-WAIT assassination
net.ipv4.tcp_rfc1337 = 1
# enable source validation of packets received (prevents IP spoofing)
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.rp_filter = 1

net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
# Protect against IP spoofing
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# prevent man-in-the-middle attacks
net.ipv4.icmp_echo_ignore_all = 1

# ignore ICMP request, helps avoid Smurf attacks
net.ipv4.conf.all.forwarding = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
# Reverse path filtering causes the kernel to do source validation of
net.ipv6.conf.all.forwarding = 0
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0

## TCP hardening
# Prevent bogus ICMP errors from filling up logs.
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Disable TCP SACK
net.ipv4.tcp_sack = 0
net.ipv4.tcp_dsack = 0
net.ipv4.tcp_fack = 0

# Userspace
# restrict usage of ptrace
kernel.yama.ptrace_scope = 2

# ASLR memory protection (64-bit systems)
vm.mmap_rnd_bits = 32
vm.mmap_rnd_compat_bits = 16

# only permit symlinks to be followed when outside of a world-writable sticky directory
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
# Prevent creating files in potentially attacker-controlled environments
fs.protected_fifos = 2
fs.protected_regular = 2

# Randomize memory
kernel.randomize_va_space = 2
# Exec Shield (Stack protection)
kernel.exec-shield = 1

## TCP optimization
# TCP Fast Open is a TCP extension that reduces network latency by packing
# data in the sender’s initial TCP SYN. Setting 3 = enable TCP Fast Open for
# both incoming and outgoing connections:
net.ipv4.tcp_fastopen = 3
# Bufferbloat mitigations + slight improvement in throughput & latency
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = cake
```

</details>

## Firewall

Flush existing iptables Rules & Disable iptables:

> ⚠️ Warning: Flushing rules will remove all existing firewall configurations.
> Ensure no critical services are running, or review existing rules with
> `iptables -L -v -n` and `ip6tables -L -v -n` before proceeding.

```bash
sudo iptables -F
sudo iptables -X
sudo iptables -t nat -F
sudo iptables -t nat -X
sudo ip6tables -F
sudo ip6tables -X

sudo systemctl disable iptables.service
sudo systemctl disable ip6tables.service
sudo systemctl stop iptables.service
sudo systemctl stop ip6tables.service
```

**Install and enable nftables**:

```bash
sudo pacman -S nftables
sudo systemctl enable nftables.service
sudo systemctl start nftables.service
```

Create nftables ruleset:

```bash
#!/usr/sbin/nft -f

table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;

        # Allow loopback
        iif "lo" accept

        # Accept established and related connections
        ct state established,related accept

        ip protocol icmp accept
        # Allow ICMPv6
        ip6 nexthdr icmpv6 accept

        # Allow SSH (port 22)
        tcp dport 22 ct state new accept

        # Allow HTTP and HTTPS (ports 80 and 443)
        tcp dport {80,443} ct state new accept
    }

    chain forward {
        type filter hook forward priority 0; policy drop;
    }

    chain output {
        type filter hook output priority 0; policy accept;

        # Allow DNS queries
        udp dport 53 accept
        tcp dport 53 accept
    }
}
```

> ❗️ If you don't use SSH or host a web server or any service, don't allow SSH
> and HTTP/HTTPS.

Load and test the rules:

```bash
sudo nft -f /etc/nftables.conf
```

```bash
sudo nft list ruleset
```

---

## ssh-keygen

The `ed25519` algorithm is significantly faster and more secure when compared to
`RSA`. You can also specify the key derivation function (KDF) rounds to
strengthen protection even more.

For example, to generate a strong key for MdBook:

```bash
ssh-keygen -t ed25519 -a 32
```

Or more specifically:

```bash
ssh-keygen -t ed25519 -a 32 -f ~/.ssh/id_ed25519_github_$(date +%Y-%m-%d) -C "SSH Key for GitHub"
```

- `-t` is for type

- `-a 32` sets the number of KDF rounds. The standard is usually good enough,
  adding extra rounds can make it harder to brute-force.

- `-f` is for filename

---

## GnuPG and gpg-agent

`gpg --full-generate-key` can be used to generate a basic keypair.

`gpg --expert --full-generate-key` can be used for keys that require more
capabilities.

> ❗ NOTE: We will first generate our GPG primary key that is required to
> atleast have sign capabilities, we will then derive subkeys from said primary
> key and use them for signing and encrypting. It is recommended to generate a
> revoke certificate right after creating your primary key.

To generate your gpg primary key you can do the following:

```bash
gpg --full-generate-key
```

- Choose `(10) (sign only)`

- Give it a name and description

- Give it an expiration date, 1y is common

- Use a strong passphrase or password

- Give it a comment, I typically add the date

If you see a warning about incorrect permissions, you can run the following:

```bash
chmod 700 ~/.gnupg
chmod 600 ~/.gnupg/*
```

Verify:

```bash
ls -ld ~/.gnupg
# Should show: drwx------

ls -l ~/.gnupg
# Files should show: -rw-------
```

---

### Generate a Revocation Certificate

`mykey` must be a key specifier, either the keyID of the primary keypair or any
part of the user ID that identifies the keypair:

Replace `mykeyID` with the keyID of your primary key and store the cert in a
safe place:

```bash
gpg --output revoke.asc --gen-revoke mykeyID
Create a revocation certificate for this key? (y/N)
Please select the reason for the revocation:
  0 = No reason specified
  1 = Key has been compromised
  2 = Key is superseded
  3 = Key is no longer used
  Q = Cancel
(Probably you want to select 1 here)
Your decision?
```

The certificate will be output to a file `revoke.asc`. If the `--output` is
ommitted, the result will be placed on stdout.

Since it's a short certificate, you can print a hardcopy and store it somewhere
safe. The cert shouldn't be somewhere that others can access it since anyone
could publish the revoke cert and render the corresponding public key useless.

To apply the revoke cert, import it:

```bash
gpg --import revoke.asc
# And optionally push the revoked key to public keyservers to notify others:
gpg --keyserver keyserver.ubuntu.com --send-keys YOUR_KEYID
```

---

### Generate Gpg Subkeys

```bash
# Take note of your public key
gpg --list-keys --with-fingerprint
/home/jr/.gnupg/pubring.kbx
---------------------------
pub   ed25519/0x095782A1B124AF15 2025-08-23 [SCA] [expires: 2026-08-23]
Key fingerprint = 5908 9C5B FEC8 0D75 FCB0  E206 0958 82C1 A124 CF15
uid                   [ultimate] Jr (08-23-25) <sayls8@proton.me>
```

- Copy the KeyID, in this example it would be `0x095722B2A123CF15`. We will use
  it for the command below.

Now we will generate 2 subkeys, 1 for encryption and 1 for authentication.

```bash
gpg --expert --edit-key 0x095722B2A123CF15
```

Choose 11 (set your own capabilities) and add A (Authenticate) and type Q.
Create another key while still in the menu with only encrypt capabilities.

> ❗ `gpg --edit-key` has many more capabilities, after launching type `help`.

**Add Keygrip of Authenticate Subkey to `sshcontrol` for gpg-agent**

```bash
gpg --list-secret-keys --with-keygrip --keyid-format LONG
```

Copy the keygrip of the subkey with Authenticate capabilities

```bash
echo "6BD11826F3845BC222127FE3D22C92C91BB3FB32" > ~/.gnupg/sshcontrol
```

```bash
ssh-add -L
# you should see something like:
ssh-ed25519 AABCC3NzaC1lZDI1NTE5ABBAIHyujgyCjjBTqIuFM3EMUSo6RGklmOXQW3uWRhWdJ1Mm (none)
```

- By itself, a keygrip cannot be used to reconstruct your private key. It's
  derived from the public key material, not from the secret key itself so it's
  safe to version control. Don't put your keygrip in a public repo if you don't
  want people to know you use that key for signing/authentication. It's not a
  security risk, but it leaks a tiny bit of metadata.

The following article mentions the keygrip being computed from public elements
of the key:

- [gnupg-users what-is-a-keygrip](https://gnupg-users.gnupg.narkive.com/q5JtahdV/gpg-agent-what-is-a-keygrip)

Create a `~/.gnupg/gpg.conf`:

Copy the KeyID of the key with Authenticate capabilities and use it as your
default-key in `gpg.conf`:

- [RiseUp GPG Best Practices](https://riseup.net/ru/security/message-security/openpgp/gpg-best-practices)

```bash
#
# This is an implementation of the Riseup OpenPGP Best Practices
# https://help.riseup.net/en/security/message-security/openpgp/best-practices
#


#-----------------------------
# default key
#-----------------------------

# The default key to sign with. If this option is not used, the default key is
# the first key found in the secret keyring

#default-key 0xD8692123C4065DEA5E0F3AB5249B39D24F25E3B6


#-----------------------------
# behavior
#-----------------------------

# Disable inclusion of the version string in ASCII armored output
no-emit-version

# Disable comment string in clear text signatures and ASCII armored messages
no-comments

# Display long key IDs
keyid-format 0xlong

# List all keys (or the specified ones) along with their fingerprints
with-fingerprint

# Display the calculated validity of user IDs during key listings
list-options show-uid-validity
verify-options show-uid-validity

# Try to use the GnuPG-Agent. With this option, GnuPG first tries to connect to
# the agent before it asks for a passphrase.
use-agent


#-----------------------------
# keyserver
#-----------------------------

# This is the server that --recv-keys, --send-keys, and --search-keys will
# communicate with to receive keys from, send keys to, and search for keys on
keyserver hkps://keys.openpgp.org/

# Set the proxy to use for HTTP and HKP keyservers - default to the standard
# local Tor socks proxy
# It is encouraged to use Tor for improved anonymity. Preferrably use either a
# dedicated SOCKSPort for GnuPG and/or enable IsolateDestPort and
# IsolateDestAddr
#keyserver-options http-proxy=socks5-hostname://127.0.0.1:9050

# Don't leak DNS, see https://trac.torproject.org/projects/tor/ticket/2846
keyserver-options no-try-dns-srv

# When using --refresh-keys, if the key in question has a preferred keyserver
# URL, then disable use of that preferred keyserver to refresh the key from
keyserver-options no-honor-keyserver-url

# When searching for a key with --search-keys, include keys that are marked on
# the keyserver as revoked
keyserver-options include-revoked


#-----------------------------
# algorithm and ciphers
#-----------------------------

# list of personal digest preferences. When multiple digests are supported by
# all recipients, choose the strongest one
personal-cipher-preferences AES256 AES192 AES CAST5

# list of personal digest preferences. When multiple ciphers are supported by
# all recipients, choose the strongest one
personal-digest-preferences SHA512 SHA384 SHA256 SHA224

# message digest algorithm used when signing a key
cert-digest-algo SHA512

# This preference list is used for new keys and becomes the default for
# "setpref" in the edit menu
default-preference-list SHA512 SHA384 SHA256 SHA224 AES256 AES192 AES CAST5 ZLIB BZIP2 ZIP Uncompressed
```

Add the following to your shell config, either `.bashrc` or `.zshrc`:

```zsh
GPG_TTY=$(tty)
export GPG_TTY
export SSH_AUTH_SOCK=$(gpgconf --list-dirs agent-ssh-socket)
gpgconf --launch gpg-agent
```

Rebuild and then restart `gpg-agent` if necessary:

```bash
gpgconf --kill gpg-agent
gpgconf --launch gpg-agent
```

Test, these should match:

```bash
echo "$SSH_AUTH_SOCK"
# output
/run/user/1000/gnupg/d.wft5hcsny4qqq3g31c76534j/S.gpg-agent.ssh

gpgconf --list-dirs agent-ssh-socket
# output
/run/user/1000/gnupg/d.wft5hcsny4qqq3g31c76834j/S.gpg-agent.ssh
```

```bash
ssh-add -L
# Copy the entire following line:
ssh-ed25519 AABBC3NzaC1lZDI1NTE5AAAAIGXwhVokJ6cKgodYT+0+0ZrU0sBqMPPRDPJqFxqRtM+I (none)
```

- It shows `(none)` because the comment field is blank on subkeys.

### Backing up Your Keys

```bash
gpg --export-secret-keys --armor --output my-private-key-backup.gpg
```

Your private keys will be encrypted with a passphrase into a .gpg file. Store
this backup in a secure location line an encrypted USB drive. This can prevent
you from losing access to your keys in the case of disk failure or accidents.

You can export your public keys and publish them publicly if you choose:

```bash
gpg --export --armor --output my-public-keys.gpg
```

Now if your keys ever get lost or corrupted, you can import these backups.

--

### Remove and Store your Primary Key offline

> ❗ NOTE: After you remove your primary key, you will no longer be able to
> derive subkeys from it or sign keys unless you re-import it.

```bash
# extract the primary key
gpg -a --export-secret-key sayls8@proton.me > secret_key
# extract the subkeys, which we will reimport later
gpg -a --export-secret-subkeys sayls8@proton.me > secret_subkeys.gpg
# delete the secret keys from the keyring, so only subkeys are left
gpg --delete-secret-keys sayls8@proton.me
Delete this key from the keyring? (y/N) y
This is a secret key! - really delete? (y/N) y
# reimport the subkeys
gpg --import secret_subkeys.gpg
# verify everything is in order
gpg --list-secret-keys
# remove the subkeys from disk
rm secret_subkeys.gpg
```

I recommend also keeping a `.gpg` version to make it easy to re-import your
primary key: `gpg --export-secret-keys --armor --output private-key-bak.gpg`

Then store `secret_key` on an encrypted USB drive or somewhere offline. If you
want to protect it for now, you can just use the encryption subkey that we
created to encrypt `secret_key` with a passphrase:

```bash
gpg --list-keys --keyid-format LONG
```

Copy the KeyID of the subkey with encrypt capabilities for the following
command:

```bash
# Encrypting your secret key for yourself
gpg --encrypt --recipient Ox37ACA569C5C44787 secret_key
```

You can check that the secret key material is missing with
`gpg --list-secret-keys`, you should see `sec#` instead of `sec`.

```bash
gpg --list-secret-keys
# Output:
sec#  ed25519/0x
# ...snip...
```

The above set of commands are from the
[RiseUp Keep your primary key offline](https://riseup.net/ru/security/message-security/openpgp/gpg-best-practices#keep-your-primary-key-entirely-offline)

---

## Hardening OpenSSH

Install and configure fail2ban:

```bash
sudo pacman -S fail2ban
```

Create a `/etc/fail2ban/jail.local` file:

```bash
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 5
bantime = 3600  # 1 hour in seconds
findtime = 600
ignoreip = 127.0.0.1/8 ::1
banaction = iptables-multiport
```

Start and enable the service:

```bash
sudo systemctl enable fail2ban
sudo systemctl start fail2ban
```

Harden OpenSSH settings in `/etc/ssh/sshd_config`:

```bash
PasswordAuthentication no
PermitEmptyPasswords no
PubkeyAuthentication yes
AuthorizedKeysFile     %h/.ssh/authorized_keys
UsePAM yes
PermitTunnel no
UseDNS no
KbdInteractiveAuthentication no
X11Forwarding no  # or yes if you have X server enabled
MaxAuthTries 3
MaxSessions 2
ClientAliveInterval 300
ClientAliveCountMax 0
AllowUsers your-user
TCPKeepAlive no
AllowTcpForwarding no
AllowAgentForwarding no
LogLevel VERBOSE
PermitRootLogin no
KexAlgorithms curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com
```

Enable and start sshd:

```bash
sudo systemctl enable sshd
sudo systemctl start sshd
```

Ensure all of the permissions are correct:

```bash
chmod 755 $HOME
chmod 700 $HOME/.ssh
chmod 600 $HOME/.ssh/authorized_keys
```

Add the output of `ssh-add -L` to `~/.ssh/authorized_keys`

```bash
echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGXwhVokJ6cKgodYT+0+0ZrU0sBqMPPRDPJqFxqRtM+I (none)" > ~/.ssh/authorized_keys
```

Finally, test an ssh connection:

```bash
ssh user@hostname
# Example
ssh jr@archlinux
# Specify the port
ssh -p 22 user@hostname
```

---

#### Tip Change the Default Port

> ⚠️ Critical Warning: Do not close your existing SSH session until you
> successfully connect using the new port. If you make a mistake and get locked
> out, you'll need console access to your server to fix it

Edit `/etc/ssh/sshd_config` to add the line:

```config
Port 2222
```

Update the Firewall Rules in `/etc/nftables.conf`:

```conf
# ...snip...
table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;

        # Allow loopback
        iif "lo" accept

        # Accept established and related connections
        ct state established,related accept

        # Allow ICMPv6
        ip protocol icmp accept
        ip6 nexthdr icmpv6 accept

        # Allow SSH (port 2222)
        tcp dport 2222 ct state new accept

        # Allow HTTP and HTTPS (ports 80 and 443)
        tcp dport {80,443} ct state new accept
    }
# ...snip...
```

Reload the Firewall:

```bash
sudo nft -f /etc/nftables.conf
```

Restart sshd:

```bash
sudo systemctl restart sshd
```

Finally, text a connection:

```bash
ssh -p 2222 user@hostname
```

---

## USB Port Protection

It's important to protect your USB ports to prevent BadUSB attacks, data
exfiltration, unauthorized device access, malware injection, etc.

To get a list of your connected USB devices you can use `lsusb` from the
`usbutils` package.

```bash
lsusb
```

Generate a policy based on your currently attached USB devices with:

```bash
sudo usbguard generate-policy | sudo tee /etc/usbguard/rules.conf
```

```bash
sudo chmod 600 /etc/usbguard/rules.d/99-policy.conf
```

### USBGuard Daemon

Edit `/etc/usbguard/usbguard-daemon.conf` to set the policy to allow devices
that are already connected for root and your user:

```conf
# Default policy for devices that were already connected when the daemon started.
# Supported values: apply-policy, allow, block, reject, keep.
PresentDevicePolicy=allow

# A list of users and groups that are allowed to interact with the daemon
# via the IPC interface.
IPCAllowedUsers=root your-user
```

From the above file we can see that it expects its configuration file to be
located at `/etc/usbguard/rules.d/`:

```bash
sudo mkdir -p /etc/usbguard/rules.d
```

Create a file `/etc/usbguard/rules.d/99-policy.conf`:

```conf
# allow `only` devices with mass storage interfaces (USB Mass Storage)
allow with-interface equals { 08:*:* }

# allow mice and keyboards
# allow with-interface equals { 03:*:* }

# Reject devices with suspicious combination of interfaces
reject with-interface all-of { 08:*:* 03:00:* }
reject with-interface all-of { 08:*:* 03:01:* }
reject with-interface all-of { 08:*:* e0:*:* }
reject with-interface all-of { 08:*:* 02:*:* }
```

The above policy can be found in
[RedHat UsbGuard](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/security_guide/sec-using-usbguard)

The only allow rule is for devices with only mass storage interfaces (08:_:_)
i.e., USB Mass storage devices, devices like keyboards and mice (which use
interface class `03:*:*`) implicitly not allowed.(commented out)

The reject rules reject devices with a suspicious combination of interfaces. A
USB drive that implements a keyboard or a network interface is very suspicious,
these reject rules prevent that.

The `presentDevicePolicy = "allow"` allows any device that is present at daemon
start up even if they're not explicitly allowed. However, newly plugged in
devices must match an allow rule or get denied implicitly.

Enable/Start `usbguard.service`:

```bash
sudo systemctl enable usbguard
sudo systemctl start usbguard --now
```

Check status:

```bash
sudo systemctl status usbguard
```

- If you plug something new in and it doesn't work, this is why. Remember this!

---

### Firejail

- [Arch Wiki Firejail](https://wiki.archlinux.org/title/Firejail)

```bash
sudo pacman -S firejail
```

Usage:

```bash
firejail librewolf
```

Using by default:

```bash
sudo firecfg
```

This creates symbolic links in `/usr/local/bin/` pointing to `/usr/bin/firejail`
for programs for which Firejail has default or self-created profiles.

You can inspect `/etc/firejail/` to see all the pre-baked profiles available.

With firejail running, I noticed that none of my browsers would allow me to
download anything. A fix for this is to run:

```bash
sudo firejail --noprofile firefox
```

Download your file, close firefox and run again in the firejail sandbox.

---

## AppArmor

[AppArmor](https://apparmor.net/) is a
[Mandatory Access Control](https://wiki.archlinux.org/title/Mandatory_Access_Control)
(MAC) system, implemented upon the
[Linux Security Modules](https://en.wikipedia.org/wiki/Linux_Security_Modules)(LSM)
-- Arch Wiki

MAC systems generally block all access by default, only permitting actions that
are explicitly defined as allowed in their security policy or access profiles.

This is why, if you read about creating your own policy that they recommend
setting AppArmor to complain mode while you use said app using all functionality
and APIs you can think of before setting to enforce. Within a policy everything
is default-deny so any action not covered in the above steps will be blocked by
default.

> ❗️ The AppArmor policy con only be considered default deny if it is deployed
> as a complete system policy which we don't do here. The apps and parts of the
> system that don't have pre-defined policies aren't covered by AppArmor so are
> therefore default allow. You can get there in time but it's beyond the scope
> of this section.

Install:

```bash
sudo pacman -S apparmor
```

Add the following to `/etc/default/grub` in `GRUB_CMDLINE_LINUX_DEFAULT`:

```grub
GRUB_CMDLINE_LINUX_DEFAULT="lsm=landlock,lockdown,yama,integrity,apparmor,bpf"
```

Rebuild grub:

```bash
sudo grub-mkconfig -o /boot/grub/grub.cfg
```

Start/Enable AppArmor:

```bash
sudo systemctl start apparmor
sudo systemctl enable apparmor
```

Ensure the LSM is loaded with:

```bash
zgrep CONFIG_LSM=/proc/config.gz
# &
cat /sys/kernel/security/lsm
```

Reboot, and run `sudo aa-enabled`, and `sudo aa-status`. You should see many
profiles in enforce mode.

Further reading:

- [AppArmor Quick Intro](https://apparmor.net/)

- [AppArmor Wiki](https://gitlab.com/apparmor/apparmor/-/wikis/home)

- [Arch Wiki AppArmor](https://wiki.archlinux.org/title/AppArmor)

```bash
paru -S bazaar
```

speling eror

## Creating profiles that aren't pre-configured

### Auditd

Install with:

```bash
sudo pacman -S audit
```

Enable:

```bash
sudo systemctl enable auditd
sudo systemctl start auditd --now
```

To create new profiles, `auditd` should be running. AppArmor can use kernel
audit logs from the userspace auditd daemon, allowing you to build new profiles.

- [Audit Framework](https://wiki.archlinux.org/title/Audit_framework)

A basic set of rules could be to create a `/etc/audit/rules.d/audit.rules` with
the following contents:

```audit.rules
# Clear existing rules
-D

# Set buffer size
-b 8192

# Monitor /etc/passwd for modifications
-w /etc/passwd -p wa -k passwd_changes

# Monitor sudo command execution
-w /usr/bin/sudo -p x -k sudo_usage

# Enable auditing
-e 1
```

Validate and load the rules, this will populate `/etc/audit/audit.rules` with
the rules we just set:

```bash
sudo augenrules --load
```

Ensure `auditd` is running:

```bash
sudo systemctl status auditd
```

Since we set a watch rule for sudo let's run an update and check the auditd
logs:

```bash
sudo pacman -Syu
sudo ausearch -k sudo_usage
```

Verify the rules are loaded:

```bash
sudo auditctl -l
```

Be careful here, if you enable `auditd` and don't iron out the kinks I've found
that it freezes after you enter your cryptroot passphrase. If this happens to
you, follow the chroot steps but skip the `arch-chroot /mnt` step and instead
run:

```bash
systemctl --root=/mnt disable auditd
```

Unmount the partitions, close cryptroot, and Reboot.

---

### Doas over sudo

For a more minimalist version of `sudo` with a smaller codebase and attack
surface, consider `doas`:

```bash
sudo pacman -S opendoas
```

Create `/etc/doas.conf` with the following contents:

```conf
permit setenv {PATH=/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin} :wheel
```

You can add a line below that one like `permit nopass your-username as root:`
Enabling your user passwordless usage, it's much less secure but an option none
the less.

```bash
doas pacman -R sudo base-devel
```

Secure the `doas.conf`:

```conf
doas chown -c root:root /etc/doas.conf
doas chmod -c 0400 /etc/doas.conf
```

Create a symlink replacing sudo with doas:

```bash
ln -s $(which doas) /usr/bin/sudo
```

### Resources

- [Arch Wiki Secure Boot](https://wiki.archlinux.org/title/Unified_Extensible_Firmware_Interface/Secure_Boot)

- [rodsbooks Secure Boot](https://www.rodsbooks.com/efi-bootloaders/secureboot.html)
