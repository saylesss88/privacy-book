# Hardening Arch Linux

<details>
<summary> ✔️ Click to Expand Table of Contents</summary>

<!-- toc -->

</details>

> ⚠️ Warning: I am not a security expert. This guide presents various options
> for hardening Arch Linux, but it is your responsibility to evaluate whether
> each adjustment suits your specific needs and environment. Security hardening
> and process isolation can introduce stability challenges, compatibility
> issues, or unexpected behavior. Additionally, these protections often come
> with performance tradeoffs. Always conduct thorough research, there are no
> plug and play one size fits all security solutions.

> Much of this guide draws inspiration or recommendations from the well-known
> [Linux Hardening Guide](https://madaidans-insecurities.github.io/guides/linux-hardening.html)
> by Madaidan's Insecurities and the Arch Wiki. Arch is great but when anonymity
> truly matters, use Whonix or Tails. The Whonix Docs have a specific section or
> Arch with KVM that is an excellent resource.

- [Whonix KVM#Arch_Linux](https://www.whonix.org/wiki/KVM#Arch_Linux), if you
  plan on using this think twice before enabling `dnscrypt-proxy` and you might
  want to consider ufw firewall rather than the nftables I share in this guide
  because of Port conflicts.

Keep in mind that Arch’s security posture is ultimately constrained by the
broader limitations of Linux security mechanisms, upstream tooling, and ongoing
development priorities.

I will assume that you're using a UKI with Secure Boot enabled with systemd-boot
for this section. If you don't and want to, you can follow the
[Guide](https://mako088.github.io/arch/enc_install.html) that I wrote or more
obviously, the Wiki.

## The Basics

Check the [Arch Linux Security Tracker](https://security.archlinux.org/) for
information about known vulnerabilities affecting Arch packages. It lists CVEs
(Common Vulnerabilities and Exposures) affecting packages, the severity, the
fixed versions, and advisory details.

Backup your system regularly, many guides consider the data already lost if it
isn't backed up because without a backup, any data loss event (hardware failure,
ransomware attack, accidental deletion, natural disaster) becomes irreversible.
Backups act as a critical safety net that enables recovery. Without them, once
data is corrupted, deleted, or encrypted, there is no reliable way to restore
it, effectively making it lost permanently.

The 3-2-1 Backup Rule:

- 3 copies of data. (Ensuring redundancy)

- 2 storage types. (Reduces risk)

- 1 offsite backup. (Protects against cyber threats and natural disasters)

- There is a backup guide for btrfs in
  [enc_install](https://mako088.github.io/arch/enc_install.html)

Use Full Disk Encryption to protect your data at rest.

Encryption is the process of using an algorithm to scramble plaintext data into
ciphertext, making it unreadable except to a person who has the key to decrypt
it.

**Data at rest** is data in storage, such as a computer's or a servers hard
disk.

**Data at rest encryption** (typically hard disk encryption), secures the
documents, directories, and files behind an encryption key. Encrypting your data
at rest prevents data leakage, physical theft, unauthorized access, and more as
long as the key management scheme isn't compromised.

Enable a UEFI password or Administrator password where it requires
authentication in order to access the UEFI/BIOS.

Use a different password/passphrase for encryption and userspace.(i.e., user
passwd)

Use Secure Boot, with a Unified Kernel Image (UKI). TPM can, in some ways
increase security; I may add a section in the future.

When Secure Boot is used with a Unified Kernel Image, it provides enhanced
protection compared to traditional boot methods because when Secure Boot
verifies the UKI's signature, it ensures the integrity and authenticity of:

- The kernel itself,

- The `initramfs`,

- The kernel command line parameters,

- And indirectly, the bootloader that loads the UKI (since the bootloader
  verifies the UKI signature before execution).

- Secure boot doesn't protect against runtime kernel exploits.

This means that any tampering with these components, such as injecting malware
into the `initramfs`, altering boot parameters, or swapping the kernel would
break the signature verification and prevent the system from booting.

`systemd-boot` has a smaller attack surface and is often recommended over GRUB
for hardened systems.

- [Encrypted Install Guide w/ systemd-boot and UKI Secure Boot](https://mako088.github.io/arch/enc_install.html)

Useful Resources:

<details>
<summary> ✔️ Click to Expand Secure Boot Resources </summary>

- [The Strange State of Authenticated Boot and Encryption](https://0pointer.net/blog/authenticated-boot-and-disk-encryption-on-linux.html)

- When using a UKI with Secure Boot, the initrd is authenticated because it's a
  sealed component of the single signed image.

</details>

---

### Best Practices and Standards

It’s crucial to **document every system change** meticulously. Since Arch Linux
typically relies on manual configuration and does not use full declarative
version control by default, maintaining clear records, such as detailed
changelogs, notes, or Git repositories for your config files is essential.

A few options to version control some of your dotfiles:

Tools like [GNU Stow](https://www.gnu.org/s/stow/manual/stow.html) and
[chezmoi](https://chezmoi.io/install/) help bring structure and version control
to manual configurations in Arch Linux.

- GNU Stow uses a symlink farm approach to manage dotfiles and configuration
  directories cleanly, making it easy to track and revert changes by organizing
  files under a single version-controlled directory.

- [chezmoi](https://www.chezmoi.io/) is a powerful dotfile manager focused on
  reproducible, encrypted, and template-driven config management. It simplifies
  applying changes across multiple machines and maintaining a documented history
  of modifications.

Using these tools enhances your ability to maintain clear, version-controlled
records of system changes. Consider making your dotfiles repo private if you're
unsure what you need to protect.

By breaking changes into smaller, manageable tasks and documenting them with
descriptive messages, you create a clear history of modifications. This makes it
far simpler to troubleshoot issues, revert problematic changes, and maintain
security best practices over time.

**User and Permission Management**

- **Implement distinct user accounts** to minimize the risk associated with
  compromised accounts.

- **Execute Specific Commands**: Always execute the specific command that
  requires elevation, rather than using sudo to open an entire root shell:
  - **Good**: `sudo pacman -Syu`

  - **Bad**: Running `sudo su -` and then running `pacman -Syu`

- Consider using a more secure or minimal form of privilege escalation like
  `doas`, `sudo-rs`, or `run0` instead of standard `sudo`.

---

### User and group management & Strong Passwords

- Users and groups are used as a form of
  [access control](https://en.wikipedia.org/wiki/access_control#Computer_security).
  They control access to the system's files, directories, and peripherals. This
  is a security feature that limits access in certain specific ways.
  - When granting access to a resource, create a specific group and add only the
    necessary users to it, rather than granting broad access to all root or
    wheel users. Demonstrated in: **[Doas over sudo](#doas-over-sudo)**.

- Apply the principle of least privilege by assigning users only the permissions
  they actually need.

- Avoid running services or applications as root; use dedicated service accounts
  where possible.

**Passwords/Password Quality**

```bash
sudo pacman -S libpwquality
```

Edit `/etc/pam.d/passwd` file to read as:

```passwd
#%PAM-1.0
password required pam_pwquality.so retry=2 minlen=10 difok=6 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1 [badwords=myservice mydomain] enforce_for_root
password required pam_unix.so use_authtok sha512 shadow
```

- [pam_pwuality(8)](https://man.archlinux.org/man/pam_pwquality.8)

- [pam_unix(8)](https://man.archlinux.org/man/pam_unix.8)

- Use strong passwords and a password manager. The Arch Wiki
  [Security](https://wiki.archlinux.org/title/Security) section goes in depth
  about this.

- Regularly review group memberships and file permissions, especially on
  sensitive system files.

---

**Package Management and System Minimalism**

- Favor packages from the official Arch repositories managed with pacman, as
  they are cryptographically signed and vetted by trusted Arch developers.

- Use AUR packages cautiously; they lack official cryptographic signatures and
  require manual review and vetting before installation.

- Install only the software and services you truly need to reduce the attack
  surface and minimize vulnerabilities.

- Remove unused packages and disable unnecessary services to free up resources
  and limit potential entry points.

- Consider using `arch-audit` to find packages with vulnerabilities and patch
  said vulnerabilities.

---

**Network and Privacy Best Practices**

On a hardened Linux system, the browser is most often the weakest link exposed
to the internet, and so security, privacy, and anti-tracking features of
browsers are now as important, or even more important than platform-level
protections.

- [Hardening Firefox/Librewolf Guide](https://mako088.github.io/arch/hardening_firefox.html)

- Prefer software and hardware with privacy-respecting defaults and a strong
  security posture.

- Use encrypted DNS and VPNs where possible: encrypted DNS protects your
  queries, while VPNs hide your IP address. Note that VPNs do not provide
  anonymity on their own and fingerprinting techniques can still reveal
  information.
  - [dnscrypt-proxy w/ dnsmasq guide](https://mako088.github.io/arch/enc_dns.html)

- Implement a firewall to control inbound and outbound network traffic based on
  predefined security rules. Firewalls serve as a critical layer of defense to
  reduce attack surfaces and monitor suspicious activity.

- Secure SSH access by disabling root login, changing default ports, and
  enforcing public-key authentication to prevent brute-force and unauthorized
  access attempts.

---

**Cryptography and Future-Proofing**

- The
  [NSA, CISA, and NIST warn](https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/3498776/post-quantum-cryptography-cisa-nist-and-nsa-recommend-how-to-prepare-now/)
  that nation-state actors are likely stockpiling encrypted data now, preparing
  for a future when quantum computers could break today’s most widely used
  encryption algorithms. Sensitive data with long-term secrecy needs is
  especially at risk.

- This is a wake-up call to use the strongest encryption available today and to
  plan early for post-quantum security.

- [NIST First 3 Post-Quantum Encryption Standards](https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards)
  Organizations and individuals should prepare to migrate cryptographic systems
  to these new standards as soon as practical.

- They chose
  [Four Quantum-Resistant Cryptographic Algorithms](https://www.nist.gov/news-events/news/2022/07/nist-announces-first-four-quantum-resistant-cryptographic-algorithms)
  warning that public-key cryptography is especially vulnerable and widely used
  to protect digital information.

- Follow developments from entities like
  [NIST’s post-quantum encryption standards](https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards)
  and implement recommendations as soon as practical.

- Stay informed of quantum-resistant algorithm updates, especially for
  public-key cryptography, as recommended by NIST and security agencies.

---

## Hardening/Sandboxing systemd

- [Arch Wiki systemd/sandboxing](https://wiki.archlinux.org/title/Systemd/Sandboxing)

`systemd` is the core "init system" and service manager that controls how
services, daemons, and basic system processes are started, stopped and
supervised on modern Linux distributions, including Arch. It provides a suite of
basic building blocks for a Linux system as well as a system and service manager
that runs as `PID 1` and starts the rest of the system.

Because it launches and supervises almost all system services, hardening systemd
means raising the baseline security of your entire system.

```bash
sudo systemd-analyze security
# ...snip
systemd-hostnamed.service                 1.7 OK        🙂
systemd-importd.service                   5.0 MEDIUM    😐
systemd-journald.service                  4.9 OK        🙂
systemd-logind.service                    2.8 OK        🙂
systemd-machined.service                  6.2 MEDIUM    😐
```

Check a specific unit:

```bash
sudo systemd-analyze security NetworkManager
```

```bash
sudo systemctl edit NetworkManager.service
→ Overall exposure level for NetworkManager.service: 9.6 UNSAFE    😨
```

The following file will open in your $EDITOR, these settings take it from UNSAFE
to OK:

```conf
[Service]
NoNewPrivileges = true
ProtectHome = true
ProtectKernelModules = true
ProtectKernelLogs = true
ProtectControlGroups = true
ProtectClock = true
ProtectHostname = true
ProtectProc = "invisible"
ProtectKernelTunables=yes
PrivateTmp = true
RestrictRealtime = true
SystemCallFilter=~@mount ~@module ~@swap ~@obsolete ~@cpu-emulation ptrace
CapabilityBoundingSet=~CAP_KILL ~CAP_SYS_CHROOT ~CAP_AUDIT_* ~CAP_SETUID ~CAP_SETGID ~CAP_SETPCAP ~CAP_SYS_ADMIN ~CAP_NET_BIND_SERVICE ~CAP_NET_BROADCAST ~CAP_NET_RAW ~CAP_DAC_OVERRIDE ~CAP
_FOWNER ~CAP_IPC_OWNER

# Allow only the essential families (AF_PACKET and exotic ones are blocked by omission)
#RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6
RestrictNamespaces = true
RestrictSUIDSGID = true
MemoryDenyWriteExecute = true
SystemCallArchitectures = "native"
LockPersonality= true
UMask=0077
User=root
PrivateDevices=yes

### Edits below this comment will be discarded
```

```bash
sudo systemctl daemon-reload
sudo systemctl restart NetworkManager
```

Sometimes you may need to reboot for the changes to take effect.

```bash
sudo systemd-analyze security NetworkManager
→ Overall exposure level for NetworkManager.service: 4.5 OK 🙂
```

> ❗️ This is just one example of the many services that you can harden if you so
> choose.

Further reading on systemd:

<details>
<summary> ✔️ Click to Expand Systemd Resources </summary>

- [systemd.io](https://systemd.io/)

- [Rethinking PID 1](https://0pointer.de/blog/projects/systemd.html)

- [Biggest Myths about Systemd](https://0pointer.de/blog/projects/the-biggest-myths.html)

</details>

---

## Lynis and other tools

Lynis is a security auditing tool for systems based on UNIX like Linux, macOS,
BSD, and others.--[lynis repo](https://github.com/CISOfy/lynis)

```bash
sudo pacman -S lynis
```

List commands:

```bash
sudo lynis show commands
Commands:
lynis audit
lynis configure
lynis generate
lynis show
lynis update
lynis upload-only
```

Audit the system:

```bash
sudo lynis audit system
 Lynis security scan details:

  Hardening index : 83 [################    ]
  Tests performed : 255
  Plugins enabled : 0
```

- The "Lynis hardening index" is an overall impression on how well a system is
  hardened. However, this is just an indicator on measures taken - not a
  percentage of how safe a system might be. A score over 75 typically indicates
  a system with more than average safety measures implemented.

- Lynis will give you more recommendations for securing your system as well.

---

**rkhunter** (Rootkit Hunter):

- [Arch Wiki RKhunter](https://wiki.archlinux.org/title/Rkhunter)

```bash
sudo pacman -S rkhunter
```

Update the file properties database:

```bash
sudo rkhunter --propupd
```

Keep rkhunters data files up-to-date with:

```bash
sudo rkhunter --update
```

Run a system check:

```bash
sudo rkhunter --check --sk
```

Validate the config files:

```bash
sudo rkhunter --config-check
```

Get rid of false positives by adding the following to `/etc/rkhunter.conf`:

```conf
SCRIPTWHITELIST=/usr/bin/egrep
SCRIPTWHITELIST=/usr/bin/fgrep
SCRIPTWHITELIST=/usr/bin/ldd
SCRIPTWHITELIST=/usr/bin/vendor_perl/GET
```

Run a config check:

```bash
sudo rkhunter --config-check
```

---

**ClamAV**

- [Arch Wiki ClamAV](https://wiki.archlinux.org/title/ClamAV)

```bash
sudo pacman -S clamav
```

Update the virus databases manually:

```bash
sudo freshclam
```

Scan your system:

```bash
sudo clamscan -r ~
----------- SCAN SUMMARY -----------
Known viruses: 8708646
Engine version: 1.4.3
Scanned directories: 6505
Scanned files: 79796
Infected files: 0
Data scanned: 4387.29 MB
Data read: 5191.41 MB (ratio 0.85:1)
Time: 1748.802 sec (29 m 8 s)
Start Date: 2025:10:03 14:32:58
End Date:   2025:10:03 15:02:07
```

> ❗️ NOTE: This can take a while, I recommend using `caffeine-ng` or `caffeine`
> for this to prevent your system going to sleep while the scan completes.

```bash
paru -S caffeine-ng
```

This creates a coffee cup icon in your bar config on next reboot. If you're in
the middle of something and don't want to reboot run:

```bash
caffeine &
```

Click the icon and `Enable Caffeine` to prevent sleep.

---

## Hardening the Kernel

Given the kernel's central role, it's a frequent target for malicious actors,
making robust hardening essential.

You can use the `linux-hardened` kernel to have a kernel that prioritizes
security over anything else:

```bash
sudo pacman -S linux-hardened linux-hardened-headers
```

Generate the `initramfs` for the hardened kernel:

```bash
sudo mkinitcpio -p linux-hardened
```

Configure systemd-boot to boot the hardened kernel, the entries are configured
under `/boot/loader/entries/`. Create or edit an entry file, for example
`/boot/loader/entries/arch-linux-hardened.conf`:

```text
title   Arch Linux Hardened
linux   /vmlinuz-linux-hardened
initrd  /initramfs-linux-hardened.img
options rd.luks.name=YOUR_UUID=cryptroot root=/dev/mapper/cryptroot rw quiet
```

Replace `YOUR_UUID` with the UUID of the encrypted root partition (from `blkid`)

To set this as the default boot entry and enable booting the last selected
kernel automatically, edit `/boot/loader/loader.conf`:

```text
default arch-linux-hardened.conf
timeout 4
console-mode auto
```

Edit `/etc/mkinitcpio.d/linux-hardened.preset`:

```preset
# mkinitcpio preset file for the 'linux-hardened' package

ALL_config="/etc/mkinitcpio.conf"
ALL_kver="/boot/vmlinuz-linux-hardened"

PRESETS=('default' 'fallback')

#default_config="/etc/mkinitcpio.conf"
# default_image="/boot/initramfs-linux-hardened.img"
default_uki="/boot/EFI/Linux/arch-linux-hardened.efi"
default_options="--splash /usr/share/systemd/bootctl/splash-arch.bmp"

#fallback_config="/etc/mkinitcpio.conf"
# fallback_image="/boot/initramfs-linux-hardened-fallback.img"
fallback_uki="/boot/EFI/Linux/arch-linux-hardened-fallback.efi"
fallback_options="-S autodetect"
```

Reboot and `linux-hardened` should be chosen by default. You can also choose
additional kernels if needed.

---

## Hardening your current Kernel

Sometimes `linux-hardened` just won't work on your system without some serious
digging. You can harden your current kernel, or even better would be to harden
the Long-Term Support (LTS) kernel.

The Linux kernel is typically released under two forms: stable and long-term
support (LTS). Choosing either has consequences, do your research.
[Stable vs. LTS kernels](https://madaidans-insecurities.github.io/guides/linux-hardening.html#stable-vs-lts)

- [The Linux Kernel Archives Active kernel releases](https://www.kernel.org/category/releases.html)

See which kernel you're currently using with:

```bash
# show the kernel release
uname -r
# show kernel version, hostname, and architecture
uname -a
```

Show the configuration of your current kernel:

```bash
zcat /proc/config.gz
```

`sysctl` is a tool that allows you to view or modify kernel settings and
enable/disable different features.

Check what each setting does [sysctl-explorer](https://sysctl-explorer.net/)

Refer to
[madadaidans-insecurities#sysctl-kernel](https://madaidans-insecurities.github.io/guides/linux-hardening.html#sysctl-kernel)
for the following settings and their explainations.

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

Check Active Linux Security Modules:

```bash
cat /sys/kernel/security/lsm
# Output:
File: /sys/kernel/security/lsm
capability,landlock,yama,bpf,apparmor
```

Check Kernel Configuration Options:

```bash
zcat /proc/config.gz | grep CONFIG_SECURITY_SELINUX
zcat /proc/config.gz | grep CONFIG_HARDENED_USERCOPY
zcat /proc/config.gz | grep CONFIG_STACKPROTECTOR
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

> ⚠️ WARNING: Always do your own research, you can find explanations to the
> following settings in:
> [madaidans insecurities Linux Hardening guide](https://madaidans-insecurities.github.io/guides/linux-hardening.html#sysctl-kernel).

You can apply these on top of the hardened kernel as well:

```conf
# Kernel Security Hardening
# ----------------------------------------------------------------------
# allow set-user-ID processes to dump core
fs.suid_dumpable = 2

# prevent pointer leaks
kernel.kptr_restrict = 2

# restrict kernel log to CAP_SYSLOG capability
kernel.dmesg_restrict = 1

# Note: certian container runtimes or browser sandboxes might rely on the following
# restrict eBPF to the CAP_BPF capability
kernel.unprivileged_bpf_disabled = 1

# should be enabled along with bpf above
# net.core.bpf_jit_harden = 2

# restrict loading TTY line disciplines to the CAP_SYS_MODULE
dev.tty.ldisk_autoload = 0

# prevent exploit of use-after-free flaws
vm.unprivileged_userfaultfd = 0

# kexec is used to boot another kernel during runtime and can be abused
kernel.kexec_load_disabled = 1

# Kernel self-protection
# SysRq exposes a lot of potentially dangerous debugging functionality to unprivileged users
# 4 makes it so a user can only use the secure attention key. A value of 0 would disable completely
kernel.sysrq = 4

# disable unprivileged user namespaces, Note: Docker and other apps may need this
# kernel.unprivileged_userns_clone = 0 # commented out because it makes apps I need fail

# restrict all usage of performance events to the CAP_PERFMON capability
kernel.perf_event_paranoid = 3

# Network Security Hardening
# ----------------------------------------------------------------------

# protect against SYN flood attacks (denial of service attack)
net.ipv4.tcp_syncookies = 1

# protection against TIME-WAIT assassination
net.ipv4.tcp_rfc1337 = 1

# enable source validation of packets received (prevents IP spoofing)
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.rp_filter = 1

# Disable ICMP redirects for IPv4
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0

# Disable ICMP redirects for IPv6 (Protect against IP spoofing)
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# prevent man-in-the-middle attacks (by ignoring ICMP echo requests)
net.ipv4.icmp_echo_ignore_all = 1

# ignore bogus ICMP errors, helps avoid Smurf attacks
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Disable IP forwarding
net.ipv4.conf.all.forwarding = 0

# Disable acceptance of source-routed packets for IPv4
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_source_route = 0

# Disable acceptance of source-routed packets for IPv6
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Disable IPv6 forwarding
net.ipv6.conf.all.forwarding = 0

# Disable Router Advertisements acceptance
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0

# TCP Hardening
# ----------------------------------------------------------------------

# Disable TCP SACK (Selective Acknowledgement)
net.ipv4.tcp_sack = 0
net.ipv4.tcp_dsack = 0
net.ipv4.tcp_fack = 0

# Userspace/Memory Security
# ----------------------------------------------------------------------

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
# NOTE: This is generally deprecated/obsolete on modern kernels that use other hardening measures
# kernel.exec-shield = 1

# TCP Optimization
# ----------------------------------------------------------------------

# TCP Fast Open: 3 = enable for both incoming and outgoing connections
net.ipv4.tcp_fastopen = 3

# Bufferbloat mitigations + slight improvement in throughput & latency
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = cake
```

</details>

## Kernel and Namespace Hardening and Blacklisting

- **Protect the kernel image**:
  - Enable Secure Boot to ensure only trusted boot components are loaded.

  - Enforce kernel module signature verification by adding
    `module.sig_enforce=1` to your kernel parameters (e.g., create
    `/etc/cmdline.d/security.conf` with this line). This restricts loading
    unsigned kernel modules.

  - NOTE: This setting is strict and may break compatibility with some drivers
    or modules. Thorough testing and research are recommended before enforcing
    it.

- **Protect the `/boot` partition**:
  - The above setting is fairly strict and will break some things. Do research
    before going so strict.

  - Make `/boot` read-only if you have a high threat model. It can cause issues
    though, setting more strict permissions helps.

- Lock kernel modules (optional):
  - Set `module.sig_enforce=1` in kernel parameters.(i.e.,
    `/etc/cmdline.d/security.conf`)

Blacklist unneeded modules in `/etc/modprobe.d/blacklist.conf`:

```conf
blacklist dccp          # Datagram Congestion Control Protocol
blacklist sctp          # Stream Control Transmission Protocol
blacklist rds           # Reliable Datagram Sockets
blacklist tipc          # Transparent Inter-Process Communication
blacklist n_hdlc        # High-level Data Link Control
blacklist ax25          # Amateur X.25
blacklist netrom        # NetRom
blacklist x25           # X.25
blacklist rose
blacklist decnet
blacklist econet
blacklist af_802154     # IEE 802.15.4
blacklist ipx           # Internetwork Packet Exchange
blacklist appletalk
blacklist psnap         # SubnetworkAccess Protocol
blacklist p8023         # Novell raw IEE 802.3
blacklist p8022         # IEE 802.3
blacklist can           # Controller Area Network
blacklist atm
# Various rare filesystems
blacklist cramfs
blacklist freevxfs
blacklist jffs2
blacklist hfs
blacklist hfsplus
blacklist udf
# Less rare but often recommended
# Optionally blacklist squashfs, cifs, nfs etc. by uncommenting:
# blacklist squashfs
# blacklist cifs
# blacklist nfs
# blacklist nfsv3
# blacklist nfsv4
# blacklist ksmbd
# blacklist gfs2
# blacklist vivid
```

There are more suggestions in the madaidans insecurities guide.

Apply the changes:

```bash
sudo mkinitcpio -P
```

Check which modules were included in the initramfs (Long Output):

```bash
mkinitcpio -v > /tmp/mk.txt
```

Then search through the file and ensure they weren't loaded.

> ❗️ Note: This may break some networking and virtualization tools.

- Force-enable PTI (Page Table Isolation):
  - Add `pti=on` to the kernel command line.

- User namespaces:
  - Do **not** set `kernel.unprivileged_userns_clone=0` if desktop
    sandboxing/containers are used.

  - Set `kernel.unprivileged_userns_clone=0` in `/etc/sysctl.d/` to disable if
    containers are not required.

- SMT/Hyperthreading policy:
  - For extra isolation, add `nosmt` to kernel parameters.

  - Disabling SMT reduces performance.

---

## Firewall

**nftables** is designed to replace **iptables** by providing a modern,
simplified, and unified packet filtering and classification framework in the
Linux kernel. It reuses the underlying Netfilter infrastructure but introduces a
new kernel API and completely different user-space tool (`nft`).

- [Arch Wiki nftables](https://wiki.archlinux.org/title/Nftables)

**Installation**:

```bash
sudo pacman -S nftables
```

There is an example firewall ruleset located at `/etc/nftables.conf` and more
examples located in `/usr/share/nftables/` and
`/usr/share/doc/nftables/examples/`

Flush existing iptables Rules & Disable iptables if necessary.

**Create nftables ruleset**:

```bash
#-----------------------------------------------------------------------------
# Flush existing rules: ensure a clean slate before loading new rules
#-----------------------------------------------------------------------------
flush ruleset
table inet filter {
    # -------------------------------------------------------------------------
    # INPUT CHAIN (Incoming Traffic destined for this host)
    # Default is to DROP all incoming traffic
    # -------------------------------------------------------------------------
    chain input {
        type filter hook input priority filter; policy drop;

        # Drop invalid packets (e.g., malformed or out-of-state)
        ct state invalid drop

        # Allow loopback traffic (localhost to localhost)
        iif "lo" accept

        # Allow established and related connections (replies to outgoing, FTP helper)
        ct state established,related accept

        # Allow specific ICMP types for IPv4
        ip protocol icmp icmp type { echo-request, echo-reply, destination-unreachable, time-exceeded } accept

        # Allow critical ICMPv6 types for IPv6 (essential for network function)
        ip6 nexthdr icmpv6 icmpv6 type { echo-request, echo-reply, destination-unreachable, packet-too-big, time-exceeded, parameter-problem, nd-router-advert, nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert } accept

        # Allow SSH (port 2222) with rate-limiting to prevent brute-force attacks
        tcp dport 2222 ct state new limit rate 15/minute accept

        # Allow HTTP and HTTPS (ports 80 and 443)
        tcp dport { 80, 443 } ct state new accept

        # Log packets that reach the end of the chain before they are dropped by the policy (optional)
        log prefix "nft-input-drop: "
    }

    # -------------------------------------------------------------------------
    # FORWARD CHAIN (Routed Traffic passing through this host)
    # Default is to DROP all routed traffic (host-based firewall)
    # -------------------------------------------------------------------------
    chain forward {
        type filter hook forward priority filter; policy drop;

        # Drop invalid packets
        ct state invalid drop

        # Allow established and related connections
        ct state established,related accept

        # Add specific FORWARD rules here if the machine is acting as a router/gateway
    }

    # -------------------------------------------------------------------------
    # OUTPUT CHAIN (Outgoing Traffic originating from this host)
    # Default is to DROP all outgoing traffic for maximum security
    # -------------------------------------------------------------------------
    chain output {
    type filter hook output priority filter; policy drop;

    # Allow essential local communication
    oif "lo" accept

    # Allow replies for established and related connections (critical)
    ct state established,related accept

    # Allow DNS queries (UDP and TCP)
    udp dport 53 accept
    tcp dport 53 accept

    # Allow general outbound web access (e.g., for updates, API calls)
    tcp dport { 80, 443 } accept

    # Allow Git (and general SSH client) outgoing connections
    tcp dport 22 ct state new accept

    # Allow NTP (Network Time Protocol) for time synchronization
    udp dport 123 accept

    # Use meta l4proto to correctly match MLDv2 Type 143 packets
    meta l4proto ipv6-icmp icmpv6 type {
        echo-request,
        destination-unreachable,
        time-exceeded,
        parameter-problem,
        nd-neighbor-solicit,
        nd-neighbor-advert,
        mld2-listener-report
    } accept

    # Log packets that reach the end of the chain before they are dropped by the policy (optional)
    log prefix "nft-output-drop: "
    }
}
```

> ❗️ Most desktop firewalls default to **allow all outgoing traffic**
> (`policy accept` on the output chain). This is done for convenience, as it
> prevents applications from breaking. However, for a system practicing zero
> trust, the best practice is to enforce a **default deny**(`policy drop`) on
> the output chain and **only explicitly allow** the services the system needs.

```bash
sudo systemctl enable nftables.service
sudo systemctl start nftables.service
```

Load and test the rules if in a different location than the default:

```bash
sudo nft -f /path/to/your/nftables.conf
```

or in default location:

```bash
sudo nft -f /etc/nftables.conf
```

> ❗️ If you don't use SSH or host a web server or any service, don't allow SSH
> and HTTP/HTTPS.

```bash
sudo nft list ruleset
```

---

## SSH & GPG Key Generation and Safety

### ssh-keygen

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

### GnuPG and gpg-agent

<details>
<summary> ✔️ Click to Expand GnuPG section </summary>

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

---

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

</details>

---

## Hardening OpenSSH

OpenSSH is a tool that allows you to remotely connect to your machine with the
SSH protocol. It encrypts all traffic to prevent eavesdropping, connection
hijacking, and other attacks.

- [Arch Wiki OpenSSH](https://wiki.archlinux.org/title/OpenSSH)

- [OpenSSH](https://www.openssh.com/)

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
```

Add the output of `ssh-add -L` to `~/.ssh/authorized_keys`

```bash
echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGXwhVokJ6cKgodYT+0+0ZrU0sBqMPPRDPJqFxqRtM+I (none)" > ~/.ssh/authorized_keys
```

After adding the `authorized_key`, adjust the permission:

```bash
chmod 600 $HOME/.ssh/authorized_keys
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

Replace this line:

```conf
tcp dport ssh accept comment "allow sshd"
```

with:

```conf
tcp dport 2222 accept comment "allow sshd on port 2222"
```

This change explicitly allows new incomming TCP connections on port 2222 for
SSH, ensuring remote access will work through the firewall.

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

- [Arch Wiki USBGuard](https://wiki.archlinux.org/title/USBGuard)

It's important to protect your USB ports to prevent BadUSB attacks, data
exfiltration, unauthorized device access, malware injection, etc.

To get a list of your connected USB devices you can use `lsusb` from the
`usbutils` package.

```bash
lsusb
```

Install usbguard:

```bash
sudo pacman -S usbguard
# Optionally; paru -S usbguard-notifier fails with bad keys
# paru -S usbguard-notifier-git
```

Create a `usbguard` group and add your user to it:

```bash
sudo groupadd usbguard
sudo usermod -aG usbguard username
```

Generate a policy based on your currently attached USB devices with:

```bash
sudo usbguard generate-policy | sudo tee /etc/usbguard/rules.conf
# Or if everything else fails
# sudo bash -c "usbguard generate-policy > /etc/usbguard/rules.conf"
```

```bash
sudo chmod 600 /etc/usbguard/rules.d/99-policy.conf
```

### USBGuard Daemon

> ❗️ If practicing zero-trust, you would want to change your default policy to
> `apply-policy`. This way any device that isn't explicitly allowed will be
> blocked. It's easy to lock yourself out if done incorrectly.

Edit `/etc/usbguard/usbguard-daemon.conf` to set the policy to allow devices
that are already connected for members of the `usbguard` group:

```conf
# ...snip...
RuleFile=/etc/usbguard/rules.conf

# Default policy for devices that were already connected when the daemon started.
# Supported values: apply-policy, allow, block, reject, keep.
PresentDevicePolicy=allow

# A list of users and groups that are allowed to interact with the daemon
# via the IPC interface.
#IPCAllowedUsers=root your-user
IPCAllowedUsers=usbguard
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

- Sometimes a reboot is required. If your keyboard doesn't work, after entering
  your encryption passphrase, enter the TTY with `Alt+Ctrl+F2` and ensure the
  `usbguard` group exists and your user is a member.

Check status:

```bash
sudo systemctl status usbguard
```

```bash
sudo usbguard list-devices
```

- If you plug something new in and it doesn't work, this is why. Remember this!

- [Authorizing (or not) USB devices](https://docs.kernel.org/usb/authorization.html)

---

### Firejail

> ❗️ Critics such as madaidan say that Firejail worsens security by acting as a
> privilege escalation hole. Firejail requires the executable to be setuid,
> meaning it runs with root privileges. Experienced users are encouraged to use
> bubblewrap for it's minimal design and specificity of its purpose.

A **setuid binary** is an executable file with a special permission bit set
called "set user ID" (setuid). When a user runs a setuid binary, the program
executes with the permissions of the binary's owner, rather than the permissions
of the user running it.

There are mitigations for the above risks I will share further down.

Another option here is [Bubblewrap](https://wiki.archlinux.org/title/Bubblewrap)

- [Arch Wiki Firejail](https://wiki.archlinux.org/title/Firejail)

- [Firejail weaknesses](https://madaidans-insecurities.github.io/linux.html#firejail)

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

fix `.desktop` files with:

```bash
firecfg --fix
```

This creates symbolic links in `/usr/local/bin/` pointing to `/usr/bin/firejail`
for programs for which Firejail has default or self-created profiles.

You can inspect `/etc/firejail/` to see all the pre-baked profiles available.

## Hardening Firejail

Add the following line to `/etc/firejail/firejail.config`:

```config
force-nonewprivs yes
```

- The above setting prevents Firejail and its child processes from gaining new
  privileges after the sandbox is started.
  - Changing the owner and group to `root:firejail` and permissions to `4750`
    means Firejail runs with setuid root but only allows execution by users in
    the firejail group reducing the attack surface.

> ❗️ This breaks some apps such as VirtualBox which I don't recommend and if
> using the hardened kernel, Wireshark and Chromium-based browsers are also
> affected.

- [Why Use KVM over VirtualBox](https://www.whonix.org/wiki/KVM#Why_Use_KVM_Over_VirtualBox?)

Add a pacman hook to automatically change firejail owner and mode. Create
`/etc/pacman.d/hooks/firejail-permissions.hook` and place the following in it:

```hook
[Trigger]
Operation = Install
Operation = Upgrade
Type = Package
Target = firejail
[Action]
Depends = coreutils
Depends = bash
When = PostTransaction
Exec = /usr/bin/sh -c "chown root:firejail /usr/bin/firejail && chmod 4750 /usr/bin/firejail"
Description = Setting /usr/bin/firejail owner to "root:firejail" and mode "4750"
```

Create a `firejail` group:

```bash
sudo groupadd firejail
```

and add your user to it:

```bash
sudo gpasswd -a $USER firejail
```

**Verify Firejail's being used**:

Launch the program that you want to ensure is running sandboxed and run:

```bash
firejail --list
# or more comprehensive
firejail --tree
```

**Enable AppArmor support**:

```bash
sudo apparmor_parser -r /etc/apparmor.d/firejail-default
```

With firejail running, I noticed that none of my browsers would allow me to
download anything. A fix for this is to run:

```bash
sudo firejail --noprofile firefox
```

Download your file, close firefox and run again in the firejail sandbox.

> Tip from Arch Wiki `/etc/pacman.d/hooks/firejail.hook`
>
> For cases where you need to manually modify the `Exec=` line of the .desktop
> file in `~/.local/share/applications` to explicitly call Firejail.
>
> ```hook
>  [Trigger]
>  Type = Path
>  Operation = Install
>  Operation = Upgrade
>  Operation = Remove
>  Target = usr/bin/*
>  Target = usr/share/applications/*.desktop
>
>  [Action]
>  Description = Configure symlinks in /usr/local/bin based on firecfg.config...
>  When = PostTransaction
>  Depends = firejail
>  Exec = /bin/sh -c 'firecfg >/dev/null 2>&1'
> ```

To manually map individual applications, execute:

```bash
sudo ln -s /usr/bin/firejail /usr/local/bin/application-to-sandbox
```

### Remove Firejail symlinks

```bash
sudo firecfg --clean
```

If you would rather confine an app with AppArmor or Bubblewrap:

```bash
sudo rm /usr/local/bin/application
```

Also, comment out `application` in the `/etc/firejail/firecfg.config` to prevent
it from being added if you run `firecfg` again.

<details>
<summary> ✔️ Click to Expand Firejail Resources </summary>

- [Arch Wiki Firejail](https://wiki.archlinux.org/title/Firejail)

- [Profiles not in firecfg](https://github.com/netblue30/firejail/issues/2507)

- [Firejail Docs](https://firejail.wordpress.com/documentation-2/)

- [Debugging Firejail](https://github.com/netblue30/firejail/wiki/Debugging-Firejail)

- [How to debug a firejail sandbox](https://debugging.works/blog/debugging-firejail/)

</details>

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

Edit `/etc/cmdline.d/security.conf`:

```conf
# enable apparmor
lsm=landlock,lockdown,yama,integrity,apparmor,bpf audit=1 audit_backlog_limit=256
```

Save & Reboot

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

Check AppArmor log messages:

Each time AppArmor denies applications from doing something potentially harmful
the event is logged.

```bash
sudo journalctl -fx
```

NOTE: Your firewall can also trigger this.

Further reading:

- [AppArmor Quick Intro](https://apparmor.net/)

- [AppArmor Wiki](https://gitlab.com/apparmor/apparmor/-/wikis/home)

- [Arch Wiki AppArmor](https://wiki.archlinux.org/title/AppArmor)

## Creating profiles that aren't pre-configured

### Auditd

Linux audit makes your system more secure by providing you the means to analyze
what's going on in your system in great detail. It does not provide any security
itself, but instead is useful for tracking these issues and helps you take
additional security measures to prevent them.

Install with:

```bash
sudo pacman -S audit
```

- Enable audit at boot-time by setting `audit=1` as a kernel parameter,
  typically either in `/etc/kernel/cmdline` or `/etc/cmdline.d/security.conf`
  for UKIs.

For example, this is my `/etc/cmdline.d/security.conf`:

```conf
# enable apparmor                               # enable audit
lsm=landlock,lockdown,yama,integrity,apparmor,bpf audit=1 audit_backlog_limit=256
```

Create a group to follow principle of least privilege:

```bash
sudo groupadd audit-view
sudo usermod -a -G audit-view $USER
```

In `/etc/audit/auditd.conf`, change `log_group = root` to:

```conf
log_group = audit-view
```

Enable:

```bash
sudo systemctl enable auditd
sudo systemctl start auditd --now
```

To create new profiles, `auditd` should be running. AppArmor can use kernel
audit logs from the userspace auditd daemon, allowing you to build new profiles.

- [Audit Framework](https://wiki.archlinux.org/title/Audit_framework)

- [Arch manpage auditd](https://man.archlinux.org/man/auditd.8.en)

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

# Make rules immutable
-e 2
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
```

View the logs:

```bash
sudo ausearch -k sudo_usage
```

View the Summary Report:

```bash
sudo aureport
sudo aureport --auth
man aureport
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

> ❗️ Removing sudo may cause compatibility issues with some scripts/tools that
> expect it, I haven't had many issues but you should test before completely
> removing it.

For a more minimalist version of `sudo` with a smaller codebase and attack
surface, consider `doas`:

```bash
sudo pacman -S opendoas
```

Create a `doas` group:

```bash
sudo groupadd doas
```

Add your user to the `doas` group:

```bash
sudo usermod -aG doas $USER
```

Create `/etc/doas.conf` with the following contents:

```conf
permit setenv {PATH=/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin} :doas
```

You can add a line below that one like `permit nopass your-username as root:`
Enabling your user passwordless usage, it's much less secure but an option.

Alternatively, you can setup the doas persist feature with the following:

```conf
permit persist setenv {PATH=/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin} :doas
```

- With the above setting, after you successfully authenticate. You won't be
  asked for your password for the next 5 minutes. It's disabled by default
  because it can be dangerous if used in the wrong environment.

- You may need to either reboot or do a soft-reset for the groups to take
  effect.

For `yay`, you can run:

```bash
yay --sudo doas --save
```

For `paru`, edit `/etc/paru.conf`. Near bottom:

```conf
Sudo = doas
```

Edit `/etc/mkepkg.conf`:

```bash
doas hx /etc/makepkg.conf
```

At the bottom of the file uncomment `PACMAN_AUTH=()` and add `doas`:

```conf
PACMAN_AUTH=(doas)
```

Secure the `doas.conf`:

```conf
doas chown -c root:root /etc/doas.conf
doas chmod -c 0400 /etc/doas.conf
```

```bash
doas pacman -Syu
```

Test and ensure most commands that you use work before removing sudo so you're
aware of potential issues. To benefit from the smaller codebase and attack
surface, you have to remove sudo.

```bash
doas pacman -R sudo base-devel
```

Create a symlink replacing sudo with doas:

```bash
ln -s $(which doas) /usr/bin/sudo
```

Now, when you run `sudo`, `doas` will be executed. There are some compatibility
issues with this method but not super common.

## Intrusion Detection

<details>
<summary> ✔️ Click to Expand AIDE Example </summary>

From what I've seen, this would work best if you're running a server or self
hosting where your system will be running without you there tweaking settings
and AIDE will alert you if anything changes in the meantime.

```bash
paru -S aide
```

- [AIDE Manual](https://aide.github.io/doc/)

- [Arch Wiki AIDE](https://wiki.archlinux.org/title/AIDE)

AIDE is an intrusion detection system (IDS) that will notify us whenever it
detects that a potential intrusion has occurred. When a system is compromised,
attackers typically will try to change file permissions and escalate to the root
user account and start to modify system files, AIDE can detect this.

To set up AIDE on your system follow these steps:

1. There is a default config at `/etc/aide.conf`:

2. Initialize the database:

```bash
sudo aide -i
```

You will see in the output of the above command that
`AIDE successfully initialized database. New AIDE database written to /var/lib/aide/aide.db.new.gz`

3. Move the new database and remove the `.new`:

```bash
sudo mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
```

4. Check the system against the baseline database:

```bash
sudo aide -C
```

5. Whenever you make changes to system files, or especially after running a
   system update or installing new tools, you have to rescan all files to update
   their checksums in the AIDE database:

```bash
sudo aide -u
```

Unfortunately, AIDE doesn't automatically replace the old database so you have
to rename the new one again:

```bash
sudo mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
```

And finally check again:

```bash
sudo aide -C
Start timestamp: 2025-10-02 14:57:49 -0400 (AIDE 0.19.2)
AIDE found NO differences between database and filesystem. Looks okay!!
```

- The default settings are fairly strict, I kept getting reports of changes
  detected because the mtime and ctime of a directory changed. It's fairly easy
  to set ignore rules by adding a `!` in front of the path.

- [aide(1) man page](https://linux.die.net/man/1/aide)

Create the logfile:

```bash
sudo mkdir -p /var/log/aide
sudo touch /var/log/aide/aide.log
```

</details>

### Resources

<details>
<summary> ✔️ Click to Expand Resources </summary>

- [Arch Wiki Secure Boot](https://wiki.archlinux.org/title/Unified_Extensible_Firmware_Interface/Secure_Boot)

- [Arch Wiki OpenVAS](https://wiki.archlinux.org/title/OpenVAS)

- [Arch Wiki AppArmor](https://wiki.archlinux.org/title/AppArmor)

- [Arch Wiki SELinux](https://wiki.archlinux.org/title/SELinux)

- [Arch Wiki Security](https://wiki.archlinux.org/title/Security)

- [archlinuxhardened/selinux](https://github.com/archlinuxhardened/selinux)

- [Gentoo Security_Handbook Concepts](https://wiki.gentoo.org/wiki/Security_Handbook/Concepts)

- STIGs are configuration standards developed by the Defense Information Systems
  Agency (DISA) to secure systems and software for the U.S. Department of
  Defense (DoD). They are considered a highly authoritative source for system
  hardening.There are recommendations for hardening all kinds of software in the
  [Stig Viewer](https://stigviewer.com/stigs)

- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks)

- [NSA Cybersecurity Directorate](https://github.com/nsacyber)

- [rodsbooks Secure Boot](https://www.rodsbooks.com/efi-bootloaders/secureboot.html)

- [TrueCrypt Guide](https://web.archive.org/web/20140422190914/https://securityinabox.org/en/truecrypt_main)

- [#! Paranoid Security Guide](https://web.archive.org/web/20140220055801/http://crunchbang.org:80/forums/viewtopic.php?id=24722)

- [Hardening-Linux-Servers](https://cybersecuritynews.com/hardening-linux-servers)

- [linux-audit Linux Server hardening best practices](https://linux-audit.com/linux-server-hardening-most-important-steps-to-secure-systems/)

- [linux-audit Linux security guide extended](https://linux-audit.com/linux-security-guide-extended-version/)

- [madaidans-insecurities](https://madaidans-insecurities.github.io/linux.html)

- [madaidans-insecurities Linux Hardening Guide](https://madaidans-insecurities.github.io/guides/linux-hardening.html)

- [Zebra Crossing digital safety checklist](https://zebracrossing.narwhalacademy.org/)

- [DataDetoxKit](https://datadetoxkit.org/en/privacy/essentials#step-1)

- [DataDetox Degooglise](https://datadetoxkit.org/en/privacy/degooglise/)

- [Tor Browser User Manual](https://tb-manual.torproject.org/)

- [Tor Wiki](https://gitlab.torproject.org/tpo/team/-/wikis/home)

</details>
