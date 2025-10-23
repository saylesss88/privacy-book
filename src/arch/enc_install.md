# Encrypted Arch Install for UEFI Systems with UKI and Secure Boot

<details>
<summary> ✔️ Click to Expand Table of Contents</summary>

<!-- toc -->

</details>

The ultimate installation resource is always goint to be the:

- [Arch Wiki Installation Guide](https://wiki.archlinux.org/title/Installation_guide)

- [Verify PGP Signatures](https://archlinux.org/download/#checksums), the ISO
  directory is just the same directory where your Arch Linux ISO file is stored.

> Always review the Wiki and never just plug random things suggested by me or
> anyone else without first doing your own research.

Edited: 09-25-25 Removed encrypted swap section. Big usability downside IMO.

<details>
<summary> ✔️ Verifying Arch Linux ISO on Other Distributions </summary>

> ❗ NOTE: If you only want to verify the ISO once, you can temporarily import
> the public key, verify the signature, and then you don’t need to keep the key
> permanently in your keyring or sign it locally. This example is from the last
> release, but the process is the same.

With `sequoia-sq`, you can get the Arch release signing key with:

```bash
sq network wkd search pierre@archlinux.org --output release-key.pgp
```

Export the chosen key to a `.pgp` file:

```bash
sq cert export --keyring=release-key.pgp --cert=3E80CA1A8B89F69CBA57D98A76A5EF9054449A5C > pierre-archlinux.pgp
```

Import into your keychain:

```bash
gpg --import pierre-archlinux.pgp
gpg: key 0x76A5EF9054449A5C: 9 signatures not checked due to missing keys
gpg: key 0x76A5EF9054449A5C: public key "Pierre Schmitz <pierre@archlinux.org>" imported
gpg: Total number processed: 1
gpg:               imported: 1
gpg: marginals needed: 3  completes needed: 1  trust model: pgp
gpg: depth: 0  valid:   3  signed:   0  trust: 0-, 0q, 0n, 0m, 0f, 3u
gpg: next trustdb check due at 2026-08-23
```

- Now, you should see `<pierre@archlinux.org>` and his keys when you run
  `gpg --list-keys`

Finally, verify the signature:

```bash
sq verify --signer-file release-key.pgp --signature-file archlinux-2025.08.01-x86_64.iso.sig archlinux-2025.08.01-x86_64.iso
Authenticated signature made by 3E80CA1A8B89F69CBA57D98A76A5EF9054449A5C (Pierre Schmitz <pierre@archlinux.org>)

1 authenticated signature.
```

> ❗ To ensure the key is authentic and not spoofed, verify that the key
> fingerprint matches the official Arch Linux signing key fingerprint, which can
> is linked below and on the Arch website.

This shows that the signature was made by the key with the ID
`3E80CA1A8B89F69CBA57D98A76A5EF9054449A5C (Pierre Schmitz)`

You can check the keys fingerprint with:

```bash
gpg --fingerprint 3E80CA1A8B89F69CBA57D98A76A5EF9054449A5C
```

- Verify it against the
  [Arch Linux master-keys](https://archlinux.org/master-keys/)

Verify it against the Arch Linux master-keys

With the `sq verify` command GPG authenticated that the signature is valid and
that the key used to sign is trusted in our keyring.

`1 authenticated signature` confirms the files integrity and authenticity.

We have successfully verified that the file was signed by Pierr's official Arch
Linux key and has not been tampered with.

The following is only if you currently already have keys on your gpg keyring.

<details>

<summary> ☑️ Click to expand Key Signing and Publishing Example </summary>

List your keys to get the arch keyID:

```bash
gpg --list-keys
# ... snip ...
pub   ed25519/0x76A5EF9054449A5C 2022-10-31 [SC] [expires: 2037-10-27]
      Key fingerprint = 3E80 CA1A 8B89 F69C BA57  D98A 76A5 EF90 5444 9A5C
uid                   [  full  ] Pierre Schmitz <pierre@archlinux.org>
uid                   [  full  ] Pierre Schmitz <pierre@archlinux.de>
sub   ed25519/0xD6D13C45BFCFBAFD 2022-10-31 [A] [expires: 2037-10-27]
sub   cv25519/0x7F56ADE50CA3D899 2022-10-31 [E] [expires: 2037-10-27]
```

Sign the key:

```bash
gpg --sign-key 0x76A5EF9054449A5C
```

Now you can export and publish the new public key and send it to a keyserver:

```bash
gpg --export --armor 0x76A5EF9054449A5C > archlinux-signed.asc
gpg --send-keys 0x76A5EF9054449A5C
```

The more people that verify, sign, and re-export and publish their keys the
better for the web of trust that gpg uses making the network more secure for
everyone.

</details>
</details>

---

1. **Connect to Wi-Fi**:

```bash
iwctl
[iwd]# device list
[iwd]# station wlan0 scan
[iwd]# station wlan0 connect NETGEAR80
# Enter your Password
# Check Connection
[iwd]# station wlan0 show
[iwd]# exit
```

```bash
ping -c 3 archlinux.org
```

---

2. **Update package databases and mirrorlist**:

```bash
pacman -Syyu
```

Save a backup of your current mirrorlist so we can safely update it:

```bash
cp /etc/pacman.d/mirrorlist /etc/pacman.d/mirrorlist.bak
```

```bash
pacman -S reflector
reflector --list-countries
# Example if you live in the US
reflector -c US --protocol https --age 6 --fastest 5 --sort rate --save /etc/pacman.d/mirrorlist
```

This actually improves security by only providing `HTTPS` mirrors, by default
both HTTP and HTTPS are used.

NOTE: This can take a bit and you can expect some failures..

---

3. **Set keyboard layout, font, and system clock**:

Default keymap is US, if you need something different:

```bash
localectl list-keymaps
loadkeys <chosen-map>
# Increase font size
setfont ter-132b
```

```bash
sudo pacman -S chrony
```

`/etc/chrony.conf`:

```conf
# Copyright © 2014-2025 GrapheneOS

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

server time.cloudflare.com iburst nts
server ntppool1.time.nl iburst nts
server nts.netnod.se iburst nts
server ptbtime1.ptb.de iburst nts
server time.dfm.dk iburst nts
server time.cifelli.xyz iburst nts

minsources 3
authselectmode require

# EF
dscp 46

driftfile /var/lib/chrony/drift
dumpdir /var/lib/chrony
ntsdumpdir /var/lib/chrony

leapseclist /usr/share/zoneinfo/leap-seconds.list
makestep 1.0 3

rtconutc
rtcsync

cmdport 0

noclientlog
```

The above setup uses Network Time Security (NTS) and is a more modern safer way
to synchronize time using chrony.

```bash
sudo systemctl disable --now systemd-timesyncd
sudo systemctl enable --now chronyd
```

```bash
timedatectl set-ntp true
timedatectl list-timezones
# Example
sudo timedatectl set-timezone America/New_York
```

---

4. **Partition your Disk**:

The only required partitions are one for the root directory `/` (typically `1G`)
and one for booting in UEFI mode, an EFI system partition (typically the rest of
the space left).

In this section, I'll assume that you're starting with a clean slate. If you're
not, you can use your existing partitions if they meet the above requirements or
delete them.

To delete existing partitions with `cfdisk`, you launch it on the target
filesystem, select the partition you want to delete and Select -> `[ Delete ]`
until all you see is `Free space` and a clean slate and `[ Write ]` & `[ Quit ]`
to save your changes.

Identify your target disk (e.g., `/dev/nvme0n1`):

```bash
fdisk -l
```

```bash
cfdisk /dev/nvme0n1
```

- Select -> `[ Free Space ]`
  - Select -> `[ New ]`

  - Partition size: `1G`

  - Type -> `EFI System`

- Select -> `[ Free Space ]`
  - Partition size: The rest of the space

  - Type -> `Linux filesystem`

  - Select -> `[ Write ]`

  - Select -> `[ Quit ]`

---

5. **Format the EFI partition as FAT32**:

```bash
mkfs.fat -F32 /dev/nvme0n1p1
```

Leave the root partition unformatted for the next step.

---

6. **Encrypt the Root partition and Open it**:

```bash
cryptsetup luksFormat /dev/nvme0n1p2
cryptsetup open /dev/nvme0n1p2 cryptroot
```

Create a filesystem:

```bash
mkfs.btrfs /dev/mapper/cryptroot
```

If you mount the filesystem with compression before running `genfstab`, it will
automatically add the chosen compression to the `fstab`.

```bash
mount /dev/nvme0n1p1 /mnt/boot  # Mount EFI partition at /mnt/boot
mount -o compress=zstd /dev/mapper/cryptroot /mnt
```

---

## Install the Base System on `/mnt` with `pacstrap`

If you prefer Nvim or a hardened kernel, change it here.

```bash
pacstrap -K /mnt base linux-zen linux-zen-headers linux-firmware networkmanager helix lightdm lightdm-gtk-greeter btrfs-progs cryptsetup sudo base-devel efibootmgr systemd-ukify
```

---

7. **Generate the Filesystem Table**:

The EFI and root partitions need to be mounted before you generate the
filesystem table in the next step.

```bash
genfstab -U /mnt >> /mnt/etc/fstab
#
hx /mnt/etc/fstab
cat /mnt/etc/fstab
```

Fix security hole and harden `/boot` permissions by adding
`fmask=0137, dmask=0027`:

```bash
hx /mnt/etc/fstab
```

Example

```fstab
# Static information about the filesystems.
# See fstab(5) for details.

# <file system> <dir> <type> <options> <dump> <pass>
# /dev/mapper/cryptroot
UUID=6d68a2bf-34ea-4adc-86d5-cb1d56de44a4	/         	btrfs     	rw,relatime,compress=zstd:3,ssd,space_cache=v2,subvol=/	0 0

# /dev/nvme0n1p1
UUID=B88B-844F      	/boot     	vfat      	rw,relatime,fmask=0137,dmask=0027,codepage=437,iocharset=ascii,shortname=mixed,utf8,errors=remount-ro	0 2
```

```bash
chmod 700 /boot
chmod 600 /boot/loader/random-seed
```

**Important**: The `fstab` should list both partitions, if it doesn't you'll
need to ensure both partitions are mounted and regenerate your fstab again with
`genfstab`. Also ensure that the root partition was mounted with compression.

---

8. **Change Root (`chroot`) into the New Installation**

```bash
arch-chroot /mnt
```

Create a user:

```bash
useradd -m -G wheel -s /bin/bash yourusername
passwd yourusername
```

Create an admin password:

```bash
passwd
```

Enable sudo for wheel group:

In `/etc/sudoers` uncomment the line:

```bash
%wheel ALL=(ALL:All) ALL
```

---

9. Edit `/etc/mkinitcpio.conf` in the new system to add an `sd-encrypt` hook
   before the `filesystems` attribute.

- Locate the `HOOKS` line

- Insert `encrypt` **before** filesystems

```bash
vim /etc/mkinitcpio.conf
```

To use `sd-encrypt`, it is necessary to replace `udev` with `systemd` and if you
require a different keyboard layout from US `sd-vconsole` is needed.

```bash
# mkinitcpio.conf
# *IF* you use an nvme drive
MODULES=(nvme)
FILES=(/etc/crypttab.initramfs /etc/vconsole.conf)
# ... snip ...
HOOKS=(base systemd autodetect microcode modconf kms keyboard keymap consolefont sd-vconsole block sd-encrypt filesystems fsck systemd-ukify)
# ... snip ...
```

Create `/etc/crypttab.initramfs`:

```initramfs
cryptroot UUID=your-uuid none luks,discard
```

---

Create `/etc/vconsole.conf`:

For example `KEYMAP=fr` is french

```conf
KEYMAP=us
FONT=lat9w-16
```

---

Edit `/etc/mkinitcpio.d/linux-zen.preset`, this enables `mkinitcpio -P` to
generate a UKI in `/boot/EFI/Linux/`:

```preset
# mkinitcpio preset file for the 'linux-zen' package

ALL_config="/etc/mkinitcpio.conf"
ALL_kver="/boot/vmlinuz-linux-zen"

PRESETS=('default' 'fallback')
# PRESETS=('default')

# default_config="/etc/mkinitcpio.conf"
# default_image="/boot/initramfs-linux-zen.img"
default_uki="/boot/EFI/Linux/arch-linux-zen.efi"
default_options="--splash /usr/share/systemd/bootctl/splash-arch.bmp"

#fallback_config="/etc/mkinitcpio.conf"
#fallback_image="/boot/initramfs-linux-zen-fallback.img"
fallback_uki="/boot/EFI/Linux/arch-linux-zen-fallback.efi"
fallback_options="-S autodetect"
```

Generate the initial RAM Filesystem (initramfs) image.

```bash
mkinitcpio -P
```

> ❗️ TIP: If `mkinitcpio -P` fails, exit `arch-chroot` and ensure both the boot
> & root partitions are mounted. `arch-chroot` back into `/mnt` and try again.
> Ensure that `/boot/EFI/Linux/arch-linux-zen.efi` and
> `/boot/EFI/Linux/arch-linux-zen-fallback.efi` exist for your kernel of choice.

---

10. **Install systemd-boot and setup Unified Kernel Image**, (while still in
    chroot environment):

Ensure your UEFI variables are accessible:

```bash
efivar --list
```

This command won't work if both partitions aren't mounted, ensure they are both
mounted and if it still doesn't work you can use `--esp-path=/boot` or
`--esp-path=/mnt/boot`.

```bash
bootctl install
```

Edit `/etc/kernel/cmdline` and add the output of `blkid` on your root partition.
For example:

```bash
blkid /dev/nvme0n1p2 > /tmp/uuid.txt
```

When you open `/etc/kernel/cmdline` in vim or helix, run `:r /tmp/uuid.txt` to
read the UUID of your root partition into the file. You only need the numbers
like so:

```cmdline
rd.luks.name=7b78e942-f4f7-4dde-a015-3a816305483f=cryptroot root=/dev/mapper/cryptroot rw
```

In the above example, `7b78e942-f4f7-4dde-a015-3a816305483f` is the UUID
extracted from the `blkid` command.

Create a `/boot/loader/entries/arch.conf` with the following:

```conf
title Arch Linux
linux /vmlinuz-linux-zen
initrd /initramfs-linux-zen.img
options rd.luks.name=7b78e942-f4f7-4dde-a015-3a816305483f=cryptroot root=/dev/mapper/cryptroot rw quiet
```

> ❗️ NOTE: The `arch.conf` here is redundant because `systemd-boot` is
> configured to autodetect the UKI. It doesn't hurt to add it though and can
> prevent issues in the future. Ensure `rd.luks.name=` contains the UUID from
> the encrypted root partition. (e.g., `blkid /dev/nvme0n1p2`).

And finally, a `/boot/loader/loader.conf`:

```conf
default arch.conf
# default @saved  # return to last choice
timeout 4
console-mode auto
auto-entries 1
```

```bash
bootctl status
```

Set a password to protect `systemd-boot` with `systemd-boot-password`:

```bash
paru -S systemd-boot-password
```

```bash
sudo sbpctl install /boot
```

You will now be prompted for your password before you can edit kernel
parameters.

---

**systemd-ukify and the Unified Kernel Image**:

We already added `systemd-ukify` in the pacstrap command, let's add a few more
tools for this process:

```bash
sudo pacman -S sbsigntools efitools
```

Copy the existing template to `/etc/kernel/uki.conf`:

```bash
cp /usr/lib/kernel/uki.conf /etc/kernel/uki.conf
```

Edit `/etc/kernel/uki.conf`:

```conf
[UKI]
#Initrd=
#Microcode=
#Splash=
#PCRPKey=
#PCRBanks=
#SecureBootSigningTool=
SecureBootPrivateKey=/etc/kernel/secure-boot-private-key.pem
SecureBootCertificate=/etc/kernel/secure-boot-certificate.pem
#SecureBootCertificateDir=
#SecureBootCertificateName=
#SecureBootCertificateValidity=
#SigningEngine=
SignKernel=yes
```

Generate your signing keys:

```bash
ukify genkey --config /etc/kernel/uki.conf
```

The above command creates `/etc/kernel/secure-boot-certificate.pem` and
`/etc/kernel/secure-boot-private-key.pem`.

Building the UKIs:

```bash
mkdir -p /boot/EFI/Linux
mkinitcpio -P
# Output
Wrote signed /boot/EFI/Linux/arch-linux-zen.efi
==> Unified kernel image generation successful
```

Sign the boot loader with the new keys:

```bash
/usr/lib/systemd/systemd-sbsign sign \
--private-key /etc/kernel/secure-boot-private-key.pem \
--certificate /etc/kernel/secure-boot-certificate.pem \
--output /usr/lib/systemd/boot/efi/systemd-bootx64.efi.signed \
/usr/lib/systemd/boot/efi/systemd-bootx64.efi
```

Output:

```text
Wrote signed PE binary to /usr/lib/systemd/boot/efi/systemd-bootx64.efi.signed
```

```bash
sudo bootctl install --secure-boot-auto-enroll yes \
--certificate /etc/kernel/secure-boot-certificate.pem \
--private-key /etc/kernel/secure-boot-private-key.pem
```

Output:

```text
Copied "/usr/lib/systemd/boot/efi/systemd-bootx64.efi.signed" to "/boot/EFI/systemd/systemd-bootx64.efi".
    3 Copied "/usr/lib/systemd/boot/efi/systemd-bootx64.efi.signed" to "/boot/EFI/BOOT/BOOTX64.EFI".
    4 ⚠️  Mount point '/boot' which backs the random seed file is world accessible, which is a security hole!  ⚠️
    5 ⚠️ Random seed file '/boot/loader/random-seed' is world accessible, which is a security hole! ⚠️
    6 Random seed file /boot/loader/random-seed successfully refreshed (32 bytes).
    7 Secure boot auto-enrollment file /boot/loader/keys/auto/PK.auth successfully written.
    8 Secure boot auto-enrollment file /boot/loader/keys/auto/KEK.auth successfully written.
    9 Secure boot auto-enrollment file /boot/loader/keys/auto/db.auth successfully written.
   10 Created EFI boot entry "Linux Boot Manager".
```

Fix the security hole:

```bash
chmod 700 /boot
```

Add the following to your `/boot/loader/loader.conf`:

```conf
secure-boot-enroll force
```

Reboot into setup-mode and it will start an automatic countdown where it enrolls
your keys when the time runs out.

After successful key enrollment, reboot into UEFI again, enable Secure Boot and
reboot.

When the desktop launches, check the output of `bootctl status` to ensure
`Secure Boot: enabled (user)`

If your system doesn't accept them, you may have to do some conversions. You can
also add the keys manually which is what I did.

<details>
<summary> ✔️ Click to Expand conversion Examples </summary>

```bash
# Create workspace for certs and outputs
mkdir -p ~/secureboot/output

# Define certificate location
CERT_PEM="/etc/kernel/secure-boot-certificate.pem"

# Convert PEM cert to DER format for UEFI enrollment
sudo openssl x509 -in $CERT_PEM -out ~/secureboot/output/db.cer -outform DER

# Convert PEM cert to EFI Signature List
cert-to-efi-sig-list $CERT_PEM ~/secureboot/output/db.esl

# Sign the Signature List (run from wherever your private key is; do not copy it)
sudo sign-efi-sig-list -k /etc/kernel/secure-boot-private-key.pem -c $CERT_PEM db \
    ~/secureboot/output/db.esl ~/secureboot/output/db.auth
```

Manual Key Enrollment:

- `db.cer` -> enroll in db (Trusted Signatures), Choose the desired drive, find
  the file and add it. Save as an `Authorized Signature` instead of `Public Key`

- `PK.cer` -> enroll in `Platform Key`(PK)

- Keep your `secure-boot-private-key.pem` **private**, with the above commands
  we only use it when signing, and otherwise keep it protected.

</details>

---

11. **Enable LightDM and NetworkManager**

```bash
systemctl enable lightdm
systemctl enable NetworkManager
```

> ❗️ NOTE: If you're ever unable to run the above commands in the chroot
> environment, exit chroot and run:
>
> ```bash
> systemctl --root=/mnt enable lightdm
> systemctl --root=/mnt enable NetworkManager
> ```

Configure LightDM greeter, edit `/etc/lightdm/lightdm.conf` to add:

```conf
# lightdm.conf
[Seat:*]
greeter-session=lightdm-gtk-greeter
```

Exit `arch-chroot` with `exit`

Unmount your partitions and reboot:

```bash
umount /mnt/boot
umount /mnt
cryptsetup close cryptroot
```

---

12. **Reboot**

```bash
bootctl status
System:
      Firmware: UEFI 2.70 (American Megatrends)
 Firmware Arch: x64
   Secure Boot: enabled (user)
  TPM2 Support: yes
  Measured UKI: yes
  Boot into FW: supported
```

---

### Creating a readonly snapshot of your root subvolume:

- [Arch Wiki System Backup](https://wiki.archlinux.org/title/System_backup)

<details>
<summary> ✔️ Click to Expand snapshot & Backup Example </summary>

1. Create readonly snapshot of root subvol:

```bash
sudo btrfs subvolume snapshot -r / /root-snapshot-$(date +%Y%m%d%H%M%S)
```

2. Mount your external backup disk:

```bash
sudo mkdir -p /mnt/backup
sudo mount /dev/sdc1 /mnt/backup
```

3. Use rsync to copy the snapshot to the external drive:

List the available snapshots and get the exact name:

```bash
sudo btrfs subvolume list /
```

```bash
sudo rsync -aAXv --delete --progress /root-snapshot-20251002135000/ /mnt/backup/root-backup/
```

4. Unmount the external drive:

```bash
sudo umount /mnt/backup
```

5. Optionally, delete older snapshots to save space:

```bash
sudo btrfs subvolume delete /root-snapshot-OLD_TIMESTAMP
```

### Restoring from a Backup

For this, you mount the partitions but don't need to `arch-chroot` in.

1. Boot from a live USB

2. Mount your encrypted root partition (unlock if encrypted) and the external
   backup drive.

3. Move or delete the corrupted data on the root partition.

4. Use rsync to copy the backed-up snapshot from the external disk back to the
   root partition, preserving permissions and attributes.

```bash
sudo rsync -aAXv --delete /mnt/backup/root-backup/ /
```

Or, the Wiki's suggestion, (Much more efficient, Direct backup of a running
system without the need for btrfs snapshots):

```bash
sudo rsync -aAXHv --exclude='/dev/*' --exclude='/proc/*' --exclude='/sys/*' --exclude='/tmp/*' --exclude='/run/*' --exclude='/mnt/*' --exclude='/media/*' --exclude='/lost+found/' / /path/to/backup
```

- `/mnt/backup/root-backup/` is the path where the backup snapshot is mounted on
  the external disk.

- `/` is the root partition mount point where you want to restore the files.

- The options:
  - `-a` archive mode to preserve symbolic links, permissions, timestamps, etc.

  - `-A` preserve ACLs (access control lists).

  - `-X` preserve extended attributes.

  - `-v` verbose output.

  - `--delete` deletes files on the destination that don't exist in the source,
    keeping an exact mirror.

If you want to restore a specific snapshot directory (e.g.,
`/root-snapshot-20251002135000`), replace the source path accordingly, like:

```bash
sudo rsync -aAXv --delete /mnt/backup/root-snapshot-20251002135000/ /
```

- [Arch Wiki rsync](https://wiki.archlinux.org/title/Rsync#As_a_backup_utility)

5. Reinstall the bootloader if necessary.

6. Unmount everything and reboot.

### Automated backup

Create `/etc/cron.daily/backup`:

```backup
#!/bin/sh
rsync -a --delete --quiet /path/to/backup /location/of/backup
```

Change `/path/to/backup` to what needs to be backed-up such as `/home` or `/`

</details>

---

### arch-chroot

<details>
<summary>  ✔️ Click to Expand `arch-chroot` Example </summary>

Say you forgot something, like forgetting to add a user and password. You reboot
and go to TTY into your system and are hit with a AHHH I can't log in WTF!

It's as easy as repeating some of the steps above. Reboot into the Live
environment, remount your partitions and `arch-chroot` back in:

Open the encrypted root partition:

```bash
cryptsetup open /dev/nvme0n1p2 cryptroot
```

Mount the decrypted root:

```bash
mount /dev/mapper/cryptroot /mnt
```

Mount the EFI partition:

```bash
mount /dev/nvme0n1p1 /mnt/boot
```

Chroot into your installed system:

```bash
arch-chroot /mnt
```

```bash
useradd -m -G wheel -s /bin/bash yourusername passwd yourusername
```

- The `-s /bin/bash` sets your default shell, you can use zsh if you have it
  installed.

Uncomment the line `%wheel ALL=(ALL:All) ALL` in `/etc/sudoers`

Exit chroot:

```bash
exit
```

Unmount and close LUKS:

```bash
umount /mnt/boot
umount /mnt
cryptsetup close cryptroot
reboot
```

### Resources

- [Arch Wiki Installation Guide](https://wiki.archlinux.org/title/Installation_guide)

- [Arch Wiki UKI/SecureBoot](https://wiki.archlinux.org/title/Unified_Extensible_Firmware_Interface/Secure_Boot)

- [Wiki UKI](https://wiki.archlinux.org/title/Unified_kernel_image)

- [Wiki systemd-boot](https://wiki.archlinux.org/title/Systemd-boot)
