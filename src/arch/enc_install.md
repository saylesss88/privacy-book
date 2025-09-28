# Encrypted Arch Install for UEFI Systems

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

With `sequoia`, you can get the Arch release signing key with:

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
pacman -Sy
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

NOTE: This can take a bit and you can expect some failures..

---

3 **Set keyboard layout, font, and system clock**:

Default keymap is US, if you need something different:

```bash
localectl list-keymaps
loadkeys <chosen-map>
# Encrease font size
setfont ter-132b
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
mount /dev/mapper/cryptroot /mnt
```

Later, we will enable compression by mounting with options like `compress=zstd`
in `fstab`

---

## Install the Base System on `/mnt` with `pacstrap`

If you prefer Nvim or a hardened kernel, change it here.

```bash
pacstrap -K /mnt base linux-zen linux-zen-headers linux-firmware networkmanager helix grub lightdm lightdm-gtk-greeter btrfs-progs cryptsetup sudo base-devel efibootmgr
```

---

7. **Generate the Filesystem Table**:

The EFI and root partitions need to be mounted before you generate the
filesystem table in the next step.

```bash
genfstab -U /mnt >> /mnt/etc/fstab
#
cat /mnt/etc/fstab
# Add compression
vim /mnt/etc/fstab
```

**Important**: The `fstab` should list both partitions, if it doesn't you'll
need to regenerate your fstab again with `genfstab`.

---

8. Add compression, **Only for the Root Partition**:

```bash
# fstab
/dev/mapper/cryptroot    /    btrfs    rw,relatime,compress=zstd,ssd, #...snip
#...snip...
```

Remount root with compression:

```bash
mount -o remount,compress=zstd /mnt
```

---

9. **Change Root (`chroot`) into the New Installation**

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

10. Edit `/etc/mkinitcpio.conf` in the new system to add an `encrypt` hook
    before the `filesystems` attribute.

- Locate the `HOOKS` line

- Insert `encrypt` **before** filesystems

```bash
vim /etc/mkinitcpio.conf
```

```bash
# mkinitcpio.conf
# ... snip ...
HOOKS=(base udev autodetect microcode modconf kms keyboard keymap consolfont block encrypt filesystems fsck)
# ... snip ...
```

Generate the initial RAM Filesystem (initramfs) image.

```bash
mkinitcpio -P
```

---

11. **Install Grub and EFI boot manager**, (while still in chroot environment):

```bash
# These should be installed in the chroot environment already
pacman -Q grub efibootmgr
```

Install GRUB for UEFI Systems:

```bash
grub-install --target=x86_64-efi --efi-directory=/boot --bootloader-id=GRUB
# Should output
Installation finished. No error reported.
```

Configure GRUB to unlock LUKS root partition

Edit `/etc/default/grub` and modify line starting with `GRUB_CMDLINE_LINUX` to
add:

```bash
# ...snip...
GRUB_CMDLINE_LINUX="cryptdevice=/dev/nvme0n1p2:cryptroot root=/dev/mapper/cryptroot"
# ...snip...
```

Generate GRUB configuration:

```bash
grub-mkconfig -o /boot/grub/grub.cfg
# Should output
Adding boot menu entry for UEFI Firmware Settings ...
done
```

To be safe re-generate the `initramfs`:

```bash
mkinitcpio -P
```

---

12. **Enable LightDM and NetworkManager**

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

13 **Reboot**

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
