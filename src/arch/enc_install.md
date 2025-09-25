# Encrypted Arch Install w/ Encrypted Swap

<details>
<summary> ✔️ Click to Expand Table of Contents</summary>

<!-- toc -->

</details>

The ultimate installation resource is always goint to be the:

- [Arch Wiki Installation Guide](https://wiki.archlinux.org/title/Installation_guide)

- [Verify PGP Signatures](https://archlinux.org/download/#checksums), the ISO
  directory is just the same directory where your Arch Linux ISO file is stored.

> Always review the Wiki and never just plug random things suggested by me or
> anyone else without first doing your own research. If you have a ton of RAM
> and don't want hibernation capabilities, you can safely skip the swap section.
> There is no security benefit to using an encrypted swap over zram that I know
> of since zram is stored in RAM it's wiped on power loss.

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

✔️ Verifying Arch Linux ISO on Other Distributions

    ❗ NOTE: If you only want to verify the ISO once, you can temporarily import the public key, verify the signature, and then you don’t need to keep the key permanently in your keyring or sign it locally. This example is from the last release, but the process is the same.

For example, if you have a folder named archISO where you keep the ISO file
archlinux-2025-09.01-x86_64.iso, you should also download the PGP signature file
archlinux-2025.09.01-x86_64.iso.sig to the same folder.

With sequoia(a separate app), you can get the Arch release signing key with:

sq network wkd search pierre@archlinux.org --output release-key.pgp

Export the chosen key to a .pgp file:

sq cert export --keyring=release-key.pgp
--cert=3E80CA1A8B89F69CBA57D98A76A5EF9054449A5C > pierre-archlinux.pgp

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

- Now, you should see <pierre@archlinux.org> and his keys when you run gpg
  --list-keys

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
`3E80CA1A8B89F69CBA57D98A76A5EF9054449A5C` (Pierre Schmitz).

You can check the keys fingerprint with:

```bash
gpg --fingerprint 3E80CA1A8B89F69CBA57D98A76A5EF9054449A5C
```

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

---

3 **Set system clock**:

```bash
timedatectl set-ntp true
timedatectl list-timezones
# Example
sudo timedatectl set-timezone America/New_York
```

---

4. **Partition your Disk**:

Identify your target disk (e.g., `/dev/mmcblk0`):

```bash
lsblk
```

> ❗ If you already have an EFI partition you do not have to create another one
> and doing so can cause issues. First check with fdisk -l, before creating a
> new one.

```bash
fdisk -l | less
Device            Size           Type
/dev/mmcblk0p1     1G            EFI System
/dev/mmcblk0p2     57.2G         Linux root (x86-64)
```

Since I already have a 1G EFI and another root partition with the rest of the
space, I'll only need cfdisk to resize `mmcblk0p2` in order to make a swap
partition.

```bash
mkdir -p /mnt/boot
mount /dev/mmcblk0p1 /mnt/boot
```

---

5. If you have a disk with no partitions on it, you'll have to use a
   partitioning tool to create them. I'll use cfdisk as an example:

```bash
cfdisk /dev/mmcblk0
```

`Select label type -> gpt`

`Free space -> 1G` (1G boot partition)

`type -> EFI System`

Stay in cfdisk and go to `type -> Linux swap`

`Free space -> RAM+2G` (RAM+2G Swap)

Stay in cfdisk `type -> Linux filesystem`

`Free space -> The Rest` (The Rest Root partition)

`Write -> Quit`

---

6. **Format the EFI partition as FAT32**:

```bash
mkfs.fat -F32 /dev/mmcblk0p1
```

Leave the root partition unformatted for the next step.

---

7. **Encrypt the Root partition and Open it**:

```bash
cryptsetup luksFormat /dev/mmcblk0p2
cryptsetup open /dev/mmcblk0p2 cryptroot
```

Create a filesystem:

```bash
mkfs.btrfs /dev/mapper/cryptroot
mount /dev/mapper/cryptroot /mnt
```

Later, we will enable compression by mounting with options like `compress=zstd`
in `fstab`

---

8. **Encrypted Swap**

> ❗ NOTE: If you have a ton of RAM a swap is probably unnecessary unless you
> want hibernation, which requires it. Anything over 16G of RAM and it is
> questionable if you need swap at all and should probably just use zram.

Verify your swap partition created earlier, in this section we assume the swap
partition is `/dev/mmcblk0p3`:

```bash
lsblk -f
```

Encrypt the swap partiton with LUKS:

```bash
cryptsetup luksFormat /dev/mmcblk0p3
# Open the encrypted swap
cryptsetup open /dev/mmcblk0p3 cryptswap
```

Format the decrypted swap partition:

```bash
mkswap /dev/mapper/cryptswap
```

Enable the swap:

```bash
swapon /dev/mapper/cryptswap
```

Add the swap to `/mnt/etc/fstab` (this will be updated later in the `genfstab`
step, but you can manually ensure it):

```bash
echo '/dev/mapper/cryptswap none swap defaults 0 0' >> /mnt/etc/fstab
```

Add the swap partition to the LUKS configuration for automatic unlocking on
boot:

```bash
echo 'cryptswap /dev/mmcblk0p3 none luks' >> /mnt/etc/crypttab
```

> ❗ Later, after arch-chroot, ensure the mkinitcpio.conf HOOKS include resume
> (after encrypt) if you plan on using hibernation. This will be covered in the
> `initramfs` step.

---

### Automating Encrypted Swap Unlock

To avoid entering a separate password for the swap on every boot, you can create
a keyfile that will automatically unlock the swap once the root partition is
decrypted. This is a recommended practice.

1. Create a keyfile: Generate a random keyfile and save it to a secure location,
   like /etc/.

```bash
dd if=/dev/urandom of=/etc/swap.key bs=4096 count=1
chmod 600 /etc/swap.key
```

Add the keyfile to the LUKS header: Add the keyfile as a new key to the
encrypted swap partition.

```bash
cryptsetup luksAddKey /dev/mmcblk0p3 /etc/swap.key
```

Update `crypttab`: Modify the `/etc/crypttab` file to use the keyfile for
unlocking the swap partition instead of a password.

```bash
# Open /etc/crypttab in a text editor like nano or vim
# and change the line to:
cryptswap UUID=<your_swap_UUID> /etc/swap.key luks
```

Update `mkinitcpio`:

```bash
sudo mkinitcpio -P
```

Update `grub`:

```bash
grub-mkconfig -o /boot/grub/grub.cfg
```

Now, when you boot and enter the password for your root partition, the system
will gain access to the keyfile, which will automatically unlock the encrypted
swap without requiring a second password.

## Install the Base System on `/mnt` with `pacstrap`

If you prefer Nvim or a hardened kernel, change it here.

```bash
pacstrap -K /mnt base linux-zen linux-zen-headers linux-firmware networkmanager helix grub lightdm lightdm-gtk-greeter btrfs-progs cryptsetup sudo base-devel
```

```bash
# Check if EFI is mounted
mount | grep /mnt/boot
# List all mounts under /mnt
findmnt /mnt
```

The EFI and root partitions need to be mounted before you generate the
filesystem table in the next step.

---

9. **Generate the Filesystem Table**:

```bash
genfstab -U /mnt >> /mnt/etc/fstab
#
cat /mnt/etc/fstab
# Add compression
vim /mnt/etc/fstab
```

**Important**: The `fstab` should list all 3 partitions, if it doesn't you'll
need to regenerate your fstab again with `genfstab`.

---

10. Add compression, **Only for the Root Partition**:

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

11. **Change Root (`chroot`) into the New Installation**

```bash
arch-chroot /mnt
```

Create a user:

```bash
useradd -m -G wheel -s /bin/bash yourusername
passwd yourusername
```

Enable sudo for wheel group:

```
EDITOR=vim visudo
```

If that doesn't work, use `vim /etc/sudoers` and edit the file accordingly.

Uncomment the line:

```bash
%wheel ALL=(ALL:All) ALL
```

---

12. Edit `/etc/mkinitcpio.conf` in the new system to add an `encrypt` hook
    before the `filesystems` attribute.

- Locate the `HOOKS` line

- Insert `encrypt` **before** filesystems

```bash
vim /etc/mkinitcpio.conf
```

> ❗ NOTE how I also added the `resume` after `encrypt`, that's required for the
> encrypted swap setup.

```bash
# mkinitcpio.conf
# ... snip ...
HOOKS=(base udev autodetect microcode modconf kms keyboard keymap consolfont block encrypt resume filesystems fsck)
# ... snip ...
```

---

14. **Install Grub and EFI boot manager**, (while still in chroot environment):

```bash
pacman -S grub efibootmgr
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
GRUB_CMDLINE_LINUX="cryptdevice=/dev/mmcblk0p2:cryptroot root=/dev/mapper/cryptroot"
# ...snip...
```

Generate GRUB configuration:

```bash
grub-mkconfig -o /boot/grub/grub.cfg
# Should output
Adding boot menu entry for UEFI Firmware Settings ...
done
```

---

15. **Enable LightDM and NetworkManager**

```bash
systemctl enable lightdm
systemctl enable NetworkManager
```

> NOTE: While following these exact steps on a different machine, the above
> commands refused to run. The solution was to exit the chroot environment and
> run the following:
>
> ```bash
> systemctl --root=/mnt enable lightdm
> systemctl --root=/mnt enable NetworkManager
> ```

Configure LightDM greeter, edit `/et/lightdm/lightdm.conf` to add:

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

16 **Reboot**

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
cryptsetup open /dev/mmcblk0p2 cryptroot
```

Mount the decrypted root:

```bash
mount /dev/mapper/cryptroot /mnt
```

Mount the EFI partition:

```bash
mount /dev/mmcblk0p1 /mnt/boot
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
umount /mnt/boot umount /mnt cryptsetup close cryptroot reboot
```

### Resources

- [Arch Wiki Installation Guide](https://wiki.archlinux.org/title/Installation_guide)
