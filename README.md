This repo is for review of requests for signing shim.  To create a request for review:

- clone this repo
- edit the template below
- add the shim.efi to be signed
- add build logs
- add any additional binaries/certificates/SHA256 hashes that may be needed
- commit all of that
- tag it with a tag of the form "myorg-shim-arch-YYYYMMDD"
- push that to github
- file an issue at https://github.com/rhboot/shim-review/issues with a link to your tag
- approval is ready when the "accepted" label is added to your issue

Note that we really only have experience with using GRUB2 on Linux, so asking
us to endorse anything else for signing is going to require some convincing on
your part.

Here's the template:

*******************************************************************************
### What organization or people are asking to have this signed?
*******************************************************************************
Proxmox Server Solutions GmbH is an Austrian company developing a suite of
Debian-derived Linux distributions.

*******************************************************************************
### What product or service is this for?
*******************************************************************************
Currently there are three products sharing a common base:
- Proxmox Virtual Environment (Hypervisor)
- Proxmox Mail Gateway
- Proxmox Backup Server

For our upcoming releases based on Debian Bookworm we'd like to enable Secure
Boot support.

*******************************************************************************
### What's the justification that this really does need to be signed for the whole world to be able to boot it?
*******************************************************************************
Proxmox only provides the software (+ optional enterprise support for it), we
don't have control over our users' systems as we don't provide any Software- or
Infrastructure-as-a-Service, nor the hardware our software runs on.

*******************************************************************************
### Why are you unable to reuse shim from another distro that is already signed?
*******************************************************************************
Proxmox products use a custom kernel built by us to provide a stable experience
for our (enterprise) users. Currently, it's based on the Ubuntu kernel series.

*******************************************************************************
### Who is the primary contact for security updates, etc.?
The security contacts need to be verified before the shim can be accepted. For subsequent requests, contact verification is only necessary if the security contacts or their PGP keys have changed since the last successful verification.

An authorized reviewer will initiate contact verification by sending each security contact a PGP-encrypted email containing random words.
You will be asked to post the contents of these mails in your `shim-review` issue to prove ownership of the email addresses and PGP keys.
*******************************************************************************
- Name: Fabian Grünbichler
- Position: Software Developer
- Email address: f.gruenbichler@proxmox.com
- PGP key fingerprint: 0x8064F5EC6714CB81B980F7743721E2DA4C8DDEEB

If needed, I can cross-sign this (work) key with my (private) key that is part
of the Debian DM keyring.

*******************************************************************************
### Who is the secondary contact for security updates, etc.?
*******************************************************************************
- Name: Proxmox Security Team
- Position: https://pve.proxmox.com/wiki/Security_Reporting
- Email address: security@proxmox.com
- PGP key fingerprint: 0xE6792AA698E11855375AB9E35D0CBD4361F204C5

*******************************************************************************
### Were these binaries created from the 15.7 shim release tar?
Please create your shim binaries starting with the 15.7 shim release tar file: https://github.com/rhboot/shim/releases/download/15.7/shim-15.7.tar.bz2

This matches https://github.com/rhboot/shim/releases/tag/15.7 and contains the appropriate gnu-efi source.

*******************************************************************************
Yes, see Dockerfile for confirmation.

*******************************************************************************
### URL for a repo that contains the exact code which was built to get this binary:
*******************************************************************************
https://git.proxmox.com/?p=efi-boot-shim.git;a=shortlog;h=refs/tags/proxmox/15.7-1%2Bpmx1

*******************************************************************************
### What patches are being applied and why:
*******************************************************************************
Currently two patches are included:
- enabling NX
- workaround for buggy gcc/binutils

both patches are taken verbatim from Debian's shim 15.7 build, but originally
from shim upstream.

*******************************************************************************
### If shim is loading GRUB2 bootloader what exact implementation of Secureboot in GRUB2 do you have? (Either Upstream GRUB2 shim_lock verifier or Downstream RHEL/Fedora/Debian/Canonical-like implementation)
*******************************************************************************
We re-use Debian's implementation (rebuilding Grub with SBAT adapted to
differentiate the two variants).

*******************************************************************************
### If shim is loading GRUB2 bootloader and your previously released shim booted a version of grub affected by any of the CVEs in the July 2020 grub2 CVE list, the March 2021 grub2 CVE list, the June 7th 2022 grub2 CVE list, or the November 15th 2022 list, have fixes for all these CVEs been applied?

* CVE-2020-14372
* CVE-2020-25632
* CVE-2020-25647
* CVE-2020-27749
* CVE-2020-27779
* CVE-2021-20225
* CVE-2021-20233
* CVE-2020-10713
* CVE-2020-14308
* CVE-2020-14309
* CVE-2020-14310
* CVE-2020-14311
* CVE-2020-15705
* CVE-2021-3418 (if you are shipping the shim_lock module)

* CVE-2021-3695
* CVE-2021-3696
* CVE-2021-3697
* CVE-2022-28733
* CVE-2022-28734
* CVE-2022-28735
* CVE-2022-28736
* CVE-2022-28737

* CVE-2022-2601
* CVE-2022-3775
*******************************************************************************
This is our first shim-review, so no previously released shim. Our Grub
packages contain fixes for all of these though, except for CVE-2020-15705 and
CVE-2021-3418, same as Debian's.

*******************************************************************************
### If these fixes have been applied, have you set the global SBAT generation on your GRUB binary to 3?
*******************************************************************************
Yes.

*******************************************************************************
### Were old shims hashes provided to Microsoft for verification and to be added to future DBX updates?
### Does your new chain of trust disallow booting old GRUB2 builds affected by the CVEs?
*******************************************************************************
No, as not applicable (first shim review), and yes.

*******************************************************************************
### If your boot chain of trust includes a Linux kernel:
### Is upstream commit [1957a85b0032a81e6482ca4aab883643b8dae06e "efi: Restrict efivar_ssdt_load when the kernel is locked down"](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=1957a85b0032a81e6482ca4aab883643b8dae06e) applied?
### Is upstream commit [75b0cea7bf307f362057cc778efe89af4c615354 "ACPI: configfs: Disallow loading ACPI tables when locked down"](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=75b0cea7bf307f362057cc778efe89af4c615354) applied?
### Is upstream commit [eadb2f47a3ced5c64b23b90fd2a3463f63726066 "lockdown: also lock down previous kgdb use"](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=eadb2f47a3ced5c64b23b90fd2a3463f63726066) applied?
*******************************************************************************
Yes, the kernels we intend to sign are based on 6.2+, which means they contain
all these fixes.

*******************************************************************************
### Do you build your signed kernel with additional local patches? What do they do?
*******************************************************************************
Yes, see https://git.proxmox.com/?p=pve-kernel.git;a=tree;f=patches/kernel

We also frequently backport or cherry-pick bug and security fixes from the
linux-stable tree.

*******************************************************************************
### If you use vendor_db functionality of providing multiple certificates and/or hashes please briefly describe your certificate setup.
### If there are allow-listed hashes please provide exact binaries for which hashes are created via file sharing service, available in public with anonymous access for verification.
*******************************************************************************
We don't use vendor_db.

*******************************************************************************
### If you are re-using a previously used (CA) certificate, you will need to add the hashes of the previous GRUB2 binaries exposed to the CVEs to vendor_dbx in shim in order to prevent GRUB2 from being able to chainload those older GRUB2 binaries. If you are changing to a new (CA) certificate, this does not apply.
### Please describe your strategy.
*******************************************************************************
Our shim contains a newly generated CA.

*******************************************************************************
### What OS and toolchain must we use to reproduce this build?  Include where to find it, etc.  We're going to try to reproduce your build as closely as possible to verify that it's really a build of the source tree you tell us it is, so these need to be fairly thorough. At the very least include the specific versions of gcc, binutils, and gnu-efi which were used, and where to find those binaries.
### If the shim binaries can't be reproduced using the provided Dockerfile, please explain why that's the case and what the differences would be.
*******************************************************************************
Debian Bookworm

the direct build dependencies are as follows:

Build-Depends: debhelper-compat (= 12),
	       gnu-efi (>= 3.0u),
	       sbsigntool,
	       openssl,
	       libelf-dev,
	       gcc-12,
	       dos2unix,
	       pesign (>= 0.112-5),
	       xxd,
	       libefivar-dev

the complete set of installed dependencies in the build environment is stored
in the file `shim_15.7-1+pmx1_amd64.buildinfo`.

*******************************************************************************
### Which files in this repo are the logs for your build?
This should include logs for creating the buildroots, applying patches, doing the build, creating the archives, etc.
*******************************************************************************
A full build log for building the package in a standard bookworm sbuild
environment is contained in the file `shim_15.7-1+pmx1_amd64.build`. This build
produced the same shim binary as the Dockerfile contained in this repository.

*******************************************************************************
### What changes were made since your SHIM was last signed?
*******************************************************************************
None, as this is the first time.

*******************************************************************************
### What is the SHA256 hash of your final SHIM binary?
*******************************************************************************
d93f0245909a4655ceb8961778f382897b2cc50b1d1e996d1ac450cf7fbcfeb7  shimx64.efi

*******************************************************************************
### How do you manage and protect the keys used in your SHIM?
*******************************************************************************
The keys are stored on a FIPS certified HSM with restricted access.

*******************************************************************************
### Do you use EV certificates as embedded certificates in the SHIM?
*******************************************************************************
No.

*******************************************************************************
### Do you add a vendor-specific SBAT entry to the SBAT section in each binary that supports SBAT metadata ( grub2, fwupd, fwupdate, shim + all child shim binaries )?
### Please provide exact SBAT entries for all SBAT binaries you are booting or planning to boot directly through shim.
### Where your code is only slightly modified from an upstream vendor's, please also preserve their SBAT entries to simplify revocation.
*******************************************************************************
```
sbat,1,UEFI shim,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
shim.proxmox,1,Proxmox,shim,15.7,https://git.proxmox.com/?p=efi-boot-shim.git

sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
grub,3,Free Software Foundation,grub,2.06,https://www.gnu.org/software/grub/
grub.proxmox,3,Proxmox,grub2,2.06-8.1+pmx1,https://git.proxmox.com/?p=grub2.git

sbat,1,UEFI shim,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
fwupd-efi,1,Firmware update daemon,fwupd-efi,1.4,https://github.com/fwupd/fwupd-efi
fwupd-efi.proxmox,1,Proxmox,fwupd,1:1.4-1+pmx1,https://git.proxmox.com/?p=fwupd-efi.git
```

*******************************************************************************
### Which modules are built into your signed grub image?
*******************************************************************************
all_video boot btrfs cat chain configfile cpuid cryptodisk echo efifwsetup
efinet ext2 f2fs fat font gcry_arcfour gcry_blowfish gcry_camellia gcry_cast5
gcry_crc gcry_des gcry_dsa gcry_idea gcry_md4 gcry_md5 gcry_rfc2268
gcry_rijndael gcry_rmd160 gcry_rsa gcry_seed gcry_serpent gcry_sha1 gcry_sha256
gcry_sha512 gcry_tiger gcry_twofish gcry_whirlpool gettext gfxmenu gfxterm
gfxterm_background gzio halt help hfsplus iso9660 jfs jpeg keystatus linux
linuxefi loadenv loopback ls lsefi lsefimmap lsefisystab lssal luks lvm
mdraid09 mdraid1x memdisk minicmd normal ntfs part_apple part_gpt part_msdos
password_pbkdf2 play png probe raid5rec raid6rec reboot regexp search
search_fs_file search_fs_uuid search_label serial sleep smbios squash4 test
tftp tpm true video xfs zfs zfscrypt zfsinfo

*******************************************************************************
### What is the origin and full version number of your bootloader (GRUB or other)?
*******************************************************************************
Based on Debian Sid's 2.0.6-8.1, packaged as 2.0.6-8.1+pmx1

*******************************************************************************
### If your SHIM launches any other components, please provide further details on what is launched.
*******************************************************************************
We are also shipping fwupd. We will evaluate including memtest in some fashion
once https://github.com/rhboot/shim-review/issues/314 has been finalized.

*******************************************************************************
### If your GRUB2 launches any other binaries that are not the Linux kernel in SecureBoot mode, please provide further details on what is launched and how it enforces Secureboot lockdown.
*******************************************************************************
It will only launch Linux in SecureBoot mode.

*******************************************************************************
### How do the launched components prevent execution of unauthenticated code?
*******************************************************************************
Grub is built with SecureBoot support, the Linux kernel with Lockdown support
and fwupd does not chainload any other binaries.

*******************************************************************************
### Does your SHIM load any loaders that support loading unsigned kernels (e.g. GRUB)?
*******************************************************************************
No

*******************************************************************************
### What kernel are you using? Which patches does it includes to enforce Secure Boot?
*******************************************************************************
6.2.6 (based on Ubuntu's 6.2.6 , shipped as 6.2.6-1-pve) or later.

it includes the following lockdown related patches, same as Ubuntu (stripped to
relevant ones since we are only supporting amd64):

```
54974ea36716a6dd2577620b2ea6a8ff522d2d3b UBUNTU: SAUCE: (lockdown) security: lockdown: Make CONFIG_LOCK_DOWN_IN_EFI_SECURE_BOOT more generic
cfd0024412bcab507f496dc26bcf2786cdddf26d UBUNTU: SAUCE: (lockdown) KEYS: Make use of platform keyring for module signature verify
a3c6001aee439e7dd5c0ea911c4e765ba32374be UBUNTU: SAUCE: (lockdown) efi: Lock down the kernel if booted in secure boot mode
90ba1ff238be7f145207973c357bd4cd38fb6f02 UBUNTU: SAUCE: (lockdown) efi: Add an EFI_SECURE_BOOT flag to indicate secure boot mode
802e3841cb6d4cf97fb5f5bda778fd8ee0aa6b34 UBUNTU: SAUCE: (lockdown) security: lockdown: expose a hook to lock the kernel down
be65e263c092c459191bc8363c75479018695d91 UBUNTU: SAUCE: (lockdown) Make get_cert_list() use efi_status_to_str() to print error messages.
00fa9e094b6b264eac83aee03d91c28d7a08f22c UBUNTU: SAUCE: (lockdown) Add efi_status_to_str() and rework efi_status_to_err().
```

the kernel is configured with:

```
CONFIG_MODULE_SIG_FORMAT=y
CONFIG_MODULE_SIG=y
CONFIG_MODULE_SIG_ALL=y
CONFIG_MODULE_SIG_SHA512=y
CONFIG_MODULE_SIG_HASH="sha512"
CONFIG_TRUSTED_KEYS=y
CONFIG_MODULE_SIG_KEY="certs/signing_key.pem"
CONFIG_MODULE_SIG_KEY_TYPE_RSA=y
CONFIG_SYSTEM_TRUSTED_KEYS="../debian/certs/combined.pem"
```

all modules (including out-of-tree ZFS modules) are built together with the
kernel image and signed using an ephemeral RSA key.

*******************************************************************************
### Add any additional information you think we may need to validate this shim.
*******************************************************************************
fwupd-efi packaging tree for our upcoming bookworm releases, based on Debian bookworm packaging:
- https://git.proxmox.com/?p=fwupd-efi.git;a=tree;h=refs/heads/proxmox/bookworm;hb=refs/heads/proxmox/bookworm

grub2 packaging tree, same
- https://git.proxmox.com/?p=grub2.git;a=tree;h=refs/heads/proxmox/bookworm;hb=refs/heads/proxmox/bookworm

kernel packaging tree, packaging is custom:
- https://git.proxmox.com/?p=pve-kernel.git;a=tree;h=refs/heads/wip-secureboot;hb=refs/heads/wip-secureboot

the kernel packages consist of packaging files (custom, directly in the repository), kernel sources (based on Ubuntu Lunar's, which are in turn based on upstream 6.2.x, included via git submodule in `submodules/ubuntu-kernel`), zfs module sources (based on our OpenZFS packaging, which is based on Debian's, included via (nested!) git submodule(s) in `submodules/zfsonlinux`) and kernel patches (in `patches/kernel`).

to get all of the kernel build files a recursive clone can be used `git clone --recursive git://git.proxmox.com/git/pve-kernel.git -b wip-secureboot`. as the branch name implies, this is the current working copy for our upcoming release, it isn't yet released or finalized.


changes since original review request:
- added additional information regarding non-shim package sources
