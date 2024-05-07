This repo is for review of requests for signing shim. To create a request for review:

- clone this repo (preferably fork it)
- edit the template below
- add the shim.efi to be signed
- add build logs
- add any additional binaries/certificates/SHA256 hashes that may be needed
- commit all of that
- tag it with a tag of the form "myorg-shim-arch-YYYYMMDD"
- push it to GitHub
- file an issue at https://github.com/rhboot/shim-review/issues with a link to your tag
- approval is ready when the "accepted" label is added to your issue

Note that we really only have experience with using GRUB2 or systemd-boot on Linux, so
asking us to endorse anything else for signing is going to require some convincing on
your part.

Hint: check the [docs](./docs/) directory in this repo for guidance on submission and getting your shim signed.

Here's the template:

*******************************************************************************
### What organization or people are asking to have this signed?
*******************************************************************************
Proxmox Server Solutions GmbH is an Austrian company developing a suite of Debian-derived Linux distributions.

*******************************************************************************
### What product or service is this for?
*******************************************************************************
Currently there are three products sharing a common base:

- Proxmox Virtual Environment (Hypervisor)
- Proxmox Mail Gateway
- Proxmox Backup Server

For our releases based on Debian Bookworm we'd like to update from shim 15.7 to 15.8.

*******************************************************************************
### What's the justification that this really does need to be signed for the whole world to be able to boot it?
*******************************************************************************
Proxmox only provides the software (+ optional enterprise support for it), we don't have control over our users' systems as we don't provide any Software- or Infrastructure-as-a-Service, nor the hardware our software runs on.

*******************************************************************************
### Why are you unable to reuse shim from another distro that is already signed?
*******************************************************************************
Proxmox products use a custom kernel built by us to provide a stable experience for our (enterprise) users. Currently, it's based on the Ubuntu kernel series.

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

Already verified as part of the previous accepted submission.

*******************************************************************************
### Who is the secondary contact for security updates, etc.?
*******************************************************************************
- Name: Proxmox Security Team
- Position: https://pve.proxmox.com/wiki/Security_Reporting
- Email address: security@proxmox.com
- PGP key fingerprint: 0xE6792AA698E11855375AB9E35D0CBD4361F204C5

Already verified as part of the previous accepted submission.

*******************************************************************************
### Were these binaries created from the 15.8 shim release tar?
Please create your shim binaries starting with the 15.8 shim release tar file: https://github.com/rhboot/shim/releases/download/15.8/shim-15.8.tar.bz2

This matches https://github.com/rhboot/shim/releases/tag/15.8 and contains the appropriate gnu-efi source.

Make sure the tarball is correct by verifying your download's checksum with the following ones:

```
a9452c2e6fafe4e1b87ab2e1cac9ec00  shim-15.8.tar.bz2
cdec924ca437a4509dcb178396996ddf92c11183  shim-15.8.tar.bz2
a79f0a9b89f3681ab384865b1a46ab3f79d88b11b4ca59aa040ab03fffae80a9  shim-15.8.tar.bz2
30b3390ae935121ea6fe728d8f59d37ded7b918ad81bea06e213464298b4bdabbca881b30817965bd397facc596db1ad0b8462a84c87896ce6c1204b19371cd1  shim-15.8.tar.bz2
```

Make sure that you've verified that your build process uses that file as a source of truth (excluding external patches) and its checksum matches. Furthermore, there's [a detached signature as well](https://github.com/rhboot/shim/releases/download/15.8/shim-15.8.tar.bz2.asc) - check with the public key that has the fingerprint `8107B101A432AAC9FE8E547CA348D61BC2713E9F` that the tarball is authentic. Once you're sure, please confirm this here with a simple *yes*.

A short guide on verifying public keys and signatures should be available in the [docs](./docs/) directory.
*******************************************************************************
Yes, see Dockerfile for confirmation.

*******************************************************************************
### URL for a repo that contains the exact code which was built to result in your binary:
Hint: If you attach all the patches and modifications that are being used to your application, you can point to the URL of your application here (*`https://github.com/YOUR_ORGANIZATION/shim-review`*).

You can also point to your custom git servers, where the code is hosted.
*******************************************************************************
https://git.proxmox.com/?p=efi-boot-shim.git;a=shortlog;h=refs/tags/proxmox/15.8-1%2Bpmx1

*******************************************************************************
### What patches are being applied and why:
Mention all the external patches and build process modifications, which are used during your building process, that make your shim binary be the exact one that you posted as part of this application.
*******************************************************************************
0001-sbat-Add-grub.peimage-2-to-latest-CVE-2024-2312.patch
0002-sbat-Also-bump-latest-for-grub-4-and-to-todays-date.patch

Both are re-used from Debian's version of the shim, and just update the latest SBAT revocation information.

*******************************************************************************
### Do you have the NX bit set in your shim? If so, is your entire boot stack NX-compatible and what testing have you done to ensure such compatibility?

See https://techcommunity.microsoft.com/t5/hardware-dev-center/nx-exception-for-shim-community/ba-p/3976522 for more details on the signing of shim without NX bit.
*******************************************************************************
No, since our boot stack is not yet NX-compatible.

*******************************************************************************
### What exact implementation of Secure Boot in GRUB2 do you have? (Either Upstream GRUB2 shim_lock verifier or Downstream RHEL/Fedora/Debian/Canonical-like implementation)
Skip this, if you're not using GRUB2.
*******************************************************************************
We re-use Debian's implementation (rebuilding Grub with SBAT adapted to
differentiate the two variants).

*******************************************************************************
### Do you have fixes for all the following GRUB2 CVEs applied?
**Skip this, if you're not using GRUB2, otherwise make sure these are present and confirm with _yes_.**

* 2020 July - BootHole
  * Details: https://lists.gnu.org/archive/html/grub-devel/2020-07/msg00034.html
  * CVE-2020-10713
  * CVE-2020-14308
  * CVE-2020-14309
  * CVE-2020-14310
  * CVE-2020-14311
  * CVE-2020-15705
  * CVE-2020-15706
  * CVE-2020-15707
* March 2021
  * Details: https://lists.gnu.org/archive/html/grub-devel/2021-03/msg00007.html
  * CVE-2020-14372
  * CVE-2020-25632
  * CVE-2020-25647
  * CVE-2020-27749
  * CVE-2020-27779
  * CVE-2021-3418 (if you are shipping the shim_lock module)
  * CVE-2021-20225
  * CVE-2021-20233
* June 2022
  * Details: https://lists.gnu.org/archive/html/grub-devel/2022-06/msg00035.html, SBAT increase to 2
  * CVE-2021-3695
  * CVE-2021-3696
  * CVE-2021-3697
  * CVE-2022-28733
  * CVE-2022-28734
  * CVE-2022-28735
  * CVE-2022-28736
  * CVE-2022-28737
* November 2022
  * Details: https://lists.gnu.org/archive/html/grub-devel/2022-11/msg00059.html, SBAT increase to 3
  * CVE-2022-2601
  * CVE-2022-3775
* October 2023 - NTFS vulnerabilities
  * Details: https://lists.gnu.org/archive/html/grub-devel/2023-10/msg00028.html, SBAT increase to 4
  * CVE-2023-4693
  * CVE-2023-4692
*******************************************************************************
Our Grub packages contain fixes for all of these, except for CVE-2020-15705 and
CVE-2021-3418, same as Debian's.

*******************************************************************************
### If shim is loading GRUB2 bootloader, and if these fixes have been applied, is the upstream global SBAT generation in your GRUB2 binary set to 4?
Skip this, if you're not using GRUB2, otherwise do you have an entry in your GRUB2 binary similar to:  
`grub,4,Free Software Foundation,grub,GRUB_UPSTREAM_VERSION,https://www.gnu.org/software/grub/`?
*******************************************************************************
Yes.

*******************************************************************************
### Were old shims hashes provided to Microsoft for verification and to be added to future DBX updates?
### Does your new chain of trust disallow booting old GRUB2 builds affected by the CVEs?
If you had no previous signed shim, say so here. Otherwise a simple _yes_ will do.
*******************************************************************************
Not yet, since we've only ever submitted one shim binary. But we will do so in the future.
We've never signed a grub with an SBAT level below 4.

*******************************************************************************
### If your boot chain of trust includes a Linux kernel:
### Is upstream commit [1957a85b0032a81e6482ca4aab883643b8dae06e "efi: Restrict efivar_ssdt_load when the kernel is locked down"](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=1957a85b0032a81e6482ca4aab883643b8dae06e) applied?
### Is upstream commit [75b0cea7bf307f362057cc778efe89af4c615354 "ACPI: configfs: Disallow loading ACPI tables when locked down"](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=75b0cea7bf307f362057cc778efe89af4c615354) applied?
### Is upstream commit [eadb2f47a3ced5c64b23b90fd2a3463f63726066 "lockdown: also lock down previous kgdb use"](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=eadb2f47a3ced5c64b23b90fd2a3463f63726066) applied?
Hint: upstream kernels should have all these applied, but if you ship your own heavily-modified older kernel version, that is being maintained separately from upstream, this may not be the case.  
If you are shipping an older kernel, double-check your sources; maybe you do not have all the patches, but ship a configuration, that does not expose the issue(s).
*******************************************************************************
Yes. The earliest kernels we signed were based on 6.5.

*******************************************************************************
### Do you build your signed kernel with additional local patches? What do they do?
*******************************************************************************
Yes, see https://git.proxmox.com/?p=pve-kernel.git;a=tree;f=patches/kernel

We also frequently backport or cherry-pick bug and security fixes from the
linux-stable tree.

*******************************************************************************
### Do you use an ephemeral key for signing kernel modules?
### If not, please describe how you ensure that one kernel build does not load modules built for another kernel.
*******************************************************************************
Yes.

*******************************************************************************
### If you use vendor_db functionality of providing multiple certificates and/or hashes please briefly describe your certificate setup.
### If there are allow-listed hashes please provide exact binaries for which hashes are created via file sharing service, available in public with anonymous access for verification.
*******************************************************************************
We don't.

*******************************************************************************
### If you are re-using the CA certificate from your last shim binary, you will need to add the hashes of the previous GRUB2 binaries exposed to the CVEs mentioned earlier to vendor_dbx in shim. Please describe your strategy.
This ensures that your new shim+GRUB2 can no longer chainload those older GRUB2 binaries with issues.

If this is your first application or you're using a new CA certificate, please say so here.
*******************************************************************************
We are using the same certificate, but we've never signed a vulnerabel GRUB2 binary.

*******************************************************************************
### Is the Dockerfile in your repository the recipe for reproducing the building of your shim binary?
A reviewer should always be able to run `docker build .` to get the exact binary you attached in your application.

Hint: Prefer using *frozen* packages for your toolchain, since an update to GCC, binutils, gnu-efi may result in building a shim binary with a different checksum.

If your shim binaries can't be reproduced using the provided Dockerfile, please explain why that's the case, what the differences would be and what build environment (OS and toolchain) is being used to reproduce this build? In this case please write a detailed guide, how to setup this build environment from scratch.
*******************************************************************************
Yes.

*******************************************************************************
### Which files in this repo are the logs for your build?
This should include logs for creating the buildroots, applying patches, doing the build, creating the archives, etc.
*******************************************************************************
shim_15.8-1+pmx1_amd64.build (build log)
shim_15.8-1+pmx1_amd64.buildinfo (versions of packages installed in the build environment)

*******************************************************************************
### What changes were made in the distro's secure boot chain since your SHIM was last signed?
For example, signing new kernel's variants, UKI, systemd-boot, new certs, new CA, etc..

Skip this, if this is your first application for having shim signed.
*******************************************************************************
We've added one patch for our custom ISO building flow to GRUB2, other than
that, we've just added a kernel series based on 6.8 and regular kernel updates.

*******************************************************************************
### What is the SHA256 hash of your final shim binary?
*******************************************************************************
9eda051612cf976cb8a41dbdee3487668e9c1007682603beef8f4239b8e7be54  shimx64.efi

*******************************************************************************
### How do you manage and protect the keys used in your shim?
Describe the security strategy that is used for key protection. This can range from using hardware tokens like HSMs or Smartcards, air-gapped vaults, physical safes to other good practices.
*******************************************************************************
The keys are stored on a FIPS certified HSM with restricted access.

*******************************************************************************
### Do you use EV certificates as embedded certificates in the shim?
A _yes_ or _no_ will do. There's no penalty for the latter.
*******************************************************************************
No.

*******************************************************************************
### Do you add a vendor-specific SBAT entry to the SBAT section in each binary that supports SBAT metadata ( GRUB2, fwupd, fwupdate, systemd-boot, systemd-stub, shim + all child shim binaries )?
### Please provide the exact SBAT entries for all binaries you are booting directly through shim.
Hint: The history of SBAT and more information on how it works can be found [here](https://github.com/rhboot/shim/blob/main/SBAT.md). That document is large, so for just some examples check out [SBAT.example.md](https://github.com/rhboot/shim/blob/main/SBAT.example.md)

If you are using a downstream implementation of GRUB2 (e.g. from Fedora or Debian), make sure you have their SBAT entries preserved and that you **append** your own (don't replace theirs) to simplify revocation.

**Remember to post the entries of all the binaries. Apart from your bootloader, you may also be shipping e.g. a firmware updater, which will also have these.**

Hint: run `objcopy --only-section .sbat -O binary YOUR_EFI_BINARY /dev/stdout` to get these entries. Paste them here. Preferably surround each listing with three backticks (\`\`\`), so they render well.
*******************************************************************************

grub:
```
sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
grub,4,Free Software Foundation,grub,2.06,https://www.gnu.org/software/grub/
grub.debian,4,Debian,grub2,2.06-13+pmx2,https://tracker.debian.org/pkg/grub2
grub.proxmox,1,Proxmox,grub2,2.06-13+pmx2,https://git.proxmox.com/?p=grub2.git
```

shim:
```
sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
shim,4,UEFI shim,shim,1,https://github.com/rhboot/shim
shim.proxmox,1,Proxmox,shim,15.8,https://git.proxmox.com/?p=efi-boot-shim.git
```

```
sbat,1,UEFI shim,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
fwupd-efi,1,Firmware update daemon,fwupd-efi,1.4,https://github.com/fwupd/fwupd-efi
fwupd-efi.proxmox,1,Proxmox,fwupd,1:1.4-1+pmx1,https://git.proxmox.com/?p=fwupd-efi.git
```

*******************************************************************************
### If shim is loading GRUB2 bootloader, which modules are built into your signed GRUB2 image?
Skip this, if you're not using GRUB2.

Hint: this is about those modules that are in the binary itself, not the `.mod` files in your filesystem.
*******************************************************************************
all_video boot btrfs cat chain configfile cpuid cryptodisk echo efifwsetup
efinet ext2 f2fs fat font gcry_arcfour gcry_blowfish gcry_camellia gcry_cast5
gcry_crc gcry_des gcry_dsa gcry_idea gcry_md4 gcry_md5 gcry_rfc2268
gcry_rijndael gcry_rmd160 gcry_rsa gcry_seed gcry_serpent gcry_sha1 gcry_sha256
gcry_sha512 gcry_tiger gcry_twofish gcry_whirlpool gettext gfxmenu gfxterm
gfxterm_background gzio halt help hfsplus iso9660 jfs jpeg keystatus linux
linuxefi loadenv loopback ls lsefi lsefimmap lsefisystab lssal luks luks2 lvm
mdraid09 mdraid1x memdisk minicmd normal ntfs part_apple part_gpt part_msdos
password_pbkdf2 play png probe raid5rec raid6rec reboot regexp search
search_fs_file search_fs_uuid search_label serial sleep smbios squash4 test tpm
true video xfs zfs zfscrypt zfsinfo

*******************************************************************************
### If you are using systemd-boot on arm64 or riscv, is the fix for [unverified Devicetree Blob loading](https://github.com/systemd/systemd/security/advisories/GHSA-6m6p-rjcq-334c) included?
*******************************************************************************
Not applicable.

*******************************************************************************
### What is the origin and full version number of your bootloader (GRUB2 or systemd-boot or other)?
*******************************************************************************
Based on Debian Bookworm's 2.0.6-13+deb12u1, packaged as 2.0.6-13+pmx2
We do plan on supporting systemd-boot on x64_64/amd64 once the packaging and policies on the Debian side are finalized.

*******************************************************************************
### If your shim launches any other components apart from your bootloader, please provide further details on what is launched.
Hint: The most common case here will be a firmware updater like fwupd.
*******************************************************************************
We are also shipping fwupd. We will evaluate including memtest in some fashion
once https://github.com/rhboot/shim-review/issues/314 has been finalized.

*******************************************************************************
### If your GRUB2 or systemd-boot launches any other binaries that are not the Linux kernel in SecureBoot mode, please provide further details on what is launched and how it enforces Secureboot lockdown.
Skip this, if you're not using GRUB2 or systemd-boot.
*******************************************************************************
It will only launch Linux in SecureBoot mode.

*******************************************************************************
### How do the launched components prevent execution of unauthenticated code?
Summarize in one or two sentences, how your secure bootchain works on higher level.
*******************************************************************************
Grub is built with SecureBoot support, the Linux kernel with Lockdown support
and fwupd does not chainload any other binaries.

*******************************************************************************
### Does your shim load any loaders that support loading unsigned kernels (e.g. certain GRUB2 configurations)?
*******************************************************************************
No.

*******************************************************************************
### What kernel are you using? Which patches and configuration does it include to enforce Secure Boot?
*******************************************************************************

6.8.4 based on Ubuntu's 6.8.0-32.32, shipped as 6.8.4-3-pve

The kernel is configured with:

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

All modules (including out-of-tree ZFS modules) are built together with the
kernel image and signed using an ephemeral RSA key.

*******************************************************************************
### Add any additional information you think we may need to validate this shim signing application.
*******************************************************************************
fwupd-efi packaging tree for our bookworm releases, based on Debian bookworm packaging:
- https://git.proxmox.com/?p=fwupd-efi.git;a=tree;h=refs/heads/proxmox/bookworm;hb=refs/heads/proxmox/bookworm

grub2 packaging tree, same
- https://git.proxmox.com/?p=grub2.git;a=tree;h=refs/heads/proxmox/bookworm;hb=refs/heads/proxmox/bookworm

kernel packaging tree, packaging is custom:
- https://git.proxmox.com/?p=pve-kernel.git;a=tree;h=refs/heads/master;hb=refs/heads/master

The kernel packages consist of packaging files (custom, directly in the
repository), kernel sources (based on Ubuntu Noble's, which are in turn based
on upstream 6.8.x, included via git submodule in `submodules/ubuntu-kernel`),
zfs module sources (based on our OpenZFS packaging, which is based on Debian's,
included via (nested!) git submodule(s) in `submodules/zfsonlinux`) and kernel
patches (in `patches/kernel`).

To get all of the kernel build files a recursive clone can be used `git clone --recursive git://git.proxmox.com/git/pve-kernel.git`.
