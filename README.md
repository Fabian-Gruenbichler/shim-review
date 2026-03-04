*******************************************************************************
### What organization or people are asking to have this signed?
*******************************************************************************
Organization name and website:  
Company: Proxmox Server Solutions GmbH
Address: Bräuhausgasse 37, 1050 Vienna, Austria

Email: office@proxmox.com
https://www.proxmox.com

*******************************************************************************
### What's the legal data that proves the organization's genuineness?
The reviewers should be able to easily verify, that your organization is a legal entity, to prevent abuse.
Provide the information, which can prove the genuineness with certainty.
*******************************************************************************
Company/tax register entries or equivalent:  

Commercial Register: FN 258879f
Place of jurisdiction: Handelsgericht Wien
CEO: Martin Maurer
https://justizonline.gv.at/jop/web/firmenbuchabfrage/258879f_1

Codesigning EV Cert data:
```
Issuer: C=BE, O=GlobalSign nv-sa, CN=GlobalSign GCC R45 EV CodeSigning CA 2020
Subject: businessCategory=Private Organization, serialNumber=258879f, jurisdictionC=AT, jurisdictionST=Vienna, jurisdictionL=Vienna, C=AT, ST=Vienna, L=Vienna, street=Braeuhausgasse 37, O=Proxmox Server Solutions GmbH, CN=Proxmox Server Solutions GmbH, emailAddress=office@proxmox.com
```

*******************************************************************************
### What product or service is this for?
*******************************************************************************
Our Debian Trixie based suite of products sharing a common base:

- Proxmox Virtual Environment (Hypervisor)
- Proxmox Mail Gateway
- Proxmox Backup Server
- Proxmox Datacenter Manager

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
### Were these binaries created from the 16.1 shim release tar?
Please create your shim binaries starting with the 16.1 shim release tar file: https://github.com/rhboot/shim/releases/download/16.1/shim-16.1.tar.bz2

This matches https://github.com/rhboot/shim/releases/tag/16.1 and contains the appropriate gnu-efi source.

Make sure the tarball is correct by verifying your download's checksum
(SHA256, SHA512) with the following ones:

```
46319cd228d8f2c06c744241c0f342412329a7c630436fce7f82cf6936b1d603  shim-16.1.tar.bz2
ca5f80e82f3b80b622028f03ef23105c98ee1b6a25f52a59c823080a3202dd4b9962266489296e99f955eb92e36ce13e0b1d57f688350006bba45f2718f159fb  shim-16.1.tar.bz2
```

Make sure that you've verified that your build process uses that file
as a source of truth (excluding external patches) and its checksum
matches. You can also further validate the release by checking the PGP
signature: there's [a detached
signature](https://github.com/rhboot/shim/releases/download/16.1/shim-16.1.tar.bz2.asc)

The release is signed by the maintainer Peter Jones - his master key
has the fingerprint `B00B48BC731AA8840FED9FB0EED266B70F4FEF10` and the
signing sub-key in the signature here has the fingerprint
`02093E0D19DDE0F7DFFBB53C1FD3F540256A1372`. A copy of his public key
is included here for reference:
[pjones.asc](https://github.com/rhboot/shim-review/blob/main/pjones.asc)

Once you're sure that the tarball you are using is correct and
authentic, please confirm this here with a simple *yes*.

A short guide on verifying public keys and signatures should be available in the [docs](./docs/) directory.
*******************************************************************************
yes

*******************************************************************************
### URL for a repo that contains the exact code which was built to result in your binary:
Hint: If you attach all the patches and modifications that are being used to your application, you can point to the URL of your application here (*`https://github.com/YOUR_ORGANIZATION/shim-review`*).

You can also point to your custom git servers, where the code is hosted.
*******************************************************************************
https://git.proxmox.com/?p=efi-boot-shim.git;a=shortlog;h=refs/tags/proxmox/16.1-1%2Bpmx1

*******************************************************************************
### What patches are being applied and why:
Mention all the external patches and build process modifications, which are used during your building process, that make your shim binary be the exact one that you posted as part of this application.
*******************************************************************************
A single commit cherry-picked from upstream for compat with different binutils
versions.

*******************************************************************************
### Do you have the NX bit set in your shim? If so, is your entire boot stack NX-compatible and what testing have you done to ensure such compatibility?

See https://techcommunity.microsoft.com/t5/hardware-dev-center/nx-exception-for-shim-community/ba-p/3976522 for more details on the signing of shim without NX bit.
*******************************************************************************
No, not yet. We plan to do this for our shim/bootloader stack based on Debian
Forky next year.

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
* February 2025
  * Details: https://lists.gnu.org/archive/html/grub-devel/2025-02/msg00024.html, SBAT increase to 5
  * CVE-2024-45774
  * CVE-2024-45775
  * CVE-2024-45776
  * CVE-2024-45777
  * CVE-2024-45778
  * CVE-2024-45779
  * CVE-2024-45780
  * CVE-2024-45781
  * CVE-2024-45782
  * CVE-2024-45783
  * CVE-2025-0622
  * CVE-2025-0624
  * CVE-2025-0677
  * CVE-2025-0678
  * CVE-2025-0684
  * CVE-2025-0685
  * CVE-2025-0686
  * CVE-2025-0689
  * CVE-2025-0690
  * CVE-2025-1118
  * CVE-2025-1125
*******************************************************************************
Our Grub packages contain fixes for all of these, except for CVE-2020-15705 and
CVE-2021-3418, same as Debian's.

A previous fix for the NTFS vulnerabilities from February 2025 was incomplete,
this was specific to our variant of Grub, as a result we have bumped the Grub
SBAT level with our vendor suffix to '2'.

*******************************************************************************
### If shim is loading GRUB2 bootloader, and if these fixes have been applied, is the upstream global SBAT generation in your GRUB2 binary set to 5?
Skip this, if you're not using GRUB2, otherwise do you have an entry in your GRUB2 binary similar to:  
`grub,5,Free Software Foundation,grub,GRUB_UPSTREAM_VERSION,https://www.gnu.org/software/grub/`?
*******************************************************************************
See above - it is set to 5.

*******************************************************************************
### Were old shims hashes provided to Microsoft for verification and to be added to future DBX updates?
### Does your new chain of trust disallow booting old GRUB2 builds affected by the CVEs?
If you had no previous signed shim, say so here. Otherwise a simple _yes_ will do.
*******************************************************************************
No. All our old shims and Grub binaries are using SBAT for revocation.

*******************************************************************************
### If your boot chain of trust includes a Linux kernel:
### Is upstream commit [1957a85b0032a81e6482ca4aab883643b8dae06e "efi: Restrict efivar_ssdt_load when the kernel is locked down"](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=1957a85b0032a81e6482ca4aab883643b8dae06e) applied?
### Is upstream commit [75b0cea7bf307f362057cc778efe89af4c615354 "ACPI: configfs: Disallow loading ACPI tables when locked down"](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=75b0cea7bf307f362057cc778efe89af4c615354) applied?
### Is upstream commit [eadb2f47a3ced5c64b23b90fd2a3463f63726066 "lockdown: also lock down previous kgdb use"](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=eadb2f47a3ced5c64b23b90fd2a3463f63726066) applied?
Hint: upstream kernels should have all these applied, but if you ship your own heavily-modified older kernel version, that is being maintained separately from upstream, this may not be the case.  
If you are shipping an older kernel, double-check your sources; maybe you do not have all the patches, but ship a configuration, that does not expose the issue(s).
*******************************************************************************
Yes. Our kernels are currently based on 6.17

*******************************************************************************
### How does your signed kernel enforce lockdown when your system runs with Secure Boot enabled?
Hint: If it does not, we are not likely to sign your shim.
*******************************************************************************
Using all the standard upstream mechanisms/security features, most prominently
the `lockdown` LSM.

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
We are re-using the CA certificate, but we've never signed a previous
vulnerable GRUB2 binary without SBAT data.

*******************************************************************************
### Is the Dockerfile in your repository the recipe for reproducing the building of your shim binary?
A reviewer should always be able to run `docker build .` to get the exact binary you attached in your application.

Hint: Prefer using *frozen* packages for your toolchain, since an update to GCC, binutils, gnu-efi may result in building a shim binary with a different checksum.

If your shim binaries can't be reproduced using the provided Dockerfile, please explain why that's the case, what the differences would be and what build environment (OS and toolchain) is being used to reproduce this build? In this case please write a detailed guide, how to setup this build environment from scratch.
*******************************************************************************
Yes

*******************************************************************************
### Which files in this repo are the logs for your build?
This should include logs for creating the buildroots, applying patches, doing the build, creating the archives, etc.
*******************************************************************************
shim_16.1-1+pmx1_arm64.build (build log)
shim_16.1-1+pmx1_arm64.buildinfo (versions of packages installed in the build environment)

*******************************************************************************
### What changes were made in the distro's secure boot chain since your SHIM was last signed?
For example, signing new kernel's variants, UKI, systemd-boot, new certs, new CA, etc..

Skip this, if this is your first application for having shim signed.
*******************************************************************************
We've added a kernel series based on 6.11 (discontinued), 6.14 and 6.17, a new
product based on the shared Secure Boot implementation, updated Grub2 for the
fixes for SBAT 5 including two regression follow-ups, and added a new optional
package containing an updated SBAT policy (`revocations.efi`) to enforce
revoking Grub2 with SBAT 4.

*******************************************************************************
### What is the SHA256 hash of your final shim binary?
*******************************************************************************

33d7087f5e96d1f8ef4b5593743cea30a40dd72f63e4158484ab92a6886cd9c6  shimaa64.efi

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
### Are you embedding a CA certificate in your shim?
A _yes_ or _no_ will do. There's no penalty for the latter. However,
if _yes_: does that certificate include the X509v3 Basic Constraints
to say that it is a CA? See the [docs](./docs/) for more guidance
about this.
*******************************************************************************
Yes.

Here are the X509 extensions of that certificate:

```
X509v3 extensions:
    X509v3 Basic Constraints: critical
        CA:TRUE
    X509v3 Key Usage: critical
        Digital Signature, Certificate Sign, CRL Sign
    X509v3 Extended Key Usage:
        Code Signing
    X509v3 Subject Key Identifier:
        B5:F1:B1:1E:48:2D:B5:86:93:29:CB:97:5A:A3:52:05:F8:72:CD:7A
    X509v3 Authority Key Identifier:
        B5:F1:B1:1E:48:2D:B5:86:93:29:CB:97:5A:A3:52:05:F8:72:CD:7A
    X509v3 Subject Alternative Name:
        email:office@proxmox.com
    X509v3 Issuer Alternative Name:
        email:office@proxmox.com
```

*******************************************************************************
### Do you add a vendor-specific SBAT entry to the SBAT section in each binary that supports SBAT metadata ( GRUB2, fwupd, fwupdate, systemd-boot, systemd-stub, shim + all child shim binaries )?
### Please provide the exact SBAT entries for all binaries you are booting directly through shim.
Hint: The history of SBAT and more information on how it works can be found [here](https://github.com/rhboot/shim/blob/main/SBAT.md). That document is large, so for just some examples check out [SBAT.example.md](https://github.com/rhboot/shim/blob/main/SBAT.example.md)

If you are using a downstream implementation of GRUB2 (e.g. from Fedora or Debian), make sure you have their SBAT entries preserved and that you **append** your own (don't replace theirs) to simplify revocation.

**Remember to post the entries of all the binaries. Apart from your bootloader, you may also be shipping e.g. a firmware updater, which will also have these.**

Hint: run `objcopy --dump-section .sbat=/dev/stdout YOUR_EFI_BINARY` to get these entries. Paste them here. Preferably surround each listing with three backticks (\`\`\`), so they render well.
*******************************************************************************

grub:
```
sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
grub,5,Free Software Foundation,grub,2.12,https://www.gnu.org/software/grub/
grub.debian,5,Debian,grub2,2.12-9+pmx2,https://tracker.debian.org/pkg/grub2
grub.debian13,1,Debian,grub2,2.12-9+pmx2,https://tracker.debian.org/pkg/grub2
grub.peimage,2,Canonical,grub2,2.12-9+pmx2,https://salsa.debian.org/grub-team/grub/-/blob/master/debian/patches/secure-boot/efi-use-peimage-shim.patch
grub.proxmox,2,Proxmox,grub2,2.12-9+pmx2,https://git.proxmox.com/?p=grub2.git
```

shim:
```
sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
shim,4,UEFI shim,shim,1,https://github.com/rhboot/shim
shim.proxmox,1,Proxmox,shim,16.1,https://git.proxmox.com/?p=efi-boot-shim.git
```

fwupd:
```
sbat,1,UEFI shim,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
fwupd-efi,1,Firmware update daemon,fwupd-efi,1.7,https://github.com/fwupd/fwupd-efi
fwupd-efi.proxmox,1,Proxmox,fwupd,1:1.7-1+pmx1,https://git.proxmox.com/?p=fwupd-efi.git
```

*******************************************************************************
### If shim is loading GRUB2 bootloader, which modules are built into your signed GRUB2 image?
Skip this, if you're not using GRUB2.

Hint: this is about those modules that are in the binary itself, not the `.mod` files in your filesystem.
*******************************************************************************
all_video boot btrfs cat chain configfile cryptodisk echo efifwsetup efinet
ext2 f2fs fat fdt font gcry_arcfour gcry_blowfish gcry_camellia gcry_cast5
gcry_crc gcry_des gcry_dsa gcry_idea gcry_md4 gcry_md5 gcry_rfc2268
gcry_rijndael gcry_rmd160 gcry_rsa gcry_seed gcry_serpent gcry_sha1 gcry_sha256
gcry_sha512 gcry_tiger gcry_twofish gcry_whirlpool gettext gfxmenu gfxterm
gfxterm_background gzio halt help hfsplus iso9660 jfs jpeg keystatus linux
loadenv loopback ls lsefi lsefimmap lsefisystab lssal luks luks2 lvm mdraid09
mdraid1x memdisk minicmd normal ntfs part_apple part_gpt part_msdos
password_pbkdf2 peimage png probe raid5rec raid6rec reboot regexp search
search_fs_file search_fs_uuid search_label serial sleep smbios squash4 test tpm
true video xfs zfs zfscrypt zfsinfo

*******************************************************************************
### If you are using systemd-boot on arm64 or riscv, is the fix for [unverified Devicetree Blob loading](https://github.com/systemd/systemd/security/advisories/GHSA-6m6p-rjcq-334c) included?
*******************************************************************************
Not applicable.

*******************************************************************************
### What is the origin and full version number of your bootloader (GRUB2 or systemd-boot or other)?
*******************************************************************************
Based on Debian Trixies's 2.12-9, packaged as 2.12-9+pmx3

We do plan on supporting systemd-boot on x64_64/amd64 and aarch64/arm64 once
the packaging and policies on the Debian side are finalized, once we rebase on
top of Debian Forky (separate upcoming shim submission).

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
Currently 6.14.x and 6.17.x as base (both based on the corresponding Ubuntu
kernel series).

Relevant KConfig values:
```
CONFIG_MODULE_SIG_FORMAT=y
CONFIG_MODULE_SIG=y
CONFIG_MODULE_SIG_ALL=y
CONFIG_MODULE_SIG_SHA512=y
CONFIG_MODULE_SIG_HASH="sha512"
CONFIG_TRUSTED_KEYS=y
CONFIG_TRUSTED_KEYS_TPM=y
CONFIG_LOCK_DOWN_IN_SECURE_BOOT=y
CONFIG_MODULE_SIG_KEY="certs/signing_key.pem"
CONFIG_MODULE_SIG_KEY_TYPE_RSA=y
```

All modules (including out-of-tree ZFS modules) are built together with the
kernel image and signed using an ephemeral RSA key.

*******************************************************************************
### What contributions have you made to help us review the applications of other applicants?
The reviewing process is meant to be a peer-review effort and the best way to have your application reviewed faster is to help with reviewing others. We are in most cases volunteers working on this venue in our free time, rather than being employed and paid to review the applications during our business hours. 

A reasonable timeframe of waiting for a review can reach 2-3 months. Helping us is the best way to shorten this period. The more help we get, the faster and the smoother things will go.

For newcomers, the applications labeled as [*easy to review*](https://github.com/rhboot/shim-review/issues?q=is%3Aopen+is%3Aissue+label%3A%22easy+to+review%22) are recommended to start the contribution process.
*******************************************************************************
We try to keep an eye out for issues or PRs related to the Debian side of the
ecosystem and participate in other discussions where our contributions seem
worthwhile.

*******************************************************************************
### Add any additional information you think we may need to validate this shim signing application.
*******************************************************************************
fwupd-efi packaging tree for our Trixie releases, based on Debian Trixie packaging:
- https://git.proxmox.com/?p=fwupd-efi.git;a=tree;h=refs/heads/proxmox/trixie;hb=refs/heads/proxmox/trixie

grub2 packaging tree, same
- https://git.proxmox.com/?p=grub2.git;a=tree;h=refs/heads/proxmox/trixie;hb=refs/heads/proxmox/trixie

kernel packaging tree, packaging is custom:
- https://git.proxmox.com/?p=pve-kernel.git;a=tree;h=refs/heads/master;hb=refs/heads/master

The kernel packages consist of packaging files (custom, directly in the
repository), kernel sources (based on Ubuntu Questing's, which are in turn based
on upstream 6.17.x, included via git submodule in `submodules/ubuntu-kernel`),
zfs module sources (based on our OpenZFS packaging, which is based on Debian's,
included via (nested!) git submodule(s) in `submodules/zfsonlinux`) and kernel
patches (in `patches/kernel`).

To get all of the kernel build files a recursive clone can be used `git clone --recursive git://git.proxmox.com/git/pve-kernel.git`.

A very similar submission for our x86_64/amd64 based releases was be submitted in #524
