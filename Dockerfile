# Adapted from Debian's shim-review request

FROM debian:bookworm-20260223
RUN apt-get update -y
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates

#########
##
## May need these 2 lines below as/when toolchain updates hit bookworm
#RUN echo "deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/20240507T000000Z/ unstable main" > /etc/apt/sources.list
#RUN echo "deb-src [check-valid-until=no] https://snapshot.debian.org/archive/debian/20240507T000000Z/ unstable main" >> /etc/apt/sources.list
##
#########

RUN apt-get update -y
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends build-essential wget git
RUN git clone https://github.com/Fabian-Gruenbichler/shim-review.git
WORKDIR /shim-review
RUN git checkout proxmox-shim-16.1-bpo12-amd64-20260325
WORKDIR /

# Download and verify the upstream source tarball for shim
RUN wget https://github.com/rhboot/shim/releases/download/16.1/shim-16.1.tar.bz2
RUN echo "46319cd228d8f2c06c744241c0f342412329a7c630436fce7f82cf6936b1d603  shim-16.1.tar.bz2" > SHA256SUM
RUN sha256sum -c < SHA256SUM

# Rename the tarball to match what our packaging tools look for
RUN mv shim-16.1.tar.bz2 shim_16.1.orig.tar.bz2
run git clone git://git.proxmox.com/git/efi-boot-shim.git
WORKDIR /efi-boot-shim
RUN ls -lha
RUN git checkout proxmox/16.1-1+pmx1_bpo12+1
RUN apt-get build-dep -y .
RUN dpkg-buildpackage -us -uc
WORKDIR /
RUN hexdump -Cv /efi-boot-shim/shim*.efi > build
RUN hexdump -Cv /shim-review/$(basename /shim/shim*.efi) > orig
RUN diff -u orig build
RUN sha256sum /efi-boot-shim/shim*.efi /shim-review/$(basename /shim/shim*.efi)
