# Adapted from Debian's shim-review request

FROM debian:bookworm-20230227
RUN apt-get update -y
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates

#########
##
## May need these 2 lines below as/when toolchain updates hit bookworm
#RUN echo "deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/20230404T000000Z/ unstable main" > /etc/apt/sources.list
#RUN echo "deb-src [check-valid-until=no] https://snapshot.debian.org/archive/debian/20230404T000000Z/ unstable main" >> /etc/apt/sources.list
##
#########

RUN apt-get update -y
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends build-essential wget git
RUN git clone https://github.com/Fabian-Gruenbichler/shim-review.git
WORKDIR /shim-review
RUN git checkout proxmox-shim-15.7-amd64-20230404
WORKDIR /

# Download and verify the upstream source tarball for shim
RUN wget https://github.com/rhboot/shim/releases/download/15.7/shim-15.7.tar.bz2
RUN echo "87cdeb190e5c7fe441769dde11a1b507ed7328e70a178cd9858c7ac7065cfade  shim-15.7.tar.bz2" > SHA256SUM
RUN sha256sum -c < SHA256SUM

# Rename the tarball to match what our packaging tools look for
RUN mv shim-15.7.tar.bz2 shim_15.7.orig.tar.bz2
run git clone git://git.proxmox.com/git/efi-boot-shim.git
WORKDIR /efi-boot-shim
RUN ls -lha
RUN git checkout proxmox/15.7-1+pmx1
RUN apt-get build-dep -y .
RUN dpkg-buildpackage -us -uc
WORKDIR /
RUN hexdump -Cv /efi-boot-shim/shim*.efi > build
RUN hexdump -Cv /shim-review/$(basename /shim/shim*.efi) > orig
RUN diff -u orig build
RUN sha256sum /efi-boot-shim/shim*.efi /shim-review/$(basename /shim/shim*.efi)
