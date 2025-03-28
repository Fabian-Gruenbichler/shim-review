# Adapted from Debian's shim-review request

FROM debian:bookworm-20250317
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
RUN git checkout proxmox-shim-16.0-amd64-20250328
WORKDIR /

# Download and verify the upstream source tarball for shim
RUN wget https://github.com/rhboot/shim/releases/download/16.0/shim-16.0.tar.bz2
RUN echo "d503f778dc75895d3130da07e2ff23d2393862f95b6cd3d24b10cbd4af847217  shim-16.0.tar.bz2" > SHA256SUM
RUN sha256sum -c < SHA256SUM

# Rename the tarball to match what our packaging tools look for
RUN mv shim-16.0.tar.bz2 shim_16.0.orig.tar.bz2
run git clone git://git.proxmox.com/git/efi-boot-shim.git
WORKDIR /efi-boot-shim
RUN ls -lha
RUN git checkout proxmox/16.0-1+pmx1
RUN apt-get build-dep -y .
RUN dpkg-buildpackage -us -uc
WORKDIR /
RUN hexdump -Cv /efi-boot-shim/shim*.efi > build
RUN hexdump -Cv /shim-review/$(basename /shim/shim*.efi) > orig
RUN diff -u orig build
RUN sha256sum /efi-boot-shim/shim*.efi /shim-review/$(basename /shim/shim*.efi)
