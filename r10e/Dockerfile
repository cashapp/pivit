# The following information is from https://hub.docker.com/r/nixos/nix/tags
FROM nixos/nix:2.9.0@sha256:13b257cd42db29dc851f9818ea1bc2f9c7128c51fdf000971fa6058c66fbe4b6 as pivit_builder

#########################################################
# Step 1: Prepare nixpkgs for reproducible (r10e) builds
#########################################################
ENV PROJECT_NAME="pivit"
WORKDIR "/build"
# nixpkgs 20220915. This version has go 1.19
ENV NIXPKGS_COMMIT_SHA="ee01de29d2f58d56b1be4ae24c24bd91c5380cea"

ENV PCSCLITE_URL="https://pcsclite.apdu.fr/files/pcsc-lite-1.9.9.tar.bz2"
ENV PCSCLITE_SHA256="cbcc3b34c61f53291cecc0d831423c94d437b188eb2b97b7febc08de1c914e8a"
ENV PCSCLITE_DEPS="pkg-config \
    autoreconfHook \
    autoconf-archive \
    autoconf \
    flex \
    systemd \
    udev \
    libusb \
    polkit \
    perl"
    #gcc \
    #glibc.static \
    #go_1_19"

# Apple M1 workaround
COPY r10e/nix.conf "/build/${PROJECT_NAME}/nix.conf"
ENV NIX_USER_CONF_FILES="/build/${PROJECT_NAME}/nix.conf"

RUN nix-env -i git gnutar bzip2 && \
    mkdir -p /build/nixpkgs && \
    cd /build/nixpkgs && \
    git init && \
    git remote add origin https://github.com/NixOS/nixpkgs.git && \
    git fetch --depth 1 origin ${NIXPKGS_COMMIT_SHA} && \
    git checkout FETCH_HEAD && \
    mkdir -p "/build/${PROJECT_NAME}"

ENV NIX_PATH=nixpkgs=/build/nixpkgs

#########################################################
# Step 2: Build statically linked libpcsclite
#########################################################
RUN cd "/build" && \
  wget "${PCSCLITE_URL}" && \
  export PCSCLITE="$(basename "${PCSCLITE_URL}")" && \
  [ "$(sha256sum "${PCSCLITE}" | cut -f1 -d' ')" = "${PCSCLITE_SHA256}" ] || exit 42 && \
  mkdir -p /build/PCSC && \
  tar xvfj ${PCSCLITE} -C /build/PCSC --strip-components 1

# Warm up cache
RUN nix-shell -p ${PCSCLITE_DEPS}

RUN cd "/build/PCSC" && \
  nix-shell -p ${PCSCLITE_DEPS} \
    --run "echo go version && \
    ./bootstrap && \
    ./configure --enable-static && \
    make && ls src/.libs/libpcsclite.a"

#########################################################
# Step 3: Build statically linked pivit
#########################################################
COPY . "/build/${PROJECT_NAME}"

RUN cd "/build/${PROJECT_NAME}" && \
  nix-shell -p glibc.static go_1_19 pcsclite pkg-config \
  --run "go version && \
  CGO_ENABLED=1 go build -trimpath --ldflags '-linkmode external -extldflags \"-static -L/build/PCSC/src/.libs\"' ./cmd/pivit && \
  file /build/${PROJECT_NAME}/pivit && \
  sha256sum /build/${PROJECT_NAME}/pivit"