# Define Mosquitto version
ARG MOSQUITTO_VERSION=2.1.4

# Use debian:stable-slim as a builder for Mosquitto and dependencies.
FROM debian:stable-slim@sha256:fbfb4059d2127120aa05b6e6064523d2102552f0cf0026ddf0701c12f1f8f3e0 AS mosquitto_builder
ARG MOSQUITTO_VERSION

# Get mosquitto build dependencies.
RUN set -ex; \
    apt-get update; \
    apt-get install -y wget build-essential libssl-dev libcjson-dev

WORKDIR /app

RUN mkdir -p mosquitto/auth mosquitto/conf.d

RUN wget http://mosquitto.org/files/source/mosquitto-${MOSQUITTO_VERSION}.tar.gz

RUN tar xzvf mosquitto-${MOSQUITTO_VERSION}.tar.gz

# Build mosquitto. WITH_WEBSOCKETS=yes selects the built-in websockets support,
# so libwebsockets is not needed. The sqlite persistence plugin, the
# mosquitto_ctrl shell and the HTTP API are disabled so the build and runtime
# need no extra libraries. Plugins are not shipped, and are left out of the
# install because the persist-sqlite install ignores WITH_SQLITE=no. Only the
# top-level install copies the headers, so they are installed explicitly for
# the go-auth build.
RUN set -ex; \
    cd mosquitto-${MOSQUITTO_VERSION}; \
    export MAKEFLAGS="WITH_WEBSOCKETS=yes WITH_SQLITE=no WITH_EDITLINE=no WITH_HTTP_API=no"; \
    make CFLAGS="-Wall -O2"; \
    for d in libcommon lib apps client src; do make -C "$d" install; done; \
    install -d /usr/local/include/mosquitto; \
    install -m 644 include/mosquitto/*.h /usr/local/include/mosquitto/; \
    install -m 644 include/*.h /usr/local/include/

# Use golang:latest as a builder for the Mosquitto Go Auth plugin.
FROM --platform=$BUILDPLATFORM golang:latest@sha256:205c7636d74e0ffbe3d007162df7d74f859f5a8c8322dfb9f907977686c126cf AS go_auth_builder

ENV CGO_CFLAGS="-I/usr/local/include -fPIC"
ENV CGO_LDFLAGS="-shared -Wl,-unresolved-symbols=ignore-all -fuse-ld=bfd"
ENV CGO_ENABLED=1

# Bring TARGETPLATFORM to the build scope
ARG TARGETPLATFORM
ARG BUILDPLATFORM

# Install TARGETPLATFORM parser to translate its value to GOOS, GOARCH, and GOARM
COPY --from=tonistiigi/xx:golang@sha256:03e312d98f8db5a7adbf403882347ee4cb620a97bd445b0cfdc8e6b47d3b319c / /
RUN go env

RUN apt-get update && apt-get install -y libcjson-dev

# Install needed libc and gcc for target platform.
RUN set -ex; \
  if [ ! -z "$TARGETPLATFORM" ]; then \
    case "$TARGETPLATFORM" in \
  "linux/arm64") \
    apt update && apt install -y gcc-aarch64-linux-gnu libc6-dev-arm64-cross \
    ;; \
  "linux/arm/v7") \
    apt update && apt install -y gcc-arm-linux-gnueabihf libc6-dev-armhf-cross \
    ;; \
  "linux/arm/v6") \
    apt update && apt install -y gcc-arm-linux-gnueabihf libc6-dev-armel-cross libc6-dev-armhf-cross \
    ;; \
  esac \
  fi

WORKDIR /app
COPY --from=mosquitto_builder /usr/local/include/ /usr/local/include/

COPY ./ ./
RUN set -ex; \
    go build -buildmode=c-archive go-auth.go; \
    go build -buildmode=c-shared -o go-auth.so; \
	  go build pw-gen/pw.go

#Start from a new image.
FROM debian:stable-slim@sha256:fbfb4059d2127120aa05b6e6064523d2102552f0cf0026ddf0701c12f1f8f3e0

RUN set -ex; \
    apt update; \
    apt install -y libc-ares2 openssl uuid tini wget libssl3t64 libcjson1

RUN mkdir -p /var/lib/mosquitto /var/log/mosquitto
RUN set -ex; \
    groupadd mosquitto; \
    useradd -s /sbin/nologin mosquitto -g mosquitto -d /var/lib/mosquitto; \
    chown -R mosquitto:mosquitto /var/log/mosquitto/; \
    chown -R mosquitto:mosquitto /var/lib/mosquitto/

#Copy confs, plugin so and mosquitto binary.
COPY --from=mosquitto_builder /app/mosquitto/ /mosquitto/
COPY --from=go_auth_builder /app/pw /mosquitto/pw
COPY --from=go_auth_builder /app/go-auth.so /mosquitto/go-auth.so
COPY --from=mosquitto_builder /usr/local/sbin/mosquitto /usr/sbin/mosquitto

COPY --from=mosquitto_builder /usr/local/lib/libmosquitto* /usr/local/lib/

COPY --from=mosquitto_builder /usr/local/bin/mosquitto_passwd /usr/bin/mosquitto_passwd
COPY --from=mosquitto_builder /usr/local/bin/mosquitto_sub /usr/bin/mosquitto_sub
COPY --from=mosquitto_builder /usr/local/bin/mosquitto_pub /usr/bin/mosquitto_pub
COPY --from=mosquitto_builder /usr/local/bin/mosquitto_rr /usr/bin/mosquitto_rr

RUN ldconfig;

EXPOSE 1883 1884

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD [ "/usr/sbin/mosquitto" ,"-c", "/etc/mosquitto/mosquitto.conf" ]
