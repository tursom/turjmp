FROM node:24-alpine3.22 AS web-build
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM alpine:3.22 AS freerdp-build
ARG FREERDP_VERSION=3.10.3
RUN apk add --no-cache \
    build-base \
    cmake \
    ffmpeg-dev \
    git \
    icu-dev \
    libjpeg-turbo-dev \
    linux-headers \
    openssl-dev \
    pkgconf \
    samurai \
    zlib-dev
WORKDIR /src
RUN git clone --depth 1 --branch "${FREERDP_VERSION}" https://github.com/FreeRDP/FreeRDP.git freerdp
WORKDIR /src/freerdp
RUN cmake -S . -B build -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=/opt/freerdp \
    -DBUILD_TESTING=OFF \
    -DWITH_CLIENT=ON \
    -DWITH_SERVER=ON \
    -DWITH_PROXY=ON \
    -DWITH_PROXY_APP=ON \
    -DWITH_SHADOW=OFF \
    -DWITH_SAMPLE=OFF \
    -DWITH_MANPAGES=OFF \
    -DWITH_X11=OFF \
    -DWITH_WAYLAND=OFF \
    -DWITH_ALSA=OFF \
    -DWITH_CUPS=OFF \
    -DWITH_FFMPEG=OFF \
    -DWITH_KRB5=OFF \
    -DWITH_PCSC=OFF \
    -DWITH_PULSE=OFF \
    -DWITH_USB=OFF \
    -DWITH_FUSE=OFF \
    -DWITH_CLIENT_COMMON=ON \
    -DWITH_CLIENT_SDL=OFF \
    -DCHANNEL_URBDRC=OFF \
    -DCHANNEL_URBDRC_CLIENT=OFF \
    -DCHANNEL_RDPDR_CLIENT=OFF \
    -DCHANNEL_DRIVE_CLIENT=OFF
RUN cmake --build build --target install
RUN test -x /opt/freerdp/bin/freerdp-proxy
RUN pc_dir=/opt/freerdp/lib/pkgconfig \
    && test -f "$pc_dir/freerdp-server-proxy3.pc" \
    && version="$(awk -F': ' '/^Version:/ {print $2; exit}' "$pc_dir/freerdp-server-proxy3.pc")" \
    && printf '%s\n' \
        'prefix=/opt/freerdp' \
        'exec_prefix=${prefix}' \
        'libdir=${prefix}/lib' \
        'includedir=${prefix}/include' \
        '' \
        'Name: FreeRDP proxy module' \
        'Description: FreeRDP proxy module development interface for Turjmp plugin builds' \
        "Version: ${version}" \
        'Requires: freerdp-server-proxy3 freerdp3 winpr3' \
        'Libs: -L${libdir} -lfreerdp-server-proxy3 -lfreerdp3 -lwinpr3' \
        'Cflags: -I${includedir}/freerdp3 -I${includedir}/winpr3' \
        > "$pc_dir/freerdp-proxy-module.pc"
RUN test -f /opt/freerdp/lib/pkgconfig/freerdp-proxy-module.pc

FROM alpine:3.22 AS rdp-plugin-build
RUN apk add --no-cache build-base cmake openssl-dev pkgconf samurai zlib-dev
COPY --from=freerdp-build /opt/freerdp /opt/freerdp
ENV PKG_CONFIG_PATH=/opt/freerdp/lib/pkgconfig
WORKDIR /src/native/rdp-freerdp-plugin
COPY native/rdp-freerdp-plugin/ ./
RUN cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH=/opt/freerdp
RUN cmake --build build
RUN test -f build/proxy-turjmp-plugin.so
RUN plugin_dir="$(pkg-config --variable=proxy_plugindir freerdp3)" \
    && test -n "$plugin_dir" \
    && mkdir -p "$plugin_dir" \
    && cp build/proxy-turjmp-plugin.so "$plugin_dir/proxy-turjmp-plugin.so" \
    && test -f "$plugin_dir/proxy-turjmp-plugin.so"

FROM golang:1.26-alpine3.22 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o /out/turjmp ./cmd/turjmp

FROM alpine:3.22
RUN apk add --no-cache ca-certificates curl ffmpeg-libswscale icu-libs libgcc libjpeg-turbo libstdc++ openssl tzdata zlib
COPY --from=freerdp-build /opt/freerdp /opt/freerdp
COPY --from=rdp-plugin-build /opt/freerdp /opt/freerdp
COPY --from=build /out/turjmp /usr/local/bin/turjmp
COPY --from=build /src/migrations /migrations
COPY --from=web-build /src/web/dist /usr/share/turjmp/web
ENV TURJMP_WEB_DIST=/usr/share/turjmp/web
ENV PATH=/opt/freerdp/bin:$PATH
ENV LD_LIBRARY_PATH=/opt/freerdp/lib
ENTRYPOINT ["turjmp"]
