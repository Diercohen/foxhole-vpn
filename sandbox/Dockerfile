# foxhole-vpn in a container, so nothing is installed on your computer and the app sees only what you mount: your
# Firefox profile (read-only) and a volume for its own settings. Build straight from GitHub (or, in a clone, with . for the URL):
#   docker build -t foxhole-sandbox -f sandbox/Dockerfile https://github.com/Diercohen/foxhole-vpn.git
# Where Docker Hub refuses (Iran), take the base from a mirror: --build-arg BASE=registry.docker.ir/library/node:22-bookworm-slim
ARG BASE=node:22-bookworm-slim
FROM ${BASE}
ENV LANG=C.UTF-8
# What global mode runs on Linux: ip, iptables, pkill, and resolvectl (systemd-resolved's client) to set the host's DNS
# over its D-Bus. Only resolvectl is taken from systemd-resolved's package: installing the package would set up a resolver here.
RUN for m in deb.debian.org mirror.shatel.ir mirror.iranserver.com mirror.mobinhost.com mirror2.chabokan.net; do \
   sed -i -E "s#^URIs: [a-z]+://[^/]+/#URIs: http://$m/#" /etc/apt/sources.list.d/debian.sources; \
   apt-get -o Acquire::http::Timeout=20 update --error-on=any && break; \
 done \
 && apt-get install -y --no-install-recommends ca-certificates curl unzip iproute2 iptables procps systemd \
 && cd /tmp && apt-get download systemd-resolved && dpkg-deb -x systemd-resolved_*.deb r && cp r/usr/bin/resolvectl /usr/local/bin/ \
 && arch=$(dpkg --print-architecture) \
 && curl -fsSL -o t2s.zip "https://github.com/xjasonlyu/tun2socks/releases/latest/download/tun2socks-linux-$arch.zip" \
 && unzip -q t2s.zip && install -m 755 "tun2socks-linux-$arch" /usr/local/bin/tun2socks \
 && rm -rf /tmp/* /var/lib/apt/lists/*
WORKDIR /app
COPY package.json package-lock.json tsconfig.json ./
COPY src src
RUN npm ci && npm run build && npm prune --omit=dev && ln -s /app/dist/cli.js /usr/local/bin/foxhole
# foxhole's settings, last country and saved token
VOLUME /root/.config/foxhole-vpn
ENTRYPOINT ["foxhole"]
