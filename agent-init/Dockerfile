FROM --platform=$TARGETPLATFORM alpine:latest

RUN apk add --no-cache iptables

COPY init.sh /usr/local/bin/init.sh
RUN chmod +x /usr/local/bin/init.sh

LABEL org.opencontainers.image.source=https://github.com/tratteria/tratteria-agent
LABEL org.opencontainers.image.description="Tratteria Agent Init Container - Initialization container for Tratteria Agents"
LABEL org.opencontainers.image.licenses=Apache

ENTRYPOINT ["/usr/local/bin/init.sh"]