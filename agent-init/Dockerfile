FROM --platform=$TARGETPLATFORM alpine:latest

RUN apk add --no-cache iptables

COPY init.sh /usr/local/bin/init.sh
RUN chmod +x /usr/local/bin/init.sh

LABEL org.opencontainers.image.source=https://github.com/tokenetes/tokenetes-agent
LABEL org.opencontainers.image.description="Tokenetes Agent Init Container - Initialization container for Tokenetes Agents"
LABEL org.opencontainers.image.licenses=Apache

ENTRYPOINT ["/usr/local/bin/init.sh"]