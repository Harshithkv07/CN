FROM alpine:3.20

# Toolbox for generating both benign and malicious traffic in the lab.
# hping3 is not in the 3.20 main/community repos, so pull just it from edge/testing.
RUN apk add --no-cache nmap nmap-scripts curl wget openssh-client bash coreutils hydra netcat-openbsd \
    && apk add --no-cache hping3 --repository=https://dl-cdn.alpinelinux.org/alpine/edge/testing \
       || echo "hping3 unavailable; SYN flood will fall back to nmap flooding"

WORKDIR /opt
