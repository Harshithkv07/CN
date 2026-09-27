FROM alpine:3.20

# Protected server: a web service (nginx) + SSH, with iptables available so the agent can
# deploy a verified block rule into this container's own netfilter tables.
RUN apk add --no-cache nginx openssh iptables ip6tables bash \
    && ssh-keygen -A \
    && adduser -D -s /bin/sh appuser \
    && echo "appuser:appuser" | chpasswd \
    && mkdir -p /run/nginx /etc/hrt \
    && echo "<h1>HRT protected server</h1>" > /var/www/localhost/htdocs/index.html

COPY baseline.rules /etc/hrt/baseline.rules
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 80 22
ENTRYPOINT ["/entrypoint.sh"]
