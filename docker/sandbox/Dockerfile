FROM alpine:3.20

# Ephemeral kernel-verification sandbox. It reads a base64 iptables-restore document from
# $RULESET_B64, dry-runs it with `iptables-restore --test`, then really commits it into this
# throwaway container's private netfilter tables. The entrypoint is fixed, so model output is
# never placed on a shell command line.
RUN apk add --no-cache iptables ip6tables coreutils
COPY verify.sh /verify.sh
RUN chmod +x /verify.sh
ENTRYPOINT ["/verify.sh"]
