FROM alpine:3.5
ADD vault-exporter /usr/bin
ENTRYPOINT ["/usr/bin/vault-exporter"]
