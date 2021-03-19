FROM alpine:3.12
ADD vault-exporter /usr/bin
ENTRYPOINT ["/usr/bin/vault-exporter"]
