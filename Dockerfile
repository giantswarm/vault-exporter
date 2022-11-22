FROM alpine:3.17
ADD vault-exporter /usr/bin
ENTRYPOINT ["/usr/bin/vault-exporter"]
