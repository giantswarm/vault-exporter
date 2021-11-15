module github.com/giantswarm/vault-exporter

go 1.14

require (
	github.com/frankban/quicktest v1.4.1 // indirect
	github.com/giantswarm/microerror v0.2.0
	github.com/go-test/deep v1.0.2 // indirect
	github.com/hashicorp/go-rootcerts v1.0.2 // indirect
	github.com/hashicorp/vault/api v1.0.5-0.20200317185738-82f498082f02
	github.com/hashicorp/vault/sdk v0.1.14-0.20200429182704-29fce8f27ce4 // indirect
	github.com/pierrec/lz4 v2.2.6+incompatible // indirect
	github.com/prometheus/client_golang v1.4.0
	github.com/prometheus/common v0.9.1
	gopkg.in/alecthomas/kingpin.v2 v2.2.6
	gopkg.in/square/go-jose.v2 v2.4.1 // indirect
)

replace github.com/gogo/protobuf => github.com/gogo/protobuf v1.3.2
