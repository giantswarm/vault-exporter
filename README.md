# Vault Exporter

Export [Hashicorp Vault](https://github.com/hashicorp/vault) health to [Prometheus](https://github.com/prometheus/prometheus).

## Exported Metrics

| Metric | Meaning | Labels |
| ------ | ------- | ------ |
| vault_up | Was the last query of Vault successful, | |
| vault_initialized | Is the Vault initialised (according to this node). | |
| vault_sealed | Is the Vault node sealed. | |
| vault_standby | Is this Vault node in standby. | |
| vault_info | Various info about the Vault node. | version, cluster_name, cluster_id |

## Dashboards and alerts

<img align="right" width="192" height="200" src="dashboard.png">

Example dashboards and alerts for this exporter are included in the
mixin directory, in the form of a jsonnet monitoring mixin.  They
are designed to be combined with the [prometheus-ksonnet](https://github.com/kausalco/public/tree/master/prometheus-ksonnet) package.

To install this mixin, use [ksonnet](https://ksonnet.io/):

```sh
$ ks registry add vault_exporter https://github.com/grapeshot/vault_exporter
$ ks pkg install vault_exporter/vault-mixin
```

Then to use, in your `main.jsonnet` file:

```js
local prometheus = (import "prometheus-ksonnet/prometheus-ksonnet.libsonnet");
local vault = (import "vault-mixin/mixin.libsonnet");

prometheus + vault {
  jobs+: {
    vault: "<my vault namespace>/<my value name label>",
  },
}
```

## Flags

```bash
$ ./vault_exporter -h
usage: vault_exporter [<flags>]

Flags:
  -h, --help              Show context-sensitive help (also try --help-long and --help-man).
      --web.listen-address=":9410"  
                                 Address to listen on for web interface and telemetry. Env var: WEB_LISTEN_ADDRESS
      --web.telemetry-path="/metrics"  
                                 Path under which to expose metrics. Env var: WEB_TELEMETRY_PATH
      --web.basic-auth=WEB.BASIC-AUTH
                                 Basic auth credentials in htpasswd format, e.g. 'test:$2y$05$FIYPVfTq2ZSRyFKm1z'. Create with `htpasswd -B
                                 -n my_user`. Env var WEB_BASIC_AUTH
      --vault-tls-cacert=VAULT-TLS-CACERT  
                                 The path to a PEM-encoded CA cert file to use to verify the Vault server SSL certificate.
      --vault-tls-client-cert=VAULT-TLS-CLIENT-CERT  
                                 The path to the certificate for Vault communication.
      --vault-tls-client-key=VAULT-TLS-CLIENT-KEY  
                                 The path to the private key for Vault communication.
      --vault-metrics            Adds Vault's metrics from sys/health to the Vault exporter's metrics output. Only the primary node delivers
                                 these metrics. Env var: VAULT_METRICS
      --insecure-ssl             Set SSL to ignore certificate validation.
      --tls.enable="false"       Enable TLS (true/false). Env var: TLS_ENABLE
      --tls.prefer-server-cipher-suites="true"
                                 Server selects the client's most preferred cipher suite (true/false). Env var:
                                 TLS_PREFER_SERVER_CIPHER_SUITES
      --tls.key-file=TLS.KEY-FILE
                                 Path to the private key file. Env var: TLS_KEY_FILE
      --tls.cert-file=TLS.CERT-FILE
                                 Path to the cert file. Can contain multiple certs. Env var: TLS_CERT_FILE
      --tls.min-ver=TLS12        TLS minimum version. Env var: TLS_MIN_VER
      --tls.max-ver=TLS13        TLS maximum version. Env var: TLS_MAX_VER
      --tls.cipher-suite=TLS.CIPHER-SUITE ...
                                 Allowed cipher suite (See https://golang.org/pkg/crypto/tls/#pkg-constants). Specify multiple times for
                                 adding more suites. Default: built-in cipher list. Env var: TLS_CIPHER_SUITES - separate multiple values
                                 with a new line
      --tls.curve=TLS.CURVE ...  Allowed curves for an elliptic curve (See https://golang.org/pkg/crypto/tls/#CurveID). Default: built-in
                                 curves list. Env var: TLS_CURVES - separate multiple values with a new line
      --log.level="info"  Only log messages with the given severity or above. Valid levels: [debug, info, warn, error, fatal]
      --log.format="logger:stderr"  
                          Set the log target and format. Example: "logger:syslog?appname=bob&local=7" or "logger:stdout?json=true"
      --version           Show application version.
```

## Vault metrics

A Vault primary node exposes under the endpoint `sys/metrics` some detailed metrics. For the sake of simplicity, 
Vault exporter proxies these metrics and adds in case of a name clash the prefix _vault_ to the metric family  
name. You can disable the Vault metrics by appending "--vault-metrics=false" to the command line.

## TLS Examples

```bash
./vault_exporter --tls.enable --tls.key-file=localhost.key --tls.cert-file=localhost.crt
```

Define list of ciphers
```bash
./vault_exporter --tls.enable=true --tls.key-file=localhost.key --tls.cert-file=localhost.crt \
                 --tls.cipher-suite="TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" \
                 --tls.cipher-suite="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
```

Define list of ciphers via environment variables
```bash
# Note the newline
TLS_CIPHER_SUITES="TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
"
./vault_exporter --tls.enable=true --tls.key-file=localhost.key --tls.cert-file=localhost.crt
```

## Generate TLS cert for local development

```bash
openssl req -new -nodes -subj "/C=DE/CN=localhost" \
                  -addext "subjectAltName = DNS:localhost" \
                  -newkey rsa:2048 -keyout localhost.key -out localhost.csr
openssl  x509  -req  -days 365  -in localhost.csr  -signkey localhost.key  -out localhost.crt
```

## Basic Auth

vault_exporter expects the basic auth credentials in the _htpasswd_ format. They can be created with the `htpasswd` 
command line utility (user: test, pass: test):
```bash
$ htpasswd -B -n test
New password:
Re-type new password:
test:$2y$05$tlFqYpCCutsYxANpwSEVEOLAP1KXm.Ndp1Vt5cPqD2mN9xPyfxkq2
```

Then just passt the resulting string with the bcrypt encrypted password via command line:

```bash
./vault_exporter --web.basic-auth='test:$2y$05$tlFqYpCCutsYxANpwSEVEOLAP1KXm.Ndp1Vt5cPqD2mN9xPyfxkq2'
``` 

## Environment variables

Note that environment variables can be overwritten by flags.

* `VAULT_ADDR` – Sets the address of Vault in the client, The format of address should be "<Scheme>://<Host>:<Port>" (defaults to `https://127.0.0.1:8200`)
* `VAULT_CACERT` – CACert is the path to a PEM-encoded CA cert file to use to verify the Vault server SSL certificate (defaults to empty)
* `VAULT_CAPATH` – CAPath is the path to a directory of PEM-encoded CA cert files to verify the Vault server SSL certificate (defaults to empty)
* `VAULT_CLIENT_CERT` – ClientCert is the path to the certificate for Vault communication (defaults to empty)
* `VAULT_CLIENT_KEY` – ClientKey is the path to the private key for Vault communication (defaults to empty)
* `VAULT_CLIENT_TIMEOUT` – Timeout is for setting custom timeout parameter in the Http-client (defaults to `0`)
* `VAULT_SKIP_VERIFY` – SkipVerify enables or disables SSL verification (defaults to `false`)
* `VAULT_TLS_SERVER_NAME` – TLSServerName, if set, is used to set the SNI host when connecting via TLS (defaults to empty)
* `VAULT_MAX_RETRIES` – MaxRetries controls the maximum number of times to retry when a 5xx error occurs (defaults to `0`)
* `VAULT_ROLE_ID` – Role ID for authenticating via AppRole
* `VAULT_SECRET_ID` – Secret ID for authenticating via AppRole
* `VAULT_APPROLE_MOUNTPOINT` – Mountpoint of the AppRole backend
