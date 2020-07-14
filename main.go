package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	auth "github.com/abbot/go-http-auth"
	"github.com/giantswarm/microerror"
	vault_api "github.com/hashicorp/vault/api"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/log"
	"github.com/prometheus/common/version"
	kingpin "gopkg.in/alecthomas/kingpin.v2"
	"net/http"
	"os"
	"strconv"
	"strings"
)

var (
	listenAddress = kingpin.Flag("web.listen-address",
		"Address to listen on for web interface and telemetry. Env var: WEB_LISTEN_ADDRESS").
		Default(":9410").
		Envar("WEB_LISTEN_ADDRESS").String()
	metricsPath = kingpin.Flag("web.telemetry-path",
		"Path under which to expose metrics. Env var: WEB_TELEMETRY_PATH").
		Default("/metrics").
		Envar("WEB_TELEMETRY_PATH").String()
	basicAuthCreds = kingpin.Flag("web.basic-auth",
		"Basic auth credentials in htpasswd format, e.g. 'test:$2y$05$FIYPVfTq2ZSRyFKm1z'. "+
			"Create with `htpasswd -B -n my_user`. Env var WEB_BASIC_AUTH ").
		Envar("WEB_BASIC_AUTH").
		String()
	vaultCACert = kingpin.Flag("vault-tls-cacert",
		"The path to a PEM-encoded CA cert file to use to verify the Vault server SSL certificate.").String()
	vaultClientCert = kingpin.Flag("vault-tls-client-cert",
		"The path to the certificate for Vault communication.").String()
	vaultClientKey = kingpin.Flag("vault-tls-client-key",
		"The path to the private key for Vault communication.").String()
	sslInsecure = kingpin.Flag("insecure-ssl",
		"Set SSL to ignore certificate validation. Env var: SSL_INSECURE").
		Envar("SSL_INSECURE").
		Default("false").Bool()
	tlsEnable = kingpin.Flag("tls.enable",
		"Enable TLS (true/false). Env var: TLS_ENABLE").
		Envar("TLS_ENABLE").
		Default("false").String()
	tlsPreferServerCipherSuites = kingpin.Flag("tls.prefer-server-cipher-suites",
		"Server selects the client's most preferred cipher suite (true/false). Env var: TLS_PREFER_SERVER_CIPHER_SUITES").
		Envar("TLS_PREFER_SERVER_CIPHER_SUITES").
		Default("true").String()
	tlsKeyFile = kingpin.Flag("tls.key-file",
		"Path to the private key file. Env var: TLS_KEY_FILE").
		Envar("TLS_KEY_FILE").ExistingFile()
	tlsCertFile = kingpin.Flag("tls.cert-file",
		"Path to the cert file. Can contain multiple certs. Env var: TLS_CERT_FILE").
		Envar("TLS_CERT_FILE").ExistingFile()
	tlsMinVer = parseTLSVersion(kingpin.Flag("tls.min-ver",
		"TLS minimum version. Env var: TLS_MIN_VER").
		Default("TLS12").
		Envar("TLS_MIN_VER"))
	tlsMaxVer = parseTLSVersion(kingpin.Flag("tls.max-ver",
		"TLS maximum  version. Env var: TLS_MAX_VER").
		Default("TLS13").
		Envar("TLS_MAX_VER"))
	tlsCipherSuites = parseTLSCipher(kingpin.Flag("tls.cipher-suite",
		"Allowed cipher suite (See https://golang.org/pkg/crypto/tls/#pkg-constants). "+
			"Specify multiple times for adding more suites. Default: built-in cipher list. "+
			"Env var: TLS_CIPHER_SUITES - separate multiple values with a new line").
		Envar("TLS_CIPHER_SUITES"))
	tlsCurves = parseTLSCurve(kingpin.Flag("tls.curve",
		"Allowed curves for an elliptic curve (See  https://golang.org/pkg/crypto/tls/#CurveID). "+
			"Default: built-in curves list. Env var: TLS_CURVES - separate multiple values with a new line").
		Envar("TLS_CURVES"))
)

const (
	namespace = "vault"
)

var (
	up = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "up"),
		"Was the last query of Vault successful.",
		nil, nil,
	)
	initialized = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "initialized"),
		"Is the Vault initialised (according to this node).",
		nil, nil,
	)
	sealed = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "sealed"),
		"Is the Vault node sealed.",
		nil, nil,
	)
	standby = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "standby"),
		"Is this Vault node in standby.",
		nil, nil,
	)
	info = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "info"),
		"Version of this Vault node.",
		[]string{"version", "cluster_name", "cluster_id"}, nil,
	)
)

// Exporter collects Vault health from the given server and exports them using
// the Prometheus metrics package.
type Exporter struct {
	client *vault_api.Client
}

// NewExporter returns an initialized Exporter.
func NewExporter() (*Exporter, error) {
	vaultConfig := vault_api.DefaultConfig()

	if *sslInsecure {
		tlsconfig := &vault_api.TLSConfig{
			Insecure: true,
		}
		err := vaultConfig.ConfigureTLS(tlsconfig)
		if err != nil {
			return nil, microerror.Mask(err)
		}
	}

	if *vaultCACert != "" || *vaultClientCert != "" || *vaultClientKey != "" {

		tlsconfig := &vault_api.TLSConfig{
			CACert:     *vaultCACert,
			ClientCert: *vaultClientCert,
			ClientKey:  *vaultClientKey,
			Insecure:   *sslInsecure,
		}
		err := vaultConfig.ConfigureTLS(tlsconfig)
		if err != nil {
			return nil, microerror.Mask(err)
		}
	}

	client, err := vault_api.NewClient(vaultConfig)
	if err != nil {
		return nil, err
	}

	return &Exporter{
		client: client,
	}, nil
}

// Describe describes all the metrics ever exported by the Vault exporter. It
// implements prometheus.Collector.
func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {
	ch <- up
	ch <- initialized
	ch <- sealed
	ch <- standby
	ch <- info
}

func bool2float(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// Collect fetches the stats from configured Vault and delivers them
// as Prometheus metrics. It implements prometheus.Collector.
func (e *Exporter) Collect(ch chan<- prometheus.Metric) {
	health, err := e.client.Sys().Health()
	if err != nil {
		ch <- prometheus.MustNewConstMetric(
			up, prometheus.GaugeValue, 0,
		)
		log.Errorf("Failed to collect health from Vault server: %v", err)
		return
	}

	ch <- prometheus.MustNewConstMetric(
		up, prometheus.GaugeValue, 1,
	)
	ch <- prometheus.MustNewConstMetric(
		initialized, prometheus.GaugeValue, bool2float(health.Initialized),
	)
	ch <- prometheus.MustNewConstMetric(
		sealed, prometheus.GaugeValue, bool2float(health.Sealed),
	)
	ch <- prometheus.MustNewConstMetric(
		standby, prometheus.GaugeValue, bool2float(health.Standby),
	)
	ch <- prometheus.MustNewConstMetric(
		info, prometheus.GaugeValue, 1, health.Version, health.ClusterName, health.ClusterID,
	)
}

func init() {
	prometheus.MustRegister(version.NewCollector("vault_exporter"))
}

type tlsVersion uint16

var tlsVersionsMap = map[string]tlsVersion{
	"TLS13": (tlsVersion)(tls.VersionTLS13),
	"TLS12": (tlsVersion)(tls.VersionTLS12),
	"TLS11": (tlsVersion)(tls.VersionTLS11),
	"TLS10": (tlsVersion)(tls.VersionTLS10),
}

func (tv *tlsVersion) Set(tlsVerName string) error {
	if v, ok := tlsVersionsMap[tlsVerName]; ok {
		*tv = v
		return nil
	}
	return errors.New("unknown TLS version: " + tlsVerName)
}

func (tv *tlsVersion) String() string {
	return ""
}

func parseTLSVersion(s kingpin.Settings) (target *tlsVersion) {
	target = new(tlsVersion)
	s.SetValue((*tlsVersion)(target))
	return
}

type cipherList []uint16

func (c *cipherList) Set(cipherName string) error {
	for _, cs := range tls.CipherSuites() {
		if cs.Name == cipherName {
			*c = append(*c, cs.ID)
			return nil
		}
	}
	return errors.New("unknown cipher: " + cipherName)
}

func (c *cipherList) String() string {
	return ""
}

func (c *cipherList) IsCumulative() bool {
	return true
}

func parseTLSCipher(s kingpin.Settings) (target *[]uint16) {
	target = new([]uint16)
	s.SetValue((*cipherList)(target))
	return
}

var curves = map[string]tls.CurveID{
	"CurveP256": tls.CurveP256,
	"CurveP384": tls.CurveP384,
	"CurveP521": tls.CurveP521,
	"X25519":    tls.X25519,
}

type curveList []tls.CurveID

func (cl *curveList) Set(curveName string) error {
	if curveid, ok := curves[curveName]; ok {
		*cl = append(*cl, curveid)
		return nil
	}
	return errors.New("unknown curve: " + curveName)
}

func (cl *curveList) String() string {
	return ""
}

func (cl *curveList) IsCumulative() bool {
	return true
}

func parseTLSCurve(s kingpin.Settings) (target *[]tls.CurveID) {
	target = new([]tls.CurveID)
	s.SetValue((*curveList)(target))
	return
}

type tlsCliConfig struct {
	CertFile                 string
	KeyFile                  string
	CipherSuites             cipherList
	CurvePreferences         curveList
	MinVersion               tlsVersion
	MaxVersion               tlsVersion
	PreferServerCipherSuites bool
	Enable                   bool
}

func listen(listenAddress string, tlsCliConfig *tlsCliConfig) error {
	if !tlsCliConfig.Enable {
		return http.ListenAndServe(listenAddress, nil)
	}

	cert, err := tls.LoadX509KeyPair(tlsCliConfig.CertFile, tlsCliConfig.KeyFile)
	if err != nil {
		return errors.New("failed to load X509KeyPair")
	}

	var tlsConfig = &tls.Config{
		MinVersion:               uint16(tlsCliConfig.MinVersion),
		MaxVersion:               uint16(tlsCliConfig.MaxVersion),
		PreferServerCipherSuites: tlsCliConfig.PreferServerCipherSuites,
		Certificates:             []tls.Certificate{cert},
		CipherSuites:             tlsCliConfig.CipherSuites,
		CurvePreferences:         tlsCliConfig.CurvePreferences,
	}

	server := &http.Server{Addr: listenAddress, Handler: nil, TLSConfig: tlsConfig}
	return server.ListenAndServeTLS("", "")
}

func basicAuthProvider() (*auth.BasicAuth, error) {
	if basicAuthCreds == nil {
		return nil, nil
	}

	credsSplit := strings.Split(*basicAuthCreds, ":")
	if len(credsSplit) != 2 {
		return nil, errors.New("parsing basic auth string failed")
	}
	usernameConfig := credsSplit[0]
	passwordConfig := credsSplit[1]

	secretProvider := func(user string, realm string) string {
		if user == usernameConfig {
			return passwordConfig
		}
		return ""
	}

	authenticator := auth.NewBasicAuthenticator("vault_exporter", secretProvider)
	return authenticator, nil
}

func rootReqHandler() http.Handler {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte(`<html>
             <head><title>Vault Exporter</title></head>
             <body>
             <h1>Vault Exporter</h1>
             <p><a href='` + *metricsPath + `'>Metrics</a></p>
             <h2>Build</h2>
             <pre>` + version.Info() + ` ` + version.BuildContext() + `</pre>
             </body>
             </html>`))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})
	return h
}

func main() {
	err := mainE()
	if err != nil {
		panic(microerror.JSON(err))
	}
}

func mainE() error {
	if (len(os.Args) > 1) && (os.Args[1] == "version") {
		version.Print("vault_exporter")
		return nil
	}

	log.AddFlags(kingpin.CommandLine)
	kingpin.Version(version.Print("vault_exporter"))
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()

	// kingpin's .Bool with .Default("true") doesn't work as expected, so we parse the value ourselves
	tlsEnableParsed, err := strconv.ParseBool(*tlsEnable)
	if err != nil {
		log.Fatalln("parsing tlsEnable value failed: " + *tlsEnable)
	}

	tlsPreferServerCipherSuitesParsed, err := strconv.ParseBool(*tlsPreferServerCipherSuites)
	if err != nil {
		log.Fatalln("parsing tlsPreferServerCipherSuites value failed: " + *tlsPreferServerCipherSuites)
	}

	var tlsConfig = &tlsCliConfig{
		CertFile:                 *tlsCertFile,
		KeyFile:                  *tlsKeyFile,
		MinVersion:               *tlsMinVer,
		MaxVersion:               *tlsMaxVer,
		CipherSuites:             *tlsCipherSuites,
		CurvePreferences:         *tlsCurves,
		Enable:                   tlsEnableParsed,
		PreferServerCipherSuites: tlsPreferServerCipherSuitesParsed,
	}

	log.Infoln("Starting vault_exporter", version.Info())
	log.Infoln("Build context", version.BuildContext())
	log.Infoln(fmt.Sprintf("TLS config %#v", tlsConfig))

	exporter, err := NewExporter()
	if err != nil {
		return microerror.Mask(err)
	}

	prometheus.MustRegister(exporter)

	rootHandler := rootReqHandler()
	metricsHandler := promhttp.Handler()

	authenticator, err := basicAuthProvider()
	if err != nil {
		return microerror.Mask(err)
	}

	if !tlsEnableParsed && authenticator != nil {
		log.Errorln("authentication is enabled, but TLS is not. Don't do this in production, mate.")
	}

	if authenticator != nil {
		authHttpHandler := func(inner http.Handler) http.Handler {
			h := authenticator.Wrap(func(w http.ResponseWriter, r *auth.AuthenticatedRequest) {
				inner.ServeHTTP(w, &r.Request)
			})
			return h
		}
		metricsHandler = authHttpHandler(metricsHandler)
		rootHandler = authHttpHandler(rootHandler)
	}

	http.Handle(*metricsPath, metricsHandler)
	http.Handle("/", rootHandler)

	log.Infoln("Listening on", *listenAddress)

	err = listen(*listenAddress, tlsConfig)
	if err != nil {
		return microerror.Mask(err)
	}

	return nil
}
