package main

import (
	"crypto/tls"
	"flag"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
)

var (
	// BuildVersion, BuildDate, BuildCommitSha are filled in by the build script
	BuildVersion   = "<<< filled in by build >>>"
	BuildDate      = "<<< filled in by build >>>"
	BuildCommitSha = "<<< filled in by build >>>"
)

func getEnv(key string, defaultVal string) string {
	if envVal, ok := os.LookupEnv(key); ok {
		return envVal
	}
	return defaultVal
}

func getEnvBool(key string) (res bool) {
	if envVal, ok := os.LookupEnv(key); ok {
		res, _ = strconv.ParseBool(envVal)
	}
	return res
}

func main() {
	var (
		redisAddr               = flag.String("redis.addr", getEnv("REDISEARCH_ADDR", "redis://localhost:6379"), "Address of the Redis instance to scrape")
		redisPwd                = flag.String("redis.password", getEnv("REDISEARCH_PASSWORD", ""), "Password of the Redis instance to scrape")
		namespace               = flag.String("namespace", getEnv("REDISEARCH_EXPORTER_NAMESPACE", "redisearch"), "Namespace for metrics")
		listenAddress           = flag.String("web.listen-address", getEnv("REDISEARCH_EXPORTER_WEB_LISTEN_ADDRESS", ":9122"), "Address to listen on for web interface and telemetry.")
		metricPath              = flag.String("web.telemetry-path", getEnv("REDISEARCH_EXPORTER_WEB_TELEMETRY_PATH", "/metrics"), "Path under which to expose metrics.")
		logFormat               = flag.String("log-format", getEnv("REDISEARCH_EXPORTER_LOG_FORMAT", "txt"), "Log format, valid options are txt and json")
		connectionTimeout       = flag.String("connection-timeout", getEnv("REDISEARCH_EXPORTER_CONNECTION_TIMEOUT", "1s"), "Timeout for connection to Redis instance")
		tlsClientKeyFile        = flag.String("tls-client-key-file", getEnv("REDISEARCH_EXPORTER_TLS_CLIENT_KEY_FILE", ""), "Name of the client key file (including full path) if the server requires TLS client authentication")
		tlsClientCertFile       = flag.String("tls-client-cert-file", getEnv("REDISEARCH_EXPORTER_TLS_CLIENT_CERT_FILE", ""), "Name of the client certificate file (including full path) if the server requires TLS client authentication")
		isDebug                 = flag.Bool("debug", getEnvBool("REDISEARCH_EXPORTER_DEBUG"), "Output verbose debug information")
		discoverIndicesWithScan = flag.Bool("discover-with-scan", getEnvBool("REDISEARCH_EXPORTER_DISCOVER_WITH_SCAN"), "Whether to use scan idx:* to discover indexes. This has TREMENDOUSLY NEGATIVE PERFORMANCE IMPACT.")
		staticIndexList         = flag.String("static-index-list", getEnv("REDISEARCH_EXPORTER_STATIC_INDEX_LIST", ""), "Use a static index list passed in a comma separated way")
		showVersion             = flag.Bool("version", false, "Show version information and exit")
		skipTLSVerification     = flag.Bool("skip-tls-verification", getEnvBool("REDISEARCH_EXPORTER_SKIP_TLS_VERIFICATION"), "Whether to to skip TLS verification")
	)
	flag.Parse()

	switch *logFormat {
	case "json":
		log.SetFormatter(&log.JSONFormatter{})
	default:
		log.SetFormatter(&log.TextFormatter{})
	}
	log.Printf("RediSearch Metrics Exporter %s    build date: %s    sha1: %s    Go: %s    GOOS: %s    GOARCH: %s",
		BuildVersion, BuildDate, BuildCommitSha,
		runtime.Version(),
		runtime.GOOS,
		runtime.GOARCH,
	)
	if *isDebug {
		log.SetLevel(log.DebugLevel)
		log.Debugln("Enabling debug output")
	} else {
		log.SetLevel(log.InfoLevel)
	}

	if *showVersion {
		return
	}

	to, err := time.ParseDuration(*connectionTimeout)
	if err != nil {
		log.Fatalf("Couldn't parse connection timeout duration, err: %s", err)
	}

	var tlsClientCertificates []tls.Certificate
	if (*tlsClientKeyFile != "") != (*tlsClientCertFile != "") {
		log.Fatal("TLS client key file and cert file should both be present")
	}
	if *tlsClientKeyFile != "" && *tlsClientCertFile != "" {
		cert, err := tls.LoadX509KeyPair(*tlsClientCertFile, *tlsClientKeyFile)
		if err != nil {
			log.Fatalf("Couldn't load TLS client key pair, err: %s", err)
		}
		tlsClientCertificates = append(tlsClientCertificates, cert)
	}

	registry := prometheus.NewRegistry()

	exp, err := NewRediSearchExporter(
		*redisAddr,
		ExporterOptions{
			Password:                *redisPwd,
			Namespace:               *namespace,
			SkipTLSVerification:     *skipTLSVerification,
			ClientCertificates:      tlsClientCertificates,
			ConnectionTimeouts:      to,
			MetricsPath:             *metricPath,
			Registry:                registry,
			DiscoverIndicesWithScan: *discoverIndicesWithScan,
			StaticIndicesList:       strings.Split(*staticIndexList, ","),
		},
	)
	if err != nil {
		log.Fatal(err)
	}

	log.Infof("Providing metrics at %s%s", *listenAddress, *metricPath)
	log.Debugf("Configured redis addr: %#v", *redisAddr)
	log.Fatal(http.ListenAndServe(*listenAddress, exp))
}
