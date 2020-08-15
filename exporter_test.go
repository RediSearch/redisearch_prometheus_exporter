package main

/*
  to run the tests with redis running on anything but localhost:6379 use
  $ go test   --redis.addr=<host>:<port>

  for html coverage report run
  $ go test -coverprofile=coverage.out  && go tool cover -html=coverage.out
*/

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
)

const (
	TestValue   = 1234.56
	TimeToSleep = 200
)

var (
	keys         []string
	keysExpiring []string
	listKeys     []string
	ts           = int32(time.Now().Unix())
)

func getTestExporter() *Exporter {
	e, _ := NewRediSearchExporter(os.Getenv("TEST_REDIS_URI"), ExporterOptions{Namespace: "test", Registry: prometheus.NewRegistry()})
	return e
}

func downloadURL(t *testing.T, url string) string {
	log.Debugf("downloadURL() %s", url)
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func init() {
	ll := strings.ToLower(os.Getenv("LOG_LEVEL"))
	if pl, err := log.ParseLevel(ll); err == nil {
		log.Printf("Setting log level to: %s", ll)
		log.SetLevel(pl)
	} else {
		log.SetLevel(log.InfoLevel)
	}

	for _, n := range []string{"john", "paul", "ringo", "george"} {
		key := fmt.Sprintf("key_%s_%d", n, ts)
		keys = append(keys, key)
	}

	listKeys = append(listKeys, "beatles_list")

	for _, n := range []string{"A.J.", "Howie", "Nick", "Kevin", "Brian"} {
		key := fmt.Sprintf("key_exp_%s_%d", n, ts)
		keysExpiring = append(keysExpiring, key)
	}
}

func TestExporter_scrapeRedisHost(t *testing.T) {
	type fields struct {
		Mutex                     sync.Mutex
		redisAddr                 string
		namespace                 string
		totalScrapes              prometheus.Counter
		scrapeDuration            prometheus.Summary
		targetScrapeRequestErrors prometheus.Counter
		metricDescriptions        map[string]*prometheus.Desc
		options                   ExporterOptions
		metricMapCounters         map[string]string
		metricMapGauges           map[string]string
		mux                       *http.ServeMux
	}
	type args struct {
		ch chan<- prometheus.Metric
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &Exporter{
				Mutex:                     tt.fields.Mutex,
				redisAddr:                 tt.fields.redisAddr,
				namespace:                 tt.fields.namespace,
				totalScrapes:              tt.fields.totalScrapes,
				scrapeDuration:            tt.fields.scrapeDuration,
				targetScrapeRequestErrors: tt.fields.targetScrapeRequestErrors,
				metricDescriptions:        tt.fields.metricDescriptions,
				options:                   tt.fields.options,
				metricMapCounters:         tt.fields.metricMapCounters,
				metricMapGauges:           tt.fields.metricMapGauges,
				mux:                       tt.fields.mux,
			}
			if err := e.scrapeRedisHost(tt.args.ch); (err != nil) != tt.wantErr {
				t.Errorf("scrapeRedisHost() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
