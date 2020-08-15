package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/RediSearch/redisearch-go/redisearch"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/gomodule/redigo/redis"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	promstrutil "github.com/prometheus/prometheus/util/strutil"
	log "github.com/sirupsen/logrus"
)

type dbKeyPair struct {
	db, key string
}

// Exporter implements the prometheus.Exporter interface, and exports Redis metrics.
type Exporter struct {
	sync.Mutex
	redisAddr string
	namespace string

	totalScrapes              prometheus.Counter
	scrapeDuration            prometheus.Summary
	targetScrapeRequestErrors prometheus.Counter

	metricDescriptions map[string]*prometheus.Desc

	options ExporterOptions

	metricMapCounters map[string]string
	metricMapGauges   map[string]string

	mux *http.ServeMux
}

type ExporterOptions struct {
	Password                string
	Namespace               string
	ClientCertificates      []tls.Certificate
	SkipTLSVerification     bool
	ConnectionTimeouts      time.Duration
	MetricsPath             string
	DiscoverIndicesWithScan bool
	Registry                *prometheus.Registry
	StaticIndicesList       []string
}

func (e *Exporter) ScrapeHandler(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	if target == "" {
		http.Error(w, "'target' parameter must be specified", 400)
		e.targetScrapeRequestErrors.Inc()
		return
	}

	if !strings.Contains(target, "://") {
		target = "redis://" + target
	}

	u, err := url.Parse(target)
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid 'target' parameter, parse err: %ck ", err), 400)
		e.targetScrapeRequestErrors.Inc()
		return
	}

	// get rid of username/password info in "target" so users don't send them in plain text via http
	u.User = nil
	target = u.String()

	opts := e.options

	registry := prometheus.NewRegistry()
	opts.Registry = registry

	_, err = NewRediSearchExporter(target, opts)
	if err != nil {
		http.Error(w, "NewRediSearchExporter() err: err", 400)
		e.targetScrapeRequestErrors.Inc()
		return
	}

	promhttp.HandlerFor(
		registry, promhttp.HandlerOpts{ErrorHandling: promhttp.ContinueOnError},
	).ServeHTTP(w, r)
}

func newMetricDescr(namespace string, metricName string, docString string, labels []string) *prometheus.Desc {
	return prometheus.NewDesc(prometheus.BuildFQName(namespace, "", metricName), docString, labels, nil)
}

// NewRediSearchExporter returns a new exporter of Redis metrics.
func NewRediSearchExporter(redisURI string, opts ExporterOptions) (*Exporter, error) {
	e := &Exporter{
		redisAddr: redisURI,
		options:   opts,
		namespace: opts.Namespace,

		totalScrapes: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: opts.Namespace,
			Name:      "exporter_scrapes_total",
			Help:      "Current total redis scrapes.",
		}),

		scrapeDuration: prometheus.NewSummary(prometheus.SummaryOpts{
			Namespace: opts.Namespace,
			Name:      "exporter_scrape_duration_seconds",
			Help:      "Duration of scrape by the exporter",
		}),

		targetScrapeRequestErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: opts.Namespace,
			Name:      "target_scrape_request_errors_total",
			Help:      "Errors in requests to the exporter",
		}),

		metricMapGauges: map[string]string{
			// # Memory

		},

		metricMapCounters: map[string]string{},
	}

	e.metricDescriptions = map[string]*prometheus.Desc{}

	for k, desc := range getRediSearchMetrics() {
		e.metricDescriptions[k] = newMetricDescr(opts.Namespace, k, desc.txt, desc.lbls)
	}

	if e.options.MetricsPath == "" {
		e.options.MetricsPath = "/metrics"
	}

	e.mux = http.NewServeMux()

	if e.options.Registry != nil {
		e.options.Registry.MustRegister(e)
		e.mux.Handle(e.options.MetricsPath, promhttp.HandlerFor(
			e.options.Registry, promhttp.HandlerOpts{ErrorHandling: promhttp.ContinueOnError},
		))
	}

	e.mux.HandleFunc("/scrape", e.ScrapeHandler)
	e.mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`ok`))
	})
	e.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>
<head><title>RediSearch Exporter ` + BuildVersion + `</title></head>
<body>
<h1>RediSearch Exporter ` + BuildVersion + `</h1>
<p><a href='` + opts.MetricsPath + `'>Metrics</a></p>
</body>
</html>
`))
	})

	return e, nil
}

func getRediSearchMetrics() map[string]struct {
	txt  string
	lbls []string
} {
	return map[string]struct {
		txt  string
		lbls []string
	}{
		"num_docs":    {txt: "Number of documents by Index", lbls: []string{"idx"}},
		"max_doc_id":  {txt: "Max Doc ID by Index", lbls: []string{"idx"}},
		"num_terms":   {txt: "Number of distinct terms by Index", lbls: []string{"idx"}},
		"num_records": {txt: "Number of records by Index", lbls: []string{"idx"}},

		"inverted_size_bytes":         {txt: "Inverted Size in Bytes by Index", lbls: []string{"idx"}},
		"total_inverted_index_blocks": {txt: "Total Inverted Index Blocks", lbls: []string{}},
		"offset_vectors_size_bytes":   {txt: "OffSet Vectors Size in Bytes by Index", lbls: []string{"idx"}},
		"doc_table_size_bytes":        {txt: "Doc Table Size in Bytes by Index", lbls: []string{"idx"}},
		"sortable_values_size_bytes":  {txt: "Sortable Values Size in Bytes by Index", lbls: []string{"idx"}},
		"key_table_size_bytes":        {txt: "Key Table Size in Bytes by Index", lbls: []string{"idx"}},
		"records_per_doc_avg":         {txt: "Average Records per document by Index", lbls: []string{"idx"}},
		"bytes_per_record_avg":        {txt: "Average Bytes Per Record by Index", lbls: []string{"idx"}},
		"offsets_per_term_avg":        {txt: "Average OffSets Per Term by Index", lbls: []string{"idx"}},
		"offset_bits_per_record_avg":  {txt: "Average OffSets Bits Per Record by Index", lbls: []string{"idx"}},
		"inverted_cap_size_bytes":     {txt: "Inverted Capacity Size by Index", lbls: []string{"idx"}},
		"inverted_cap_ovh":            {txt: "Inverted Capacity Ovh by Index", lbls: []string{"idx"}},

		//GC
		"gc_stats_bytes_collected":         {txt: "GC Bytes Collected by Index", lbls: []string{"idx"}},
		"gc_stats_total_ms_run":            {txt: "GC Total Time (ms) by Index", lbls: []string{"idx"}},
		"gc_stats_total_cycles":            {txt: "GC Total Cycles by Index", lbls: []string{"idx"}},
		"gc_stats_avarage_cycle_time_ms":   {txt: "GC Average Cycle Time (ms) by Index", lbls: []string{"idx"}},
		"gc_stats_last_run_time_ms":        {txt: "GC Last Run Time (ms) by Index", lbls: []string{"idx"}},
		"gc_stats_gc_numeric_trees_missed": {txt: "GC numeric trees missed by Index", lbls: []string{"idx"}},
		"gc_stats_gc_blocks_denied":        {txt: "GC Blocks denied by Index", lbls: []string{"idx"}},

		//CursorStats
		"cursor_stats_global_idle":    {txt: "Cursor Global Total Idle", lbls: []string{}},
		"cursor_stats_global_total":   {txt: "Cursor Global Total", lbls: []string{}},
		"cursor_stats_index_capacity": {txt: "Cursor Capacity by Index", lbls: []string{"idx"}},
		"cursor_stats_index_total":    {txt: "Cursor Total by Index", lbls: []string{"idx"}},
	}
}

func (e *Exporter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	e.mux.ServeHTTP(w, r)
}

// Describe outputs Redis metric descriptions.
func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {
	for _, desc := range e.metricDescriptions {
		ch <- desc
	}

	for _, v := range e.metricMapGauges {
		ch <- newMetricDescr(e.options.Namespace, v, v+" metric", nil)
	}

	for _, v := range e.metricMapCounters {
		ch <- newMetricDescr(e.options.Namespace, v, v+" metric", nil)
	}

	ch <- e.totalScrapes.Desc()
	ch <- e.scrapeDuration.Desc()
	ch <- e.targetScrapeRequestErrors.Desc()
}

// Collect fetches new metrics from the RedisHost and updates the appropriate metrics.
func (e *Exporter) Collect(ch chan<- prometheus.Metric) {
	e.Lock()
	defer e.Unlock()
	e.totalScrapes.Inc()

	if e.redisAddr != "" {
		start := time.Now().UnixNano()
		var up float64 = 1
		if err := e.scrapeRedisHost(ch); err != nil {
			up = 0
			e.registerConstMetricGauge(ch, "exporter_last_scrape_error", 1.0, fmt.Sprintf("%s", err))
		} else {
			e.registerConstMetricGauge(ch, "exporter_last_scrape_error", 0, "")
		}

		e.registerConstMetricGauge(ch, "up", up)
		e.registerConstMetricGauge(ch, "exporter_last_scrape_duration_seconds", float64(time.Now().UnixNano()-start)/1000000000)
	}

	ch <- e.totalScrapes
	ch <- e.scrapeDuration
	ch <- e.targetScrapeRequestErrors
}

func (e *Exporter) includeMetric(s string) bool {
	if strings.HasPrefix(s, "db") || strings.HasPrefix(s, "cmdstat_") || strings.HasPrefix(s, "cluster_") {
		return true
	}
	if _, ok := e.metricMapGauges[s]; ok {
		return true
	}

	_, ok := e.metricMapCounters[s]
	return ok
}

func sanitizeMetricName(n string) string {
	return promstrutil.SanitizeLabelName(n)
}

func (e *Exporter) registerConstMetricGauge(ch chan<- prometheus.Metric, metric string, val float64, labels ...string) {
	e.registerConstMetric(ch, metric, val, prometheus.GaugeValue, labels...)
}

func (e *Exporter) registerConstMetric(ch chan<- prometheus.Metric, metric string, val float64, valType prometheus.ValueType, labelValues ...string) {
	descr := e.metricDescriptions[metric]
	if descr == nil {
		descr = newMetricDescr(e.options.Namespace, metric, metric+" metric", nil)
	}

	if m, err := prometheus.NewConstMetric(descr, valType, val, labelValues...); err == nil {
		ch <- m
	} else {
		log.Debugf("NewConstMetric() err: %s", err)
	}
}

func doRedisCmd(c redis.Conn, cmd string, args ...interface{}) (reply interface{}, err error) {
	log.Debugf("c.Do() - running command: %s %s", cmd, args)
	defer log.Debugf("c.Do() - done")
	res, err := c.Do(cmd, args...)
	if err != nil {
		log.Debugf("c.Do() - err: %s", err)
	}
	return res, err
}

func (e *Exporter) connectToRedis() (redis.Conn, error) {
	options := []redis.DialOption{
		redis.DialConnectTimeout(e.options.ConnectionTimeouts),
		redis.DialReadTimeout(e.options.ConnectionTimeouts),
		redis.DialWriteTimeout(e.options.ConnectionTimeouts),

		redis.DialTLSConfig(&tls.Config{
			InsecureSkipVerify: e.options.SkipTLSVerification,
			Certificates:       e.options.ClientCertificates,
		}),
	}

	if e.options.Password != "" {
		options = append(options, redis.DialPassword(e.options.Password))
	}

	uri := e.redisAddr
	if !strings.Contains(uri, "://") {
		uri = "redis://" + uri
	}
	log.Debugf("Trying DialURL(): %s", uri)
	c, err := redis.DialURL(uri, options...)
	if err != nil {
		log.Debugf("DialURL() failed, err: %s", err)
		if frags := strings.Split(e.redisAddr, "://"); len(frags) == 2 {
			log.Debugf("Trying: Dial(): %s %s", frags[0], frags[1])
			c, err = redis.Dial(frags[0], frags[1], options...)
		} else {
			log.Debugf("Trying: Dial(): tcp %s", e.redisAddr)
			c, err = redis.Dial("tcp", e.redisAddr, options...)
		}
	}
	return c, err
}

func GetRediSearchIndexes(c redis.Conn, pattern string) ([]string, error) {

	iter := 0
	var keys []string
	for {
		arr, err := redis.Values(c.Do("SCAN", iter, "MATCH", pattern))
		if err != nil {
			return keys, fmt.Errorf("error retrieving '%s' keys", pattern)
		}

		iter, _ = redis.Int(arr[0], nil)
		k, _ := redis.Strings(arr[1], nil)
		for _, kk := range k {
			kk_split := strings.Split(kk, ":")
			if len(kk_split) > 1 {
				keys = append(keys, kk_split[1])
			}
		}

		if iter == 0 {
			break
		}
	}

	return keys, nil
}

// Schema represents an index schema Schema, or how the index would
// treat documents sent to it.
type GCStats struct {
	BytesCollected     uint64  `redis:"bytes_collected"`
	GlobalTotal        uint64  `redis:"total_ms_run"`
	TotalCycles        uint64  `redis:"total_cycles"`
	AverageCycleTimeMs float64 `redis:"avarage_cycle_time_ms"`
	LastRunTimeMs      float64 `redis:"last_run_time_ms"`
	NumericTreesMissed uint64  `redis:"gc_numeric_trees_missed"`
	BlocksDenied       uint64  `redis:"gc_blocks_denied"`
}

func (info *GCStats) setTarget(key string, value interface{}) error {
	v := reflect.ValueOf(info).Elem()
	for i := 0; i < v.NumField(); i++ {
		tag := v.Type().Field(i).Tag.Get("redis")
		if tag == key {
			targetInfo := v.Field(i)
			switch targetInfo.Kind() {
			case reflect.String:
				s, _ := redis.String(value, nil)
				targetInfo.SetString(s)
			case reflect.Uint64:
				u, _ := redis.Uint64(value, nil)
				targetInfo.SetUint(u)
			case reflect.Float64:
				f, _ := redis.Float64(value, nil)
				targetInfo.SetFloat(f)
			default:
				panic("Tag set without handler")
			}
			return nil
		}
	}
	return errors.New("setTarget: No handler defined for :" + key)
}

// Schema represents an index schema Schema, or how the index would
// treat documents sent to it.
type CursorStats struct {
	GlobalIdle    uint64 `redis:"global_idle"`
	GlobalTotal   uint64 `redis:"global_total"`
	IndexCapacity uint64 `redis:"index_capacity"`
	IndexTotal    uint64 `redis:"index_total"`
}

func (info *CursorStats) setTarget(key string, value interface{}) error {
	v := reflect.ValueOf(info).Elem()
	for i := 0; i < v.NumField(); i++ {
		tag := v.Type().Field(i).Tag.Get("redis")
		if tag == key {
			targetInfo := v.Field(i)
			switch targetInfo.Kind() {
			case reflect.String:
				s, _ := redis.String(value, nil)
				targetInfo.SetString(s)
			case reflect.Uint64:
				u, _ := redis.Uint64(value, nil)
				targetInfo.SetUint(u)
			case reflect.Float64:
				f, _ := redis.Float64(value, nil)
				targetInfo.SetFloat(f)
			default:
				panic("Tag set without handler")
			}
			return nil
		}
	}
	return errors.New("setTarget: No handler defined for :" + key)
}

// IndexInfo - Structure showing information about an existing index
type IndexInfo struct {
	Schema                      redisearch.Schema
	Name                        string  `redis:"index_name"`
	DocCount                    uint64  `redis:"num_docs"`
	MaxDocID                    uint64  `redis:"max_doc_id"`
	TermCount                   uint64  `redis:"num_terms"`
	RecordCount                 uint64  `redis:"num_records"`
	InvertedIndexSizeMB         float64 `redis:"inverted_sz_mb"`
	InvertedIndexTotalBlocks    float64 `redis:"total_inverted_index_blocks"`
	OffsetVectorSizeMB          float64 `redis:"offset_vector_sz_mb"`
	DocTableSizeMB              float64 `redis:"doc_table_size_mb"`
	SortableValuesSizeMB        float64 `redis:"sortable_values_size_mb"`
	KeyTableSizeMB              float64 `redis:"key_table_size_mb"`
	RecordsPerDocAvg            float64 `redis:"records_per_doc_avg"`
	BytesPerRecordAvg           float64 `redis:"bytes_per_record_avg"`
	OffsetsPerTermAvg           float64 `redis:"offsets_per_term_avg"`
	OffsetBitsPerRecordAvg      float64 `redis:"offset_bits_per_record_avg"`
	InvertedIndexCapacitySizeMB float64 `redis:"inverted_cap_mb"`
	InvertedIndexCapacityOvh    float64 `redis:"inverted_cap_ovh"`
	GCStats                     GCStats
	CursorStats                 CursorStats
}

func (info *IndexInfo) setTarget(key string, value interface{}) error {
	v := reflect.ValueOf(info).Elem()
	for i := 0; i < v.NumField(); i++ {
		tag := v.Type().Field(i).Tag.Get("redis")
		if tag == key {
			targetInfo := v.Field(i)
			switch targetInfo.Kind() {
			case reflect.String:
				s, _ := redis.String(value, nil)
				targetInfo.SetString(s)
			case reflect.Uint64:
				u, _ := redis.Uint64(value, nil)
				targetInfo.SetUint(u)
			case reflect.Float64:
				f, _ := redis.Float64(value, nil)
				targetInfo.SetFloat(f)
			default:
				panic("Tag set without handler")
			}
			return nil
		}
	}
	return errors.New("setTarget: No handler defined for :" + key)
}

func (e *Exporter) scrapeRedisHost(ch chan<- prometheus.Metric) error {
	c, err := e.connectToRedis()
	if err != nil {
		log.Errorf("Couldn't connect to redis instance")
		log.Debugf("connectToRedis( %s ) err: %s", e.redisAddr, err)
		return err
	}
	defer c.Close()

	log.Debugf("connected to: %s", e.redisAddr)

	if _, err := doRedisCmd(c, "CLIENT", "SETNAME", "redisearch_exporter"); err != nil {
		log.Errorf("Couldn't set client name, err: %s", err)
	}
	resM, err := redis.Values(doRedisCmd(c, "MODULE", "LIST"))
	rediSearchPresent := false
	for _, moduleRaw := range resM {
		moduleInfo, _ := redis.Strings(moduleRaw, nil)
		moduleName := moduleInfo[1]
		if moduleName == "ft" {
			rediSearchPresent = true
		}
	}
	if rediSearchPresent {
		var indexes []string = []string{}

		if len(e.options.StaticIndicesList) > 0 {
			indexes = append(indexes, e.options.StaticIndicesList...)
		}

		if e.options.DiscoverIndicesWithScan {
			//Retrive the list of RediSearch Indexes with Scan
			if indexes, err = GetRediSearchIndexes(c, "idx:*"); err != nil {
				log.Errorf("Couldn't Retrive the list of RediSearch Indexes, err: %s", err)
			}
		}

		if len(indexes) == 0 {
			log.Debugf("no RediSearch Indices to scrape")
		}

		for _, indexName := range indexes {
			res, err := redis.Values(doRedisCmd(c, "FT.INFO", indexName))
			ret := IndexInfo{}
			if err != nil {
				log.Errorf("RediSearch FT.INFO err: %s", err)
				return err
			} else {
				// Iterate over the values

				for ii := 0; ii < len(res); ii += 2 {
					key, _ := redis.String(res[ii], nil)
					if err := ret.setTarget(key, res[ii+1]); err == nil {
						continue
					}
					switch key {
					case "gc_stats":
						gcStats, _ := redis.Values(res[ii+1], nil)
						for iii := 0; iii < len(gcStats); iii += 2 {
							key, _ := redis.String(gcStats[iii], nil)
							if err := ret.GCStats.setTarget(key, gcStats[iii+1]); err == nil {
								continue
							}
						}
					case "cursor_stats":
						cursorStats, _ := redis.Values(res[ii+1], nil)
						for iii := 0; iii < len(cursorStats); iii += 2 {
							key, _ := redis.String(cursorStats[iii], nil)
							if err := ret.CursorStats.setTarget(key, cursorStats[iii+1]); err == nil {
								continue
							}
						}

					}
				}

				e.registerConstMetricGauge(ch, "num_docs", float64(ret.DocCount), indexName)
				e.registerConstMetricGauge(ch, "max_doc_id", float64(ret.MaxDocID), indexName)
				e.registerConstMetricGauge(ch, "num_terms", float64(ret.TermCount), indexName)
				e.registerConstMetricGauge(ch, "num_records", float64(ret.RecordCount), indexName)

				e.registerConstMetricGauge(ch, "inverted_size_bytes", ret.InvertedIndexSizeMB*1024*1024, indexName)
				e.registerConstMetricGauge(ch, "total_inverted_index_blocks", ret.InvertedIndexTotalBlocks, indexName)
				e.registerConstMetricGauge(ch, "offset_vectors_size_bytes", ret.OffsetVectorSizeMB*1024*1024, indexName)
				e.registerConstMetricGauge(ch, "doc_table_size_bytes", ret.DocTableSizeMB*1024*1024, indexName)
				e.registerConstMetricGauge(ch, "sortable_values_size_bytes", ret.SortableValuesSizeMB*1024*1024, indexName)
				e.registerConstMetricGauge(ch, "key_table_size_bytes", ret.KeyTableSizeMB*1024*1024, indexName)
				e.registerConstMetricGauge(ch, "records_per_doc_avg", ret.RecordsPerDocAvg, indexName)
				e.registerConstMetricGauge(ch, "bytes_per_record_avg", ret.BytesPerRecordAvg, indexName)
				e.registerConstMetricGauge(ch, "offsets_per_term_avg", ret.OffsetsPerTermAvg, indexName)
				e.registerConstMetricGauge(ch, "offset_bits_per_record_avg", ret.OffsetBitsPerRecordAvg, indexName)
				e.registerConstMetricGauge(ch, "inverted_cap_size_bytes", ret.InvertedIndexCapacitySizeMB*1024*1024, indexName)
				e.registerConstMetricGauge(ch, "inverted_cap_ovh", ret.InvertedIndexCapacityOvh, indexName)

				//GC
				e.registerConstMetricGauge(ch, "gc_stats_bytes_collected", float64(ret.GCStats.BytesCollected), indexName)
				e.registerConstMetricGauge(ch, "gc_stats_total_ms_run", float64(ret.GCStats.GlobalTotal), indexName)
				e.registerConstMetricGauge(ch, "gc_stats_total_cycles", float64(ret.GCStats.TotalCycles), indexName)
				e.registerConstMetricGauge(ch, "gc_stats_avarage_cycle_time_ms", ret.GCStats.AverageCycleTimeMs, indexName)
				e.registerConstMetricGauge(ch, "gc_stats_last_run_time_ms", ret.GCStats.LastRunTimeMs, indexName)
				e.registerConstMetricGauge(ch, "gc_stats_gc_numeric_trees_missed", float64(ret.GCStats.NumericTreesMissed), indexName)
				e.registerConstMetricGauge(ch, "gc_stats_gc_blocks_denied", float64(ret.GCStats.BlocksDenied), indexName)

				//CursorStats
				e.registerConstMetricGauge(ch, "cursor_stats_global_idle", float64(ret.CursorStats.GlobalIdle))
				e.registerConstMetricGauge(ch, "cursor_stats_global_total", float64(ret.CursorStats.GlobalTotal))
				e.registerConstMetricGauge(ch, "cursor_stats_index_capacity", float64(ret.CursorStats.IndexCapacity), indexName)
				e.registerConstMetricGauge(ch, "cursor_stats_index_total", float64(ret.CursorStats.IndexTotal), indexName)
			}
		}
	} else {
		log.Infof("RediSearch Module not present on Redis Host")
	}
	log.Debugf("scrapeRedisHost() done")
	return nil
}
