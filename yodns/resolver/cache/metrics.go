package cache

import (
	"github.com/prometheus/client_golang/prometheus"
	"reflect"
)

var Metrics = struct {
	Hits    prometheus.Counter
	Discard prometheus.Counter
	Misses  prometheus.Counter
	Size    prometheus.Gauge

	InfraSize     prometheus.Gauge
	InfraBackoffs prometheus.Histogram
}{
	Discard: prometheus.NewCounter(prometheus.CounterOpts{
		Name: "dns_cache_discard",
		Help: "The total number messages that the cache refused to cache",
	}),
	Hits: prometheus.NewCounter(prometheus.CounterOpts{
		Name: "dns_cache_hits",
		Help: "The total number of dns cache hits",
	}),
	Misses: prometheus.NewCounter(prometheus.CounterOpts{
		Name: "dns_cache_misses",
		Help: "The total number of dns cache misses",
	}),
	Size: prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "dns_cache_size",
		Help: "The total number of items in the dns cache",
	}),
	InfraSize: prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "infra_cache_size",
		Help: "The total number of items in the infrastructure cache",
	}),
	InfraBackoffs: prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "infra_cache_backoff_duration_seconds",
		Help:    "Histogram of the backoff durations suggested by the infrastructure cache",
		Buckets: prometheus.ExponentialBucketsRange(1, 100, 20),
	}),
}

func RegisterMetrics(reg prometheus.Registerer) {
	val := reflect.ValueOf(Metrics)
	for i := 0; i < val.NumField(); i++ {
		field := val.Field(i)
		reg.MustRegister(field.Interface().(prometheus.Collector))
	}
}
