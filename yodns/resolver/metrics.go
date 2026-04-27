package resolver

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/DNS-MSMT-INET/yodns/resolver/model"
	"reflect"
	"strconv"
)

type MetricsDef struct {
	QueryResponses   *prometheus.CounterVec
	QueriesSent      prometheus.Counter
	ResolutionTime   prometheus.Histogram
	ResponseQueueLen prometheus.Gauge
}

var Metrics = MetricsDef{
	QueryResponses: prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "resolver_query_responses",
		Help: "The total number of query responses received in the retrying client.",
	}, []string{"rcode", "truncated", "hasErr", "isFinal"}),
	QueriesSent: prometheus.NewCounter(prometheus.CounterOpts{
		Name: "resolver_query_sent",
		Help: "The total number of queries sent by the retrying client.",
	}),
	ResolutionTime: prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "resolver_resolution_time",
		Help:    "Runtime of a domain name resolution",
		Buckets: prometheus.ExponentialBucketsRange(1, 60000, 8), //nolint:gomnd
	}),

	// Only for debugging purposes, needs to be uncommented in code
	ResponseQueueLen: prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "resolver_response_queue_len",
		Help: "Length of the response queue",
	}),
}

func RegisterMetrics(reg prometheus.Registerer) {
	val := reflect.ValueOf(Metrics)
	for i := 0; i < val.NumField(); i++ {
		field := val.Field(i)
		reg.MustRegister(field.Interface().(prometheus.Collector))
	}
}

func (m *MetricsDef) TrackResponse(msgEx model.MessageExchange, stop bool) {
	rCode := 0
	truncated := false

	if msgEx.Error != nil {
		rCode = -1
	}
	if msgEx.Message != nil {
		truncated = msgEx.Message.Truncated
		rCode = msgEx.Message.Rcode
	}

	m.QueryResponses.With(prometheus.Labels{
		"rcode":     strconv.Itoa(rCode),
		"truncated": strconv.FormatBool(truncated),
		"isFinal":   strconv.FormatBool(stop),
		"hasErr":    strconv.FormatBool(msgEx.Error != nil),
	}).Inc()
}
