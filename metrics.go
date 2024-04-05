package ginprometheus

import "github.com/samber/lo"

type MetricType string

const (
	Counter      MetricType = "counter"
	CounterVec   MetricType = "counter_vec"
	Gauge        MetricType = "gauge"
	GaugeVec     MetricType = "gauge_vec"
	Histogram    MetricType = "histogram"
	HistogramVec MetricType = "histogram_vec"
	Summary      MetricType = "summary"
	SummaryVec   MetricType = "summary_vec"
)

const (
	LabelCode    = "code"
	LabelMethod  = "method"
	LabelHandler = "handler"
	LabelUrl     = "url"
)

// Standard default metrics
//
//	counter, counter_vec, gauge, gauge_vec,
//	histogram, histogram_vec, summary, summary_vec
var requestCount = &Metric{
	Name:        "requests_total",
	Description: "How many HTTP requests processed, partitioned by status code and HTTP method.",
	Type:        CounterVec,
	Args:        []string{LabelCode, LabelMethod, LabelHandler, LabelUrl},
}

var requestDurationSeconds = &Metric{
	Name:        "request_duration_seconds",
	Description: "The HTTP request latencies in seconds.",
	Type:        HistogramVec,
	Args:        []string{LabelCode, LabelMethod, LabelUrl},
}

var responseSizeBytes = &Metric{
	Name:        "response_size_bytes",
	Description: "The HTTP response sizes in bytes.",
	Type:        SummaryVec,
	Args:        []string{LabelCode, LabelMethod, LabelUrl},
}

var requestSizeBytes = &Metric{
	Name:        "request_size_bytes",
	Description: "The HTTP request sizes in bytes.",
	Type:        SummaryVec,
	Args:        []string{LabelCode, LabelMethod, LabelUrl},
}

var standardMetrics = []*Metric{
	requestCount,
	requestDurationSeconds,
	responseSizeBytes,
	responseSizeBytes,
}

var standardMetricName = lo.Map(standardMetrics, func(metric *Metric, index int) string {
	return metric.Name
})
