package ginprometheus

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/samber/lo"
	log "github.com/sirupsen/logrus"
)

const (
	defaultNamespace  = "http"
	defaultMetricPath = "/metrics"
)

/*
RequestUrlGetter is a function which can be supplied to the middleware to control
the URL label in the prometheus metrics. By default, the full URL is used. This function can be
used to redact sensitive information from the URL. For example, you could use this function to
replace all instances of an ID with the string ":id". This function is called once per request.
*/
type RequestUrlGetter func(c *gin.Context) string

// Metric is a definition for the name, description, type, ID, and
// prometheus.Collector type (i.e. CounterVec, Summary, etc) of each metric
type Metric struct {
	MetricCollector prometheus.Collector
	Name            string
	Description     string
	Type            MetricType
	Args            []string
	Bucket          []float64
}

// Prometheus contains the metrics gathered by the instance and its path
type Prometheus struct {
	namespace                 string
	subsystem                 string
	requestCount              *prometheus.CounterVec
	requestDurationSeconds    *prometheus.HistogramVec
	requestSize, responseSize *prometheus.SummaryVec
	inFlightRequestsCount    *prometheus.GaugeVec
	router                    *gin.Engine
	listenAddress             string
	Ppg                       PrometheusPushGateway
	metricsList               []*Metric
	metricsPath               string
	requestUrlGetter          RequestUrlGetter
	excludedPaths              []string
}

// PrometheusPushGateway contains the configuration for pushing to a Prometheus pushgateway (optional)
type PrometheusPushGateway struct {

	// Push interval in seconds
	PushInterval time.Duration

	// Push Gateway URL in format http://domain:port
	// where JOBNAME can be any string of your choice
	PushGatewayURL string

	// Local metrics URL where metrics are fetched from, this could be ommited in the future
	// if implemented using prometheus common/expfmt instead
	MetricsURL string

	// pushgateway job name, defaults to "gin"
	Job string
}

// NewPrometheus generates a new set of metrics
func NewPrometheus(opts ...Options) *Prometheus {

	var metricsList = make([]*Metric, len(standardMetrics))
	copy(metricsList, standardMetrics)

	p := &Prometheus{
		namespace:   defaultNamespace,
		metricsList: metricsList,
		metricsPath: defaultMetricPath,
		requestUrlGetter: func(c *gin.Context) string {
			return c.FullPath()
		},
		excludedPaths: []string{defaultMetricPath},
	}

	for _, opt := range opts {
		opt.apply(p)
	}

	p.registerMetrics(p.namespace, p.subsystem)

	return p
}

// SetPushGateway sends metrics to a remote pushgateway exposed on pushGatewayURL
// every pushIntervalSeconds. Metrics are fetched from metricsURL
func (p *Prometheus) SetPushGateway(pushGatewayURL, metricsURL string, pushInterval time.Duration) {
	p.Ppg.PushGatewayURL = pushGatewayURL
	p.Ppg.MetricsURL = metricsURL
	p.Ppg.PushInterval = pushInterval
	p.startPushTicker()
}

// SetPushGatewayJob job name, defaults to "gin"
func (p *Prometheus) SetPushGatewayJob(j string) {
	p.Ppg.Job = j
}

// SetListenAddress for exposing metrics on address. If not set, it will be exposed at the
// same address of the gin engine that is being used
func (p *Prometheus) SetListenAddress(address string) {
	p.listenAddress = address
	if p.listenAddress != "" {
		p.router = gin.Default()
	}
}

// SetListenAddressWithRouter for using a separate router to expose metrics. (this keeps things like GET /metrics out of
// your content's access log).
func (p *Prometheus) SetListenAddressWithRouter(listenAddress string, r *gin.Engine) {
	p.listenAddress = listenAddress
	if len(p.listenAddress) > 0 {
		p.router = r
	}
}

// SetMetricsPath set metrics paths
func (p *Prometheus) SetMetricsPath(e *gin.Engine) {

	if p.listenAddress != "" {
		p.router.GET(p.metricsPath, prometheusHandler())
		p.runServer()
	} else {
		e.GET(p.metricsPath, prometheusHandler())
	}
}

// SetMetricsPathWithAuth set metrics paths with authentication
func (p *Prometheus) SetMetricsPathWithAuth(e *gin.Engine, accounts gin.Accounts) {

	if p.listenAddress != "" {
		p.router.GET(p.metricsPath, gin.BasicAuth(accounts), prometheusHandler())
		p.runServer()
	} else {
		e.GET(p.metricsPath, gin.BasicAuth(accounts), prometheusHandler())
	}

}

func (p *Prometheus) runServer() {
	if p.listenAddress != "" {
		go p.router.Run(p.listenAddress)
	}
}

func (p *Prometheus) getMetrics() []byte {
	response, err := http.Get(p.Ppg.MetricsURL)
	if err != nil {
		log.WithError(err).Errorln("Error fetching metrics")
		return nil
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		log.WithError(err).Errorln("Error reading response body")
		return nil
	}

	defer response.Body.Close()

	return body
}

func (p *Prometheus) getPushGatewayURL() string {
	h, _ := os.Hostname()
	if p.Ppg.Job == "" {
		p.Ppg.Job = "gin"
	}
	return p.Ppg.PushGatewayURL + "/metrics/job/" + url.PathEscape(p.Ppg.Job) + "/instance/" + url.PathEscape(h)
}

func (p *Prometheus) sendMetricsToPushGateway(metrics []byte) {
	req, err := http.NewRequest("POST", p.getPushGatewayURL(), bytes.NewBuffer(metrics))
	if err != nil {
		log.WithError(err).Errorln("Error creating request to push gateway")
		return
	}
	client := &http.Client{}
	if _, err = client.Do(req); err != nil {
		log.WithError(err).Errorln("Error sending to push gateway")
	}
}

func (p *Prometheus) startPushTicker() {
	ticker := time.NewTicker(time.Second * p.Ppg.PushInterval)
	go func() {
		for range ticker.C {
			p.sendMetricsToPushGateway(p.getMetrics())
		}
	}()
}

// NewMetric associates prometheus.Collector based on Metric.Type
func NewMetric(m *Metric, namespace, subsystem string) prometheus.Collector {
	var metric prometheus.Collector
	switch m.Type {
	case CounterVec:
		metric = prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      m.Name,
				Help:      m.Description,
			},
			m.Args,
		)
	case Counter:
		metric = prometheus.NewCounter(
			prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      m.Name,
				Help:      m.Description,
			},
		)
	case GaugeVec:
		metric = prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      m.Name,
				Help:      m.Description,
			},
			m.Args,
		)
	case Gauge:
		metric = prometheus.NewGauge(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      m.Name,
				Help:      m.Description,
			},
		)
	case HistogramVec:
		if m.Bucket == nil {
			m.Bucket = prometheus.DefBuckets
		}
		metric = prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      m.Name,
				Help:      m.Description,
				Buckets:   m.Bucket,
			},
			m.Args,
		)
	case Histogram:
		if m.Bucket == nil {
			m.Bucket = prometheus.DefBuckets
		}

		metric = prometheus.NewHistogram(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      m.Name,
				Help:      m.Description,
				Buckets:   m.Bucket,
			},
		)
	case SummaryVec:
		metric = prometheus.NewSummaryVec(
			prometheus.SummaryOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      m.Name,
				Help:      m.Description,
			},
			m.Args,
		)
	case Summary:
		metric = prometheus.NewSummary(
			prometheus.SummaryOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      m.Name,
				Help:      m.Description,
			},
		)
	}
	return metric
}

func (p *Prometheus) registerMetrics(namespace, subsystem string) {

	for _, metricDef := range p.metricsList {
		metric := NewMetric(metricDef, namespace, subsystem)
		if err := prometheus.Register(metric); err != nil {
			log.WithError(err).Errorf("%s could not be registered in Prometheus", metricDef.Name)
		}
		switch metricDef.Name {
		case requestCount.Name:
			p.requestCount = metric.(*prometheus.CounterVec)
		case requestDurationSeconds.Name:
			p.requestDurationSeconds = metric.(*prometheus.HistogramVec)
		case responseSizeBytes.Name:
			p.responseSize = metric.(*prometheus.SummaryVec)
		case requestSizeBytes.Name:
			p.requestSize = metric.(*prometheus.SummaryVec)
		case inFlightRequestsCount.Name:
			p.inFlightRequestsCount = metric.(*prometheus.GaugeVec)
		}
		metricDef.MetricCollector = metric
	}
}

// Use adds the middleware to a gin engine.
func (p *Prometheus) Use(e *gin.Engine) {
	e.Use(p.HandlerFunc())
	p.SetMetricsPath(e)
}

// UseWithAuth adds the middleware to a gin engine with BasicAuth.
func (p *Prometheus) UseWithAuth(e *gin.Engine, accounts gin.Accounts) {
	e.Use(p.HandlerFunc())
	p.SetMetricsPathWithAuth(e, accounts)
}

// HandlerFunc defines handler function for middleware
func (p *Prometheus) HandlerFunc() gin.HandlerFunc {
	return func(c *gin.Context) {
		if lo.Contains(p.excludedPaths, c.Request.URL.Path) {
			c.Next()
			return
		}

		start := time.Now()
		reqSz := computeApproximateRequestSize(c.Request)
		url := p.requestUrlGetter(c)
		p.inFlightRequestsCount.WithLabelValues(c.Request.Method, url).Inc()
		c.Next()
		p.inFlightRequestsCount.WithLabelValues(c.Request.Method, url).Dec()
		status := strconv.Itoa(c.Writer.Status())
		elapsed := time.Since(start).Seconds()
		resSz := c.Writer.Size()
		p.requestDurationSeconds.WithLabelValues(status, c.Request.Method, url).Observe(elapsed)
		p.requestCount.WithLabelValues(status, c.Request.Method, url).Inc()
		p.requestSize.WithLabelValues(status, c.Request.Method, url).Observe(float64(reqSz))
		p.responseSize.WithLabelValues(status, c.Request.Method, url).Observe(float64(resSz))
	}
}

func prometheusHandler() gin.HandlerFunc {
	h := promhttp.Handler()
	return func(c *gin.Context) {
		h.ServeHTTP(c.Writer, c.Request)
	}
}

// From https://github.com/DanielHeckrath/gin-prometheus/blob/master/gin_prometheus.go
func computeApproximateRequestSize(r *http.Request) int {
	s := 0
	if r.URL != nil {
		s = len(r.URL.Path)
	}

	s += len(r.Method)
	s += len(r.Proto)
	for name, values := range r.Header {
		s += len(name)
		for _, value := range values {
			s += len(value)
		}
	}
	s += len(r.Host)

	// N.B. r.Form and r.MultipartForm are assumed to be included in r.URL.

	if r.ContentLength != -1 {
		s += int(r.ContentLength)
	}
	return s
}
