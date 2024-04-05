package ginprometheus

import (
	"github.com/samber/lo"
	log "github.com/sirupsen/logrus"
)

type Options interface {
	apply(p *Prometheus)
}

type funcOptions struct {
	f func(p *Prometheus)
}

func (fo *funcOptions) apply(p *Prometheus) {
	fo.f(p)
}

func newFuncOptions(f func(p *Prometheus)) *funcOptions {
	return &funcOptions{
		f: f,
	}
}

// WithCustomMetrics sets the custom metrics list
func WithCustomMetrics(metricList ...*Metric) Options {
	return newFuncOptions(func(p *Prometheus) {
		for _, metric := range metricList {
			if lo.Contains(standardMetricName, metric.Name) {
				log.Errorf("Custom metric name already exists in standard metrics", "metric", metric.Name)
				continue
			}

			p.metricsList = append(p.metricsList, metric)
		}

	})
}

// WithNamespace sets the namespace
// By default, the namespace is "http"
func WithNamespace(namespace string) Options {
	return newFuncOptions(func(p *Prometheus) {
		p.namespace = namespace
	})
}

// WithSubsystem sets the subsystem
func WithSubsystem(subsystem string) Options {
	return newFuncOptions(func(p *Prometheus) {
		p.subsystem = subsystem
	})
}

// WithMetricsPath sets the metrics path
// By default, the metrics path is "/metrics"
func WithMetricsPath(path string) Options {
	return newFuncOptions(func(p *Prometheus) {
		// Remove the old metrics path from the excluded paths
		p.excludedPaths = lo.Filter(p.excludedPaths, func(s string, index int) bool {
			return s != p.metricsPath
		})

		p.metricsPath = path
		p.excludedPaths = lo.Uniq(append(p.excludedPaths, path))
	})
}

// WithRequestUrlGetter sets a custom request url getter
// By default, the request url is taken from the gin.Context.FullPath()
func WithRequestUrlGetter(f RequestUrlGetter) Options {
	return newFuncOptions(func(p *Prometheus) {
		p.requestUrlGetter = f
	})
}

// WithRequestDurationBuckets sets the buckets for the request duration histogram
func WithRequestDurationBuckets(bucket []float64) Options {
	return newFuncOptions(func(p *Prometheus) {
		for _, metric := range p.metricsList {
			if metric.Name == requestDurationSeconds.Name {
				metric.Bucket = bucket
				break
			}
		}
	})
}

// WithExcludedPaths sets the excluded paths
// By default, the excluded paths are empty
func WithExcludedPaths(paths ...string) Options {
	return newFuncOptions(func(p *Prometheus) {
		paths = lo.Uniq(paths)
		p.excludedPaths = append(p.excludedPaths, paths...)
	})
}
