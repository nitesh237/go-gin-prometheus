package main

import (
	"github.com/nitesh237/go-gin-prometheus"

	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.New()

	/*	// Optional custom metrics list
		customMetrics := []*ginprometheus.Metric{
			&ginprometheus.Metric{
				Name:	"test_metric",			// required string
				Description:	"Counter test metric",	// required string
				Type:	ginprometheus.Counter,			// required string
			},
			&ginprometheus.Metric{
				Name:	"test_metric_2",		// Metric Name
				Description:	"Summary test metric",	// Help Description
				Type:	ginprometheus.Summary, // type associated with prometheus collector
			},
			&ginprometheus.Metric{
				Name:	"test_metric_2",		// Metric Name
				Description:	"Summary test metric",	// Help Description
				Type:	ginprometheus.HistogramVec, // type associated with prometheus collector
				Bucket: []float64{0.1, 0.2, 0.3, 0.4, 0.5}, // Buckets for histogram
			},
			// Add more custom metrics here
		}
		p := ginprometheus.NewPrometheus(ginprometheus.WithCustomMetrics(customMetrics...))
	*/

	// refer options.go for more options
	p := ginprometheus.NewPrometheus()

	p.Use(r)
	r.GET("/", func(c *gin.Context) {
		c.JSON(200, "Hello world!")
	})

	r.Run(":29090")
}
