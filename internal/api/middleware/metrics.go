package middleware

import (
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	httpRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "turjmp_http_requests_total",
		Help: "Total HTTP requests.",
	}, []string{"method", "path", "status"})
	httpDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "turjmp_http_request_duration_seconds",
		Help:    "HTTP request duration in seconds.",
		Buckets: prometheus.DefBuckets,
	}, []string{"method", "path"})
)

func init() {
	prometheus.MustRegister(httpRequests, httpDuration)
}

func Metrics() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		path := c.FullPath()
		if path == "" {
			path = c.Request.URL.Path
		}
		httpRequests.WithLabelValues(c.Request.Method, path, strconv.Itoa(c.Writer.Status())).Inc()
		httpDuration.WithLabelValues(c.Request.Method, path).Observe(time.Since(start).Seconds())
	}
}
