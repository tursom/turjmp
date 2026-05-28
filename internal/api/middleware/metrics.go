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

// Metrics 是 Prometheus HTTP 指标采集中间件。记录每个 HTTP 请求的方法、路径和状态码，
// 并统计请求耗时。采集的指标包括：turjmp_http_requests_total（计数器）和
// turjmp_http_request_duration_seconds（直方图），均由 Prometheus client 库暴露的 /metrics 端点采集。
// 该中间件通过 init() 函数在包初始化时自动注册指标到 Prometheus 默认注册表。
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
