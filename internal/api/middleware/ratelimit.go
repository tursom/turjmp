package middleware

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/tursom/turjmp/internal/config"
)

// bucket 是令牌桶限流算法的内部桶结构，存储当前可用令牌数和上次更新时间。
// 每个桶按"客户端 IP | 请求路径"的组合键进行隔离。
type bucket struct {
	tokens float64
	last   time.Time
}

// RateLimit 是基于令牌桶算法的 HTTP 限流中间件。以"客户端 IP + 请求路径"为维度进行限流，
// 每个桶以 cfg.RequestsPerSecond 速率补充令牌，桶容量等于该速率值。
// 当 cfg.Enabled 为 false 或 cfg.RequestsPerSecond <= 0 时限流功能关闭，直接放行。
// 每次请求消耗 1 个令牌，令牌不足时返回 HTTP 429 Too Many Requests。
func RateLimit(cfg config.RateLimitConfig) gin.HandlerFunc {
	if !cfg.Enabled || cfg.RequestsPerSecond <= 0 {
		return func(c *gin.Context) { c.Next() }
	}
	var mu sync.Mutex
	buckets := map[string]*bucket{}
	burst := cfg.RequestsPerSecond
	if burst < 1 {
		burst = 1
	}
	return func(c *gin.Context) {
		key := c.ClientIP() + "|" + c.FullPath()
		now := time.Now()
		mu.Lock()
		b := buckets[key]
		if b == nil {
			b = &bucket{tokens: burst, last: now}
			buckets[key] = b
		}
		elapsed := now.Sub(b.last).Seconds()
		b.last = now
		b.tokens += elapsed * cfg.RequestsPerSecond
		if b.tokens > burst {
			b.tokens = burst
		}
		if b.tokens < 1 {
			mu.Unlock()
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": gin.H{"code": "rate_limited", "message": "too many requests"}})
			return
		}
		b.tokens--
		mu.Unlock()
		c.Next()
	}
}
