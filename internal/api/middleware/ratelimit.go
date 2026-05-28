package middleware

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/tursom/turjmp/internal/config"
)

type bucket struct {
	tokens float64
	last   time.Time
}

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
