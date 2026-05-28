// server 包负责 HTTP 服务器的创建、启动、关闭以及优雅停机的生命周期管理。
package server

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/tursom/turjmp/internal/api"
	"github.com/tursom/turjmp/internal/api/handler"
	"github.com/tursom/turjmp/internal/config"
	"github.com/tursom/turjmp/internal/repository"
)

// Server 封装 HTTP 服务器及其依赖。
type Server struct {
	HTTP   *http.Server // 标准库 HTTP 服务器实例
	Logger *zap.Logger  // 结构化日志记录器
}

// New 创建 Server 实例，初始化 Gin 路由并配置 http.Server。
// cfg 提供监听地址等配置，log 用于日志输出，
// db 和 h 传递给路由层用于依赖注入。
// ReadHeaderTimeout 设为 10 秒，防止慢速客户端攻击。
func New(cfg config.Config, log *zap.Logger, db *repository.DB, h *handler.Handler) *Server {
	router := api.NewRouter(cfg, log, db, h)
	srv := &http.Server{
		Addr:              cfg.HTTP.Addr,
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second,
	}
	return &Server{HTTP: srv, Logger: log}
}

// Start 启动 HTTP 服务器，调用 ListenAndServe 阻塞监听。
// 返回 http.ErrServerClosed 表示服务器已正常关闭。
func (s *Server) Start() error {
	return s.HTTP.ListenAndServe()
}

// Shutdown 优雅关闭服务器，等待现有请求处理完毕后再关闭。
// ctx 用于设定关闭超时时间。
func (s *Server) Shutdown(ctx context.Context) error {
	return s.HTTP.Shutdown(ctx)
}

// String 返回服务器描述字符串，包含监听地址。
func (s *Server) String() string {
	return fmt.Sprintf("http server on %s", s.HTTP.Addr)
}

// SetMode 根据运行环境设置 Gin 框架模式。
// 生产环境使用 ReleaseMode 以禁用调试输出和提升性能。
func SetMode(environment string) {
	if environment == "prod" {
		gin.SetMode(gin.ReleaseMode)
	}
}
