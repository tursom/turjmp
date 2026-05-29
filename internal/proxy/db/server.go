// Package dbproxy 实现数据库协议代理和 Web 数据库终端。
// 本文件提供数据库代理服务器的生命周期管理（创建、启动、停止）。
package dbproxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/tursom/turjmp/internal/config"
)

// Server 是数据库代理服务器。
// 负责管理 MySQL 和 PostgreSQL TCP 监听器、API 客户端、以及代理的启动与优雅停止。
type Server struct {
	cfg       config.Config      // 全局配置
	api       *APIClient         // 后端 API 客户端
	listeners []net.Listener     // TCP 监听器
	cancel    context.CancelFunc // 用于取消服务运行的取消函数
	mu        sync.Mutex         // 保护 listeners 和 cancel 的并发访问
}

// NewServer 创建一个新的代理服务器实例。
// 初始化 API 客户端并关联配置。
func NewServer(cfg config.Config) *Server {
	return &Server{cfg: cfg, api: NewAPIClient(cfg)}
}

// Start 启动代理服务器。在指定端口上监听 MySQL 和 PostgreSQL TCP 连接。
// 返回 net.ErrClosed 视为正常关闭（不报错）。
// 流程：
//  1. 根据配置中的监听地址创建 MySQL 和 PostgreSQL TCP listener
//  2. 创建带取消功能的 context
//  3. 构造 mysqlProxy 和 postgresProxy 实例（传入连接限制、连接超时、空闲超时）
//  4. 并行调用 proxy.serve 进入接受连接的主循环
func (s *Server) Start(ctx context.Context) error {
	mysqlLn, err := net.Listen("tcp", s.cfg.Proxy.DB.MySQLListenAddr())
	if err != nil {
		return err
	}
	// 步骤 1（续）：创建 PostgreSQL TCP listener；失败时关闭已创建的 MySQL listener 避免资源泄漏
	postgresLn, err := net.Listen("tcp", s.cfg.Proxy.DB.PostgresListenAddr())
	if err != nil {
		_ = mysqlLn.Close()
		return err
	}

	s.mu.Lock()
	runCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	s.listeners = []net.Listener{mysqlLn, postgresLn}
	s.mu.Unlock()

	// 步骤 3（实现）：构造 MySQL 和 PostgreSQL 代理实例，传入连接限制、连接超时、空闲超时配置
	mysqlProxy := newMySQLProxy(
		s.api,
		s.cfg.Proxy.DB.ConnectionLimit(),
		s.cfg.Proxy.DB.ConnectTimeout(),
		s.cfg.Proxy.DB.IdleTimeout(),
	)
	postgresProxy := newPostgresProxy(
		s.api,
		s.cfg.Proxy.DB.ConnectionLimit(),
		s.cfg.Proxy.DB.ConnectTimeout(),
		s.cfg.Proxy.DB.IdleTimeout(),
	)

	// 步骤 4（实现）：并行启动两个 proxy 的 serve 循环，用 errCh 收集各自的错误
	errCh := make(chan error, 2)
	go func() {
		errCh <- normalizeServeError("mysql", mysqlProxy.serve(runCtx, mysqlLn))
	}()
	go func() {
		errCh <- normalizeServeError("postgres", postgresProxy.serve(runCtx, postgresLn))
	}()

	// 等待任一 proxy 退出或 context 被取消；无论哪种情况都关闭所有 listener
	select {
	case <-runCtx.Done():
		s.closeListeners()
		return nil
	case err := <-errCh:
		cancel()
		s.closeListeners()
		return err
	}
}

// Stop 优雅停止代理服务器。
// 先取消 context（触发 serve 循环退出），再关闭 TCP 监听器。
func (s *Server) Stop() {
	s.closeListeners()
}

// closeListeners 取消服务 context 并关闭所有 TCP listener，实现优雅停止。
// 先调用 cancel() 触发 goroutine 退出，再关闭 listener 释放端口。
func (s *Server) closeListeners() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancel != nil {
		s.cancel()
	}
	for _, ln := range s.listeners {
		if ln != nil {
			_ = ln.Close()
		}
	}
}

// normalizeServeError 规范化 serve 函数返回的错误。
// net.ErrClosed 视为正常关闭，返回 nil；其他错误包装上 proxy 名称前缀。
func normalizeServeError(name string, err error) error {
	if err == nil || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return fmt.Errorf("%s proxy: %w", name, err)
}
