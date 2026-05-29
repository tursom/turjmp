// Package dbproxy 实现数据库协议代理和 Web 数据库终端。
// 本文件提供 MySQL 代理服务器的生命周期管理（创建、启动、停止）。
package dbproxy

import (
	"context"
	"errors"
	"net"
	"sync"

	"github.com/tursom/turjmp/internal/config"
)

// Server 是 MySQL 数据库代理服务器。
// 负责管理 TCP 监听器、API 客户端、以及 MySQL 代理的启动与优雅停止。
type Server struct {
	cfg      config.Config            // 全局配置
	api      *APIClient               // 后端 API 客户端
	listener net.Listener             // TCP 监听器
	cancel   context.CancelFunc       // 用于取消服务运行的取消函数
	mu       sync.Mutex               // 保护 listener 和 cancel 的并发访问
}

// NewServer 创建一个新的代理服务器实例。
// 初始化 API 客户端并关联配置。
func NewServer(cfg config.Config) *Server {
	return &Server{cfg: cfg, api: NewAPIClient(cfg)}
}

// Start 启动代理服务器。在指定端口上监听 TCP 连接，创建 MySQL 代理并开始接受连接。
// 返回 net.ErrClosed 视为正常关闭（不报错）。
// 流程：
//  1. 根据配置中的监听地址创建 TCP listener
//  2. 创建带取消功能的 context
//  3. 构造 mysqlProxy 实例（传入连接限制、连接超时、空闲超时）
//  4. 调用 proxy.serve 进入接受连接的主循环
func (s *Server) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.Proxy.DB.MySQLListenAddr())
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.listener = ln
	runCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	s.mu.Unlock()

	proxy := newMySQLProxy(
		s.api,
		s.cfg.Proxy.DB.ConnectionLimit(),
		s.cfg.Proxy.DB.ConnectTimeout(),
		s.cfg.Proxy.DB.IdleTimeout(),
	)
	err = proxy.serve(runCtx, ln)
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

// Stop 优雅停止代理服务器。
// 先取消 context（触发 serve 循环退出），再关闭 TCP 监听器。
func (s *Server) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancel != nil {
		s.cancel()
	}
	if s.listener != nil {
		_ = s.listener.Close()
	}
}
