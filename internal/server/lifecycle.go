// server 包负责 HTTP 服务器的创建、启动、关闭以及优雅停机的生命周期管理。
package server

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// SignalContext 创建一个被操作系统信号取消的 context。
// 监听 SIGTERM 和 SIGINT（Ctrl+C）信号，任意一个触发即取消 context。
// 返回的 CancelFunc 可主动取消 context。
// 用于 main goroutine 阻塞等待退出信号。
func SignalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
}

// Shutdown 在指定超时内执行关闭函数，实现优雅停机。
// timeout 为关闭操作的最大等待时间，超时后 context 自动取消。
// fn 为实际的关闭函数（如 server.Shutdown），接收带超时的 context。
// 使用 defer cancel() 确保超时 context 资源被释放。
func Shutdown(ctx context.Context, timeout time.Duration, fn func(context.Context) error) error {
	shutdownCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return fn(shutdownCtx)
}
