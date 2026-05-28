package server

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func SignalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
}

func Shutdown(ctx context.Context, timeout time.Duration, fn func(context.Context) error) error {
	shutdownCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return fn(shutdownCtx)
}
