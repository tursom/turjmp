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

type Server struct {
	HTTP   *http.Server
	Logger *zap.Logger
}

func New(cfg config.Config, log *zap.Logger, db *repository.DB, h *handler.Handler) *Server {
	router := api.NewRouter(cfg, log, db, h)
	srv := &http.Server{
		Addr:              cfg.HTTP.Addr,
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second,
	}
	return &Server{HTTP: srv, Logger: log}
}

func (s *Server) Start() error {
	return s.HTTP.ListenAndServe()
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.HTTP.Shutdown(ctx)
}

func (s *Server) String() string {
	return fmt.Sprintf("http server on %s", s.HTTP.Addr)
}

func SetMode(environment string) {
	if environment == "prod" {
		gin.SetMode(gin.ReleaseMode)
	}
}
