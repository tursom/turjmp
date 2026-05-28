package logging

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/tursom/turjmp/internal/config"
)

func New(cfg config.LoggingConfig) (*zap.Logger, error) {
	level := zap.NewAtomicLevelAt(zap.InfoLevel)
	if cfg.Level != "" {
		if err := level.UnmarshalText([]byte(cfg.Level)); err != nil {
			return nil, err
		}
	}
	enc := "json"
	if cfg.Encoding != "" {
		enc = cfg.Encoding
	}
	zcfg := zap.NewProductionConfig()
	zcfg.Level = level
	zcfg.Encoding = enc
	zcfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	if enc == "console" {
		zcfg = zap.NewDevelopmentConfig()
		zcfg.Level = level
		zcfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	}
	return zcfg.Build()
}
