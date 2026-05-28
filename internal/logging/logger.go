// logging 包封装 zap 日志库的初始化，
// 根据配置创建适合开发或生产环境的 Logger 实例。
package logging

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/tursom/turjmp/internal/config"
)

// New 根据日志配置创建并返回一个 zap.Logger 实例。
// 参数 cfg 决定日志级别和输出格式：
//   - cfg.Level：debug / info / warn / error，默认 "info"
//   - cfg.Encoding："json"（结构化，适合生产）或 "console"（可读，适合开发）
// console 模式使用 zap.NewDevelopmentConfig 以输出彩色级别标签和调用栈。
// 时间格式统一为 ISO 8601。
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
