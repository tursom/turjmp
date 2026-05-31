// 包 repository 提供数据库抽象层和持久化操作。
//
// 支持 PostgreSQL（通过 pgx 驱动）和 SQLite（通过 modernc 纯 Go 实现）两种数据库后端。
// 使用 sqlx 提供编译时安全的命名参数和结构体映射。
// 连接池默认配置：最大 25 个空闲连接、10 个活跃连接、连接最大存活 30 分钟。
package repository

import (
	"fmt"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/jmoiron/sqlx"
	_ "modernc.org/sqlite"

	"github.com/tursom/turjmp/internal/config"
)

// DB 封装 sqlx.DB 并记录当前使用的驱动名称（"postgres" 或 "sqlite"），
// 用于 Rebind 方法按驱动差异处理 SQL 占位符。
type DB struct {
	*sqlx.DB
	Driver string
}

// NewDB 根据配置打开数据库连接。
// PostgreSQL 使用 pgx 驱动（高性能纯 Go 实现），SQLite 使用 modernc 纯 Go 实现（无需 CGO）。
// 连接池配置：最大 25 个打开连接、10 个空闲连接、连接最长存活 30 分钟。
func NewDB(cfg config.DatabaseConfig) (*DB, error) {
	driver := cfg.Driver
	if driver == "postgres" {
		driver = "pgx"
	}
	db, err := sqlx.Open(driver, cfg.DSN)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(10)
	db.SetConnMaxLifetime(30 * time.Minute)
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("连接数据库失败：%w", err)
	}
	return &DB{DB: db, Driver: cfg.Driver}, nil
}

// Rebind 将 SQL 查询中的 ? 占位符转换为当前数据库对应的占位符格式。
// PostgreSQL 使用 pgx 驱动时转换为 $1, $2, ...；SQLite 保持 ? 不变。
func (db *DB) Rebind(query string) string {
	if db.Driver == "postgres" {
		return db.DB.Rebind(query)
	}
	return query
}
