package repository

import (
	"fmt"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/jmoiron/sqlx"
	_ "modernc.org/sqlite"

	"github.com/tursom/turjmp/internal/config"
)

type DB struct {
	*sqlx.DB
	Driver string
}

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
		return nil, fmt.Errorf("connect database: %w", err)
	}
	return &DB{DB: db, Driver: cfg.Driver}, nil
}

func (db *DB) Rebind(query string) string {
	if db.Driver == "postgres" {
		return db.DB.Rebind(query)
	}
	return query
}
