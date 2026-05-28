CONFIG ?= configs/config.dev.yaml
BIN_DIR ?= bin

.PHONY: build test lint run migrate-up migrate-down migrate-status clean

build:
	go build -o $(BIN_DIR)/turjmp ./cmd/turjmp

test:
	go test ./...

lint:
	golangci-lint run ./...

run:
	go run ./cmd/turjmp --config $(CONFIG) --api

migrate-up:
	go run ./cmd/turjmp --config $(CONFIG) --migrate up

migrate-down:
	go run ./cmd/turjmp --config $(CONFIG) --migrate down

migrate-status:
	go run ./cmd/turjmp --config $(CONFIG) --migrate status

clean:
	rm -rf $(BIN_DIR)
