CONFIG ?= configs/config.dev.yaml
BIN_DIR ?= bin

.PHONY: build test lint run migrate-up migrate-down migrate-status rdp-plugin clean

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

rdp-plugin:
	cmake -S native/rdp-freerdp-plugin -B native/rdp-freerdp-plugin/build
	cmake --build native/rdp-freerdp-plugin/build

clean:
	rm -rf $(BIN_DIR)
