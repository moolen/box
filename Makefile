.PHONY: build test bin envoy

build: bin envoy
	go build -o ./bin/box ./cmd/box
	go build -o ./bin/box-initshim ./internal/initshim

test:
	go test ./... -v

bin:
	mkdir -p ./bin

envoy: bin
	go run ./cmd/envoypack --output ./bin/envoy
