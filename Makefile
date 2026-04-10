.PHONY: build test bin

build: bin
	go build -o ./bin/box ./cmd/box
	go build -o ./bin/box-initshim ./internal/initshim

test:
	go test ./... -v

bin:
	mkdir -p ./bin
