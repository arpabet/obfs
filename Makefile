VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

all: build

version:
	@echo $(VERSION)

vet:
	go vet ./...

test: vet
	go test -race -cover ./...

build: test
	go build ./...

vuln:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

update:
	go get -u ./... && go mod tidy
