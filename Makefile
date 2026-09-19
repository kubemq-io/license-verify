.PHONY: all fmt vet test

all: fmt vet test

fmt:
	@test -z "$$(gofmt -l .)" || (gofmt -l . && exit 1)

vet:
	go vet ./...

test:
	go test -race ./...
