VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -ldflags "-X main.version=$(VERSION)"

all: latch

latch:
	go build $(LDFLAGS) -o latch ./cmd/latch

PREFIX ?= /usr/local

install: latch
	install -d $(PREFIX)/bin
	install -m 755 latch $(PREFIX)/bin/latch
	install -d $(PREFIX)/share/man/man1
	install -m 644 doc/latch.1 $(PREFIX)/share/man/man1/latch.1
	install -d $(PREFIX)/share/man/man5
	install -m 644 doc/latch.conf.5 $(PREFIX)/share/man/man5/latch.conf.5

test:
	go test ./...

test-race:
	go test -race -count=1 ./...

vet:
	go vet ./...

lint:
	golangci-lint run

cross:
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o latch-linux-amd64 ./cmd/latch
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o latch-linux-arm64 ./cmd/latch
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o latch-darwin-amd64 ./cmd/latch
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o latch-darwin-arm64 ./cmd/latch
	CGO_ENABLED=0 GOOS=freebsd GOARCH=amd64 go build $(LDFLAGS) -o latch-freebsd-amd64 ./cmd/latch

uninstall:
	rm -f $(PREFIX)/bin/latch
	rm -f $(PREFIX)/share/man/man1/latch.1
	rm -f $(PREFIX)/share/man/man5/latch.conf.5

clean:
	rm -f latch latch-linux-* latch-darwin-* latch-freebsd-*

.PHONY: all latch install uninstall test test-race vet lint cross clean
