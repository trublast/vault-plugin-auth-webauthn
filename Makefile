GOARCH ?= amd64
UNAME := $(shell uname -s)
ifeq ($(UNAME), Linux)
	OS ?= linux
else ifeq ($(UNAME), Darwin)
	OS ?= darwin
endif

.PHONY: build build-web fmt clean test

build:
	GOOS=$(OS) GOARCH=$(GOARCH) go build -o plugins/webauthn ./cmd/vault-plugin-auth-webauthn

build-web:
	go build -o bin/webauthn-web ./cmd/webauthn-web

fmt:
	go fmt ./...

clean:
	rm -f vault-auth-plugin-webauthn webauthn-web

test:
	go test ./...
