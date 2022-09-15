MAKEFILE_ROOT = $(shell dirname $(realpath $(word $(words $(MAKEFILE_LIST)),$(MAKEFILE_LIST))))
BUILD_DIR = $(MAKEFILE_ROOT)/build
GOOS ?= $(shell go version | awk '{print $$NF}' | cut -d/ -f1)
GOARCH ?= $(shell go version | awk '{print $$NF}' | cut -d/ -f2)
EXE = $(BUILD_DIR)/pivit-$(GOOS)-$(GOARCH)

.PHONY: all build

all: build

build: # Builds executable and gzips it
	mkdir -p $(BUILD_DIR)
	# Cross-compile would be hard ¯\_(ツ)_/¯
	CGO_ENABLED=1 go build -o $(EXE) ./cmd/pivit
	gzip -9 $(EXE)

clean:
	rm -rf $(BUILD_DIR)
