.PHONY: all
all: pivit

#
# pivit: build pivit binary locally for development 
#
.PHONY: pivit
pivit:
	CGO_ENABLED=1 go build ./cmd/pivit

#
# install: install pivit to $GOPATH/bin
#
.PHONY: install
install:
	go install ./cmd/pivit

#
# release: build a possibly cross-compiled and compressed release binary
#
.PHONY: release
GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)
EXE = pivit-$(GOOS)-$(GOARCH)
release: pivit
	(\
	set -e ;\
	cp -f pivit $(EXE) ;\
	gzip -f -9 $(EXE) ;\
	)

#
# test: run tests
#
.PHONY: test
test: pivit
	(\
	set -e ;\
	go test -coverprofile=cover.out ./pkg/... ;\
	file pivit ;\
	./pivit --help 2> /dev/null ;\
	)

#
# clean: remove locally built artifacts
#
.PHONY: clean
clean:
	rm -rf ./pivit* ./cover.out
