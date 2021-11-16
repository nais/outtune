all: clean api cli

COMMON_GO_FILES = $(shell find pkg/ -type f)

.PHONY: cli
cli: outtune-cli
outtune-cli: $(COMMON_GO_FILES) $(shell find cmd/outtune-cli -type f)
	go build -o $@ ./cmd/$@

.PHONY: api
api: outtune-api
outtune-api: $(COMMON_GO_FILES) $(shell find cmd/outtune-api -type f)
	go build -o $@ ./cmd/$@

.PHONY: clean
clean:
	rm -f outtune-api outtune-cli

.PHONY: test
test:
	go test ./...
