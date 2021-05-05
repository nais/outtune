all: clean api cli

COMMON_GO_FILES = $(shell find pkg/ -type f)

cli: $(COMMON_GO_FILES) $(shell find cmd/outtune_cli/ -type f)
	go build -o $@ ./cmd/outtune_cli

api: $(COMMON_GO_FILES) $(shell find apiserver cmd/outtune -type f)
	go build -o $@ ./cmd/outtune

.PHONY: clean
clean:
	rm -f \
		./api \
		./cli
