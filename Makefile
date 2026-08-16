GO ?= go

.PHONY: build test fmt demo clean

build:
	$(GO) build -o cbomscope ./cmd/cbomscope

test:
	$(GO) vet ./...
	$(GO) test ./...

fmt:
	gofmt -w .

# Scan this repository and write a bill of materials for it.
demo: build
	./cbomscope scan .
	@echo
	./cbomscope cbom . -o cbom.json && echo "wrote cbom.json"

clean:
	rm -f cbomscope cbom.json
