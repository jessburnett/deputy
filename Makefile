.PHONY: verify build test tidy clean

verify: tidy build test
	@echo "✓ deputy green"

build:
	go build ./...

test:
	go test ./... -count=1

tidy:
	go mod tidy

clean:
	go clean -testcache
