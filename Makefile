.PHONY: build clean demo fmt lint test verify snapshot

build:
	go build -o bin/remoteexec .

clean:
	go clean

demo: build
	@command -v vhs >/dev/null || { echo 'Install VHS (https://github.com/charmbracelet/vhs) to record the demo.' >&2; exit 1; }
	mkdir -p docs/assets
	PATH="$(CURDIR)/bin:$$PATH" vhs scripts/vhs/demo.tape

fmt:
	gofmt -w $$(find . -name '*.go' -not -path './vendor/*')

lint:
	test -z "$$(gofmt -l .)"
	go vet ./...

test:
	go test -race ./...

verify: lint test build

snapshot:
	goreleaser release --snapshot --clean --skip=sign --config .goreleaser/goreleaser.yml
