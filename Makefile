.PHONY: build clean demo fmt lint test verify snapshot

build:
	go build -o bin/remoteexec .

clean:
	go clean

demo: build
	@command -v vhs >/dev/null || { echo 'Install VHS (https://github.com/charmbracelet/vhs) to record the demo.' >&2; exit 1; }
	@test -r "$$HOME/.ssh/remoteexec_demo" || { echo 'Configure the demo private key at ~/.ssh/remoteexec_demo.' >&2; exit 1; }
	@getent hosts server01 >/dev/null || { echo 'Configure server01 as an authorized SSH test target.' >&2; exit 1; }
	mkdir -p docs/assets
	PATH="$(CURDIR)/bin:$$PATH" vhs scripts/vhs/demo.tape

fmt:
	gofmt -w $$(git ls-files '*.go')

lint:
	test -z "$$(gofmt -l $$(git ls-files '*.go'))"
	go vet ./...

test:
	go test -race ./...

verify: lint test build

snapshot:
	goreleaser release --snapshot --clean --skip=sign --config .goreleaser/goreleaser.yml
