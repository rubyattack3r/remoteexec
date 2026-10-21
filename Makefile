.PHONY: build clean demo fmt lint test verify snapshot

build:
	go build -o bin/remoteexec .

clean:
	go clean

demo:
	@command -v vhs >/dev/null || { echo 'Install VHS (https://github.com/charmbracelet/vhs) to record the demo.' >&2; exit 1; }
	@command -v powershell >/dev/null || { echo 'Record the demo from an authorized Windows operator host with PowerShell.' >&2; exit 1; }
	@command -v remoteexec.exe >/dev/null || { echo 'Place remoteexec.exe on PATH before recording the demo.' >&2; exit 1; }
	mkdir -p docs/assets
	vhs scripts/vhs/demo.tape

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
