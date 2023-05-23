FORMAT_FILES := grep -L -R "^\/\/ Code generated .* DO NOT EDIT\.$$" --exclude-dir=.git --exclude-dir=vendor --include="*.go" .

GOLANGCI_LINT_VERSION ?= v1.52.2

install:
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(shell go env GOPATH)/bin $(GOLANGCI_LINT_VERSION)

	go install \
		github.com/daixiang0/gci \
		gotest.tools/gotestsum \
		mvdan.cc/gofumpt

format:
	$(FORMAT_FILES) | xargs gofumpt -extra -w
	$(FORMAT_FILES) | xargs gci write \
		--section standard \
		--section default \
		--section 'Prefix(github.com/utilitywarehouse/castle-go)'

lint:
	golangci-lint run

mod:
	go mod tidy

semgrep:
	semgrep scan --config .semgrep/rules.yaml --config=p/semgrep-go-correctness

test:
	gotestsum -- -vet=off -race ./...
