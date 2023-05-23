FORMAT_FILES := grep -L -R "^\/\/ Code generated .* DO NOT EDIT\.$$" --exclude-dir=.git --exclude-dir=vendor --include="*.go" .
GOLANGCI_LINT_VERSION ?= v1.52.2

install:
	@ [ -e ./bin/golangci-lint ] || wget -O - -q https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s $(GOLANGCI_LINT_VERSION)

format:
	$(FORMAT_FILES) | xargs gofumpt -extra -w
	$(FORMAT_FILES) | xargs gci write \
		--section standard \
		--section default \
		--section 'Prefix(github.com/utilitywarehouse/castle-go)'

lint: install
	golangci-lint run

mod:
	go mod tidy

test:
	gotestsum -- -vet=off -race ./...
