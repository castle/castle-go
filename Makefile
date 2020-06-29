LINT_FLAGS :=--disable-all --enable=vet --enable=vetshadow --enable=golint --enable=ineffassign --enable=goconst --enable=gofmt
LINTER_EXE := gometalinter.v1
LINTER := $(GOPATH)/bin/$(LINTER_EXE)

LEXC :=
ifdef LINT_EXCLUDE
	LEXC := $(call join-with,|,$(LINT_EXCLUDE))
endif

$(LINTER):
	go get -u gopkg.in/alecthomas/$(LINTER_EXE)
	$(LINTER) --install

lint: $(LINTER)
ifdef LEXC
	$(LINTER) --exclude '$(LEXC)' $(LINT_FLAGS) ./castle/...
else
	$(LINTER) $(LINT_FLAGS) ./castle/...
endif

test:
	go test ./castle/...

install:
	go get -t ./castle/...
