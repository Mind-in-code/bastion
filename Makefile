# BASTION — zero external dependencies, one source file.
#
# Reproducible build flags, and what each one is for:
#   CGO_ENABLED=0    no host C toolchain gets linked in
#   -trimpath        strip absolute source paths out of the binary
#   -buildvcs=false  keep git commit/dirty state out of the binary
#   -s -w            drop the symbol and DWARF debug tables
#   -buildid=        clear Go's build id, which otherwise varies between builds
#
# Together these remove everything that depends on *where* and *when* you built,
# so the output depends only on the source and the Go version.

GO       ?= go
SRC      := bastion.go
BIN      := bastion
DIST     := dist
BUILDENV := CGO_ENABLED=0
GOFLAGS  := -trimpath -buildvcs=false
LDFLAGS  := -s -w -buildid=

# sha256sum on Linux, shasum on macOS.
SHA256 := $(shell command -v sha256sum >/dev/null 2>&1 && echo sha256sum || echo shasum -a 256)

.PHONY: all build test test-short bench reproducible audit clean

all: build

## build: compile ./bastion with the reproducible flags
build:
	$(BUILDENV) $(GO) build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o $(BIN) $(SRC)
	@echo "built ./$(BIN)"

## test: full suite with coverage
test:
	$(GO) test -v -cover .

## test-short: quick pre-commit run, skips the heavy payloads
test-short:
	$(GO) test -short .

## bench: benchmarks only, with allocation counts
bench:
	$(GO) test -bench=. -benchmem -run=^# .

## reproducible: build three times and prove the bytes are identical
reproducible:
	@mkdir -p $(DIST)
	@rm -rf $(DIST)/.elsewhere
	$(BUILDENV) $(GO) build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o $(DIST)/bastion-1 $(SRC)
	$(BUILDENV) $(GO) build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o $(DIST)/bastion-2 $(SRC)
#	Build three comes from a different absolute path. This is the build that
#	actually proves -trimpath works: two builds in the same directory would
#	still match even if the binary had that directory's name baked into it.
	@mkdir -p $(DIST)/.elsewhere
	@cp $(SRC) go.mod $(DIST)/.elsewhere/
	cd $(DIST)/.elsewhere && $(BUILDENV) $(GO) build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o ../bastion-3 $(SRC)
	@echo
	@$(SHA256) $(DIST)/bastion-1 $(DIST)/bastion-2 $(DIST)/bastion-3
	@echo
	@if cmp -s $(DIST)/bastion-1 $(DIST)/bastion-2 && cmp -s $(DIST)/bastion-1 $(DIST)/bastion-3; then \
		echo "REPRODUCIBLE: all three builds are byte-for-byte identical"; \
		echo "              (build 3 came from a different directory, so no host path leaked in)"; \
	else \
		echo "NOT REPRODUCIBLE: the builds differ"; exit 1; \
	fi
	@rm -rf $(DIST)/.elsewhere

## audit: prove the dependency manifest is empty
audit:
	@echo "--- go.mod ---"
	@cat go.mod
	@echo "--- go list -m all ---"
	@$(GO) list -m all
	@if grep -q '^require' go.mod; then \
		echo "FAIL: go.mod has a require block"; exit 1; \
	else \
		echo "OK: no require block, no external dependencies"; \
	fi

## clean: remove binaries and test artefacts
clean:
	rm -rf $(DIST)
	rm -f $(BIN) $(BIN).exe coverage.out
	$(GO) clean -testcache
	@echo "cleaned"
