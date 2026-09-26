BINARY    := naddr
BIN_DIR   := bin
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64

GO_BUILD_FLAGS := -trimpath
GO_LDFLAGS     := -s -w

DATA_DIR  := tsv
DATA_FILE := $(DATA_DIR)/ip2asn-combined.tsv.gz
DATA_URL  := https://iptoasn.com/data/ip2asn-combined.tsv.gz

FUZZTIME     ?= 10s
FUZZ_TARGETS := FuzzTSVParser FuzzCIDRMembership FuzzParseAddr8 FuzzLookupDifferential

os   = $(word 1,$(subst /, ,$1))
arch = $(word 2,$(subst /, ,$1))
ext  = $(if $(filter windows,$(call os,$1)),.exe,)

.PHONY: all lint fmt-check vet test test-race bench fuzz clean build data run summary $(PLATFORMS)

# summary is intentionally not part of all: it needs the external summarize tool.
all: lint clean test test-race build

lint: fmt-check vet

fmt-check:
	@unformatted="$$(gofmt -l .)"; \
	if [ -n "$$unformatted" ]; then echo "gofmt needed:"; echo "$$unformatted"; exit 1; fi

vet:
	go vet ./...

test:
	go test -count=1 ./...

test-race:
	go test -race -count=1 ./...

bench:
	go test -run='^$$' -bench=. -benchmem ./...

# Go runs one fuzz target per invocation.
fuzz:
	@for target in $(FUZZ_TARGETS); do \
		echo "==> $$target"; \
		go test -run='^$$' -fuzz="^$$target\$$" -fuzztime=$(FUZZTIME) ./ess || exit 1; \
	done

# Download the IPtoASN database for local development. The download is
# verified and moved into place atomically, so a running naddr never
# observes a partial file.
data:
	@mkdir -p $(DATA_DIR)
	curl -fsSL --retry 3 -o $(DATA_FILE).tmp $(DATA_URL)
	gzip -t $(DATA_FILE).tmp
	mv $(DATA_FILE).tmp $(DATA_FILE)

run:
	NADDR_DATA=$${NADDR_DATA:-$(DATA_FILE)} go run .

clean:
	go clean ./...
	rm -rf $(BIN_DIR)

summary:
	summarize -s useExpanded,templates/lib,tsv,.git,.idea,summaries,lemmings -x useExpanded,jpg,tsv,LICENSE

build: $(PLATFORMS)

$(PLATFORMS):
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 GOOS=$(call os,$@) GOARCH=$(call arch,$@) \
		go build $(GO_BUILD_FLAGS) -ldflags "$(GO_LDFLAGS)" \
		-o $(BIN_DIR)/$(BINARY)-$(call os,$@)-$(call arch,$@)$(call ext,$@) .