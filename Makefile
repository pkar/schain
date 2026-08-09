GO      ?= go
LDFLAGS ?= -s -w

# Install dir: PREFIX wins if given, else first user-writable candidate
# (Homebrew on Apple Silicon, then /usr/local, then ~/.local), else
# ~/.local/bin which install -d will create.
ifdef PREFIX
BINDIR ?= $(PREFIX)/bin
else
BINDIR ?= $(shell for d in /opt/homebrew/bin /usr/local/bin "$$HOME/.local/bin"; do \
	[ -w "$$d" ] && { echo "$$d"; exit; }; done; echo "$$HOME/.local/bin")
endif

.PHONY: all help build test vet install uninstall clean

all: build

help:
	@echo "schain make targets:"
	@echo "  build      build stripped binary (default)"
	@echo "  test       run tests"
	@echo "  vet        run go vet"
	@echo "  install    install to \$$(BINDIR) [$(BINDIR)]"
	@echo "  uninstall  remove installed binary"
	@echo "  clean      remove build output"
	@echo ""
	@echo "variables: PREFIX (forces \$$PREFIX/bin), BINDIR, DESTDIR, GO [$(GO)]"
	@echo "default install dir is the first user-writable of:"
	@echo "  /opt/homebrew/bin /usr/local/bin ~/.local/bin"

build:
	$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o schain .

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

install: build
	@dir=$(DESTDIR)$(BINDIR); \
	while [ ! -e "$$dir" ]; do dir=$$(dirname "$$dir"); done; \
	if [ ! -w "$$dir" ]; then \
		echo "error: no write access to $$dir"; \
		echo "  try:  sudo make install"; \
		echo "  or:   make install PREFIX=\$$HOME/.local  (then add ~/.local/bin to PATH)"; \
		exit 1; \
	fi
	install -d $(DESTDIR)$(BINDIR)
	install -m 0755 schain $(DESTDIR)$(BINDIR)/schain
	@echo "installed $(BINDIR)/schain"
	@case ":$$PATH:" in *:"$(BINDIR)":*) ;; \
	*) echo "note: $(BINDIR) is not on your PATH" ;; esac

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/schain

clean:
	rm -f schain
