.PHONY: all config build clean release help

VERSION ?= $(shell date +v%Y.%m.%d)

all: build

config:
	bash auto/config

build: config
	lb build 2>&1 | tee build.log

clean:
	lb clean --purge

release:
	@echo "==> Tagging release $(VERSION)"
	git add -A
	git commit -m "release: $(VERSION)" 2>/dev/null || true
	git tag -a $(VERSION) -m "KOPPA-OS $(VERSION)"
	git push origin main
	git push origin $(VERSION)
	@echo "==> GitHub Actions will now build the ISO and publish the release."

help:
	@echo ""
	@echo "  KOPPA-OS Build System"
	@echo "  ====================="
	@echo "  Requires: Debian 12, live-build, debootstrap, xorriso"
	@echo ""
	@echo "  make                   Configure + build ISO"
	@echo "  make config            Run auto/config only"
	@echo "  make build             Build ISO (assumes config done)"
	@echo "  make clean             Remove all build artifacts"
	@echo "  make release           Tag + push release (triggers CI build)"
	@echo "  make release VERSION=v1.0.2   Tag a specific version"
	@echo "  make help              Show this message"
	@echo ""
	@echo "  Quick start (on Debian 12):"
	@echo "    sudo apt-get install live-build debootstrap xorriso squashfs-tools"
	@echo "    make"
	@echo ""
