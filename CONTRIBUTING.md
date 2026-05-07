# Contributing to KOPPA-OS

## Requirements

Build requires a **Debian 12 (Bookworm)** host or container. Ubuntu 22.04+ also works.

```bash
sudo apt-get update
sudo apt-get install -y \
  live-build debootstrap xorriso squashfs-tools \
  grub-pc-bin grub-efi-amd64-bin mtools dosfstools \
  python3-pil python3-pip rsync curl wget git
```

## Build from source

```bash
git clone https://github.com/guea14012/koppa-os
cd koppa-os
make          # runs auto/config then lb build
```

The output ISO will be named `live-image-amd64.hybrid.iso` in the project root.
Run `make release VERSION=v1.x.x` to tag and trigger a CI release build.

## Project structure

| Path | Purpose |
|------|---------|
| `auto/config` | live-build configuration (distro, arch, mirrors, boot flags) |
| `auto/build` | calls `lb build` |
| `config/hooks/` | chroot hooks that install tools during build |
| `config/includes.chroot/` | files copied verbatim into the ISO filesystem |
| `config/package-lists/` | Debian packages to include |
| `koppa-packages/` | KOPPA package registry (`.kop` modules + `index.json`) |
| `www/` | GitHub Pages website (deployed automatically on push to main) |
| `.github/workflows/` | CI/CD: `build-iso.yml` builds + releases, `pages.yml` deploys site |

## Adding a tool

**Option A — Debian package** (preferred): add the package name to
`config/package-lists/koppa-os.list.chroot`.

**Option B — Hook script** (for tools not in Debian repos): add installation
commands to `config/hooks/0100-koppa-setup.hook.chroot`. Always use `|| true`
so a failed install does not abort the entire build.

**Option C — KOPPA package**: add a `.kop` file to `koppa-packages/` and
register it in `koppa-packages/index.json`.

## Releasing

1. Update `CHANGELOG.md` with the new version.
2. Run `make release VERSION=v1.x.x` — this tags and pushes, which triggers
   the GitHub Actions build job that produces the ISO and creates a GitHub Release.
3. The website (`www/`) is auto-deployed after each successful build.

## Code style

Hook scripts are plain bash. Keep them idempotent and always guard with `|| true`
so silent failures don't break the build.
