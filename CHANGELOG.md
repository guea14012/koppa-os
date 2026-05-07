# Changelog

All notable changes to KOPPA-OS are listed here.

## [v1.0.1] — 2026-05-07

### Added
- Plymouth boot splash with KOPPA-OS branding
- Custom GRUB theme (dark red / matrix aesthetic)
- Full XFCE4 desktop with LightDM autologin
- KOPPA-C2 HTTP/DNS C2 framework + web operator console
- neofetch with KOPPA-OS ASCII art on login
- 50+ pre-installed security tools (see README)
- 26 KOPPA packages in the registry
- Calamares GUI installer for disk install
- GitHub Actions CI/CD: auto-build ISO on tag push, auto-deploy website

### Fixed
- LightDM autologin PAM uid check removed (fixes login loop on some VMs)
- Docker daemon using `vfs` storage driver (fixes overlay2 issues in VirtualBox live)

---

## [v1.0.0] — 2026-04-17

### Added
- Initial KOPPA-OS release based on Debian 12 Bookworm
- live-build configuration for hybrid ISO (USB + CD)
- KOPPA language runtime pre-installed
- Base security toolset: nmap, metasploit, sqlmap, hydra, hashcat, aircrack-ng
- GitHub Pages landing page with download section
