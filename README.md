# KOPPA-OS

<p align="center">
  <img src="logo koppa-os(favicon).png" width="120" alt="KOPPA-OS"/>
</p>

<p align="center">
  <strong>Redteam Operating System</strong><br/>
  <em>Powered by KOPPA v3.0.1 · Built on Kali Linux</em>
</p>

---

> **⚠️ LEGAL DISCLAIMER**
>
> KOPPA-OS is designed **exclusively for authorized security testing, penetration testing, CTF competitions, and security research**.
> Using this software against systems without explicit written authorization is illegal and unethical.
> The developers assume no liability for misuse. By downloading or using KOPPA-OS, you agree to comply with all applicable laws.

---

## What is KOPPA-OS?

A Kali Linux-based live OS with the [KOPPA language](https://guea14012.github.io/koppa-lang) pre-installed — a security-native DSL designed for offensive and defensive security professionals.

## Pre-installed Tools

| Tool | Description |
|---|---|
| `koppa` | KOPPA language runtime v3.0.1 |
| `apollo` | Apollo DSL alias |
| `koppa-portscan` | TCP port scanner |
| `koppa-jwt-attack` | JWT analysis & attack toolkit |
| `koppa-subdomain` | Subdomain enumeration |
| `koppa-hashcrack` | Hash identification & cracking |
| `koppa-webfuzz` | Web directory & parameter fuzzer |
| `nmap-ai` | AI-powered vulnerability scanner |
| Full Kali toolset | nmap, Metasploit, Burp, Wireshark... |

## Quick Start

```bash
# Boot ISO → open terminal

koppa repl                         # Interactive KOPPA shell
koppa run script.kop               # Run a script
koppa pkg install koppa-portscan   # Install package
koppa pkg audit                    # Audit installed packages
```

## Build ISO

ISO is built automatically via GitHub Actions on every push.

Download from: [Releases](https://github.com/guea14012/koppa-os/releases) | [Actions Artifacts](https://github.com/guea14012/koppa-os/actions)

```bash
# Manual build (requires Docker)
bash scripts/build.sh
```

## Links

- [KOPPA Language](https://guea14012.github.io/koppa-lang)
- [KOPPA Package Registry](https://guea14012.github.io/koppa-registry-/)
- [KOPPA Playground](https://guea14012.github.io/koppa-lang/playground.html)

## License

MIT — For authorized security testing only.
