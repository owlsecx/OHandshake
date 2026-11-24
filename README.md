# 🦉 OHandshake

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Linux-0a0c10?style=flat-square"/>
  <img src="https://img.shields.io/badge/Category-Wireless%20/%20RF-blue?style=flat-square"/>
  <img src="https://img.shields.io/badge/License-GPL--3.0-blue?style=flat-square"/>
  <img src="https://img.shields.io/badge/Part%20of-OwlSec%20Toolkit-7b5ea7?style=flat-square"/>
  <img src="https://img.shields.io/badge/Version-1.0-cyan?style=flat-square"/>
</p>

> **OHandshake** — WPA/WPA2 handshake analyzer — 4-way/PMKID detect, hashcat -m 22000 export (offline) ║

---

> ⚠️ **AUTHORISED USE ONLY** — Use only on systems you own or have explicit written permission to test. Unauthorised use is illegal.

---

## 📌 Overview

OHandshake is an offline-first OwlSec tool for WPA/WPA2 handshake analyzer — 4-way/PMKID detect, hashcat -m 22000 export (offline). It provides an interactive cyan terminal UI and a full CLI with multi-format export (TXT, Markdown, JSON, CSV, SARIF), designed for authorized security work on Linux.

---

## ✨ Features

- Offline WPA/WPA2 4-way handshake and PMKID detection from pcap
- Identify complete vs partial handshakes and message timing
- Export hashcat -m 22000 compatible material
- Howto mode and self-test for lab validation
- Cyan TUI plus CLI batch analysis
- Report export via format/output flags

---

## ⚙️ Requirements

- **Linux**
- **Go 1.21+** (stdlib only; `CGO_ENABLED=0`)

---

## 🚀 Usage

```bash
go build -ldflags="-s -w" -o OHandshake OHandshake.go
./OHandshake --help
./OHandshake --input capture.pcap
./OHandshake --pcap handshake.pcap --format json
./OHandshake --input capture.pcap --output hs_report.md --format md
```

---

## 📦 Part of OwlSec Toolkit

This tool is part of the **OwlSec** suite — a collection of 275+ security and privacy tools.

🔗 [owlsec.org](https://owlsec.org)

---

## ©️ License

**GNU General Public License v3.0** — © 2026 Owlsec LLC

This tool is free software: its full source code is published in this repository and you may study, modify and redistribute it under the GPL-3.0.

> Other OwlSec tools are separate, independent programs under their own terms; many remain proprietary.
