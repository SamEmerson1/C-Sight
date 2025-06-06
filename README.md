# C-Sight

*Python network traffic analyzer that can be used to translate raw packets into plain English for non-tech audiences.*

## Purpose

- Sniffs packets from your local Wi-Fi/LAN traffic
- Translates traffic into human-readable summaries.

## Reason

- To improve network visibility for users without technical backgrounds (e.g. C-suite)
- Also good for training and security awareness
- Understanding network traffic shouldn't require a CS degree
- Network security peace of mind is a human right!

## Setup

### Clone

```bash
git clone https://github.com/SamEmerson1/C-Sight.git
cd C-Sight
```

### Install
Use a Python venv (recommended):

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install requirements:
```bash
pip install -r requirements.txt
```

### Starting

```bash
cd csight
python3 main_csight.py
```

### Checklist (MVP)

- [x] Watch live local traffic using PyShark
- [x] Use SNI (for TLS) and Host headers (for HTTP) to extract hostnames
- [x] Deduplicates recent logs to avoid spammy console output
- [x] QUIC/UDP detection
- [x] DNS traffic interpretation
- [x] Reverse DNS lookups
- [x] IPv6 support
- [x] Session-level tracking
- [x] File logging

---
### Checklist (V.1 - Security detection)

- [x] DNS Tunneling patterns
- [x] Abnormal QUIC traffic
- [x] Access to malicious domains
- [x] Communications with unexpected regions
- [x] Frequent DNS failures and NXDOMAIN spikes
- [x] Cleartext HTTP usage on sensitive domains
- [x] High volume of unique TLS destinations
- [x] SSH attempts on unusual ports
- [x] High-frequency TLS handshakes on new destinations

---
### Checklist (V.2 - Usability/clarity)

- [x] Add domain/IP ignorelist
- [x] Log verbosity levels
- [x] Human friendly log formatting
- [x] Add definitions/type glossary
- [x] Log metadata
- [x] Config file

---
### Notes

- Currently building for MacOS - would work for Window and Linux w/ adjustments
- Using/Experimenting with PyShark
- Using IP database from https://ipinfo.io/ (05/29/25)
- Malicious url database from https://urlhaus.abuse.ch/ (05/31/25)
- IP location database(s) from https://dev.maxmind.com/ (06/01/25)
- Frequent NXDOMAIN detection is weird, because DNS responses without monitor mode can be missed
- TLS handshake rate and excessive TLS differ accounting rate vs. accounting scope, they compliment one another
