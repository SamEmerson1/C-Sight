# C-Sight
---
*Python network traffic analyzer that can be used to translate raw packets into plain English for non-tech audiences.*

## Purpose

- Sniffs packets from your local Wi-Fi/LAN traffic
- Translates traffic into human-readable summaries.
---
## Reason

- To improve network visibility for users without technical backgrounds (e.g. C-suite)
- Also good for training and security awareness
- Understanding network traffic shouldn't require a CS degree
- Network security peace of mind is a human right!
---
### How to Run

```bash
cd csight # (initially)
sudo python3 csight/pyshark_translator.py
```
---
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

- [ ] Add domain/IP ignorelist
- [ ] Log verbosity levels
- [ ] Human friendly log formatting
- [ ] Color coded logging
- [ ] Add definitions/type glossary
- [ ] Log metadata
- [ ] Config file
- [ ] Summary printout
- [ ] Anomaly scoring 

---
### Notes

- Currently building for MacOS
- Using/Experimenting with PyShark
- Using IP database from https://ipinfo.io/ (05/29/25)
- Malicious url database from https://urlhaus.abuse.ch/ (05/31/25)
- IP location database(s) from https://dev.maxmind.com/ (06/01/25)
- Frequent NXDOMAIN detection is weird, because DNS responses without monitor mode can be missed
- TLS handshake rate and excessive TLS differ accounting rate vs. accounting scope, they compliment one another
