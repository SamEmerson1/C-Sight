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
## Checklist

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
### Notes

- Currently building for MacOS
- Using/Experimenting with PyShark
- Using IP database from https://ipinfo.io/

