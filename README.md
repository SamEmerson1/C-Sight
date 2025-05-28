# C-Sight
Python network traffic analyzer that can be used to translate raw packets into plain English for non-tech audiences.

## What it actually does

- Sniffs packets from your local Wi-Fi/LAN traffic
- Translates traffic into human-readable summaries like:
  - "A device on your network is connecting to example.com securely.”
  - “Unusual behavior on network! device sent 100+ ICMP packets in 60 seconds.”

## Why I wanted to make it

 - To improve network visibility for users without technical backgrounds (e.g. C-suite)
 - Also good for training and security awareness
 - Understanding network traffic shouldn't require a CS degree
 - Network security peace of mind is a human right!

### Notes

 - Currently building for MacOS
 - Using/Experimenting with PyShark