#!/usr/bin/env bash
# Send fake QUIC packets to random IPs on UDP port 443
# Used to trigger abnormal_quic.py detection

for i in $(seq 1 50); do
  # Random IP in 192.0.2.0/24 (reserved for documentation/testing)
  OCTET=$((RANDOM % 254 + 1))
  TARGET="192.0.2.${OCTET}"

  echo "QUIC?" | nc -u -w 1 "${TARGET}" 443 > /dev/null 2>&1 &

  sleep 0.2
done

wait
echo "✅ Sent 50 fake QUIC packets to random IPs"
