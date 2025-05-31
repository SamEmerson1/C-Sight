#!/usr/bin/env bash
# Generate 50 random subdomains and fire off DNS queries for them
# Used in testing DNS tunneling detection
# PASSED ✅
ROOT="example.com"    # any real domain will work

for i in $(seq 1 50); do
  # generate 8 hex characters (no chance of invalid bytes):
  RAND_LABEL=$(openssl rand -hex 4)

  FQDN="${RAND_LABEL}.${ROOT}"
  # fire off a TXT query for that random subdomain
  dig +short -t TXT "${FQDN}" @8.8.8.8 > /dev/null &
  sleep 0.3
done

wait
echo "Done sending 50 random-subdomain queries to ${ROOT}"
