# Import the detect() function from the DNS-tunneling module:
from .dns_tunneling_patterns import detect as dns_tunnel_detect

# List of all detectors we want to run (add new detectors here later):
ALL_DETECTORS = [
    dns_tunnel_detect,
    # add other detectors here
]