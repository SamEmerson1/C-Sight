# Import the detect() function from the DNS-tunneling module:
from .dns_tunneling_patterns import detect as dns_tunnel_detect
from .abnormal_quic import detect as abnormal_quic_detect
from .malicious_url_access import detect as malicious_url_detect
from .unexpected_regions import detect as unexpected_region_detect
from .frequent_nxdomain import detect as nxdomain_spike_detect


# List of all detectors we want to run (add new detectors here later):
ALL_DETECTORS = [
    dns_tunnel_detect,
    abnormal_quic_detect,
    malicious_url_detect,
    unexpected_region_detect,
    nxdomain_spike_detect,
    # add other detectors here
]