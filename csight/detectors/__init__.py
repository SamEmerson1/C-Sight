# Import the detect() function from the DNS-tunneling module:
from .dns_tunneling_patterns import detect as dns_tunnel_detect
from .abnormal_quic import detect as abnormal_quic_detect
from .malicious_url_access import detect as malicious_url_detect
from .unexpected_regions import detect as unexpected_region_detect
from .frequent_nxdomain import detect as nxdomain_spike_detect
from .sensitive_cleartext import detect as sensitive_cleartext_detect
from .excessive_tls import detect as excessive_tls_detect
from .ssh_unusual_ports import detect as ssh_unusual_ports_detect
from .tls_handshake_rate import detect as tls_handshake_rate_detect


# List of all detectors we want to run (add new detectors here later):
ALL_DETECTORS = [
    dns_tunnel_detect,
    abnormal_quic_detect,
    malicious_url_detect,
    unexpected_region_detect,
    nxdomain_spike_detect,
    sensitive_cleartext_detect,
    excessive_tls_detect,
    ssh_unusual_ports_detect,
    tls_handshake_rate_detect,
    # add other detectors here
]