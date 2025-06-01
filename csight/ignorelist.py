def load_ignorelist(filepath="ignorelist.txt") -> set:
    try:
        with open(filepath, "r") as f:
            return {line.strip() for line in f if line.strip()}
    except FileNotFoundError:
        return set()

IGNORELIST = load_ignorelist()

def should_ignore(packet_info: dict) -> bool:
    values_to_check = [
        packet_info.get("src_ip"),
        packet_info.get("dst_ip"),
        packet_info.get("tls_sni"),
        packet_info.get("http_host"),
        packet_info.get("dns_query"),
    ]
    return any(v in IGNORELIST for v in values_to_check if v)
