import csv
import ipaddress
import os
import time
import pytricia
from typing import Dict, Optional
from config import load_config

CONFIG = load_config()

DETECTOR_CONFIG = CONFIG.get("detectors", {}).get("unexpected_regions", {})

# Paths to MaxMind CSVs (06/01/25)
BASE_DIR = os.path.expanduser(DETECTOR_CONFIG.get(
    "base_dir", "~/Documents/C-Sight/C-Sight/csight/detectors"))
BLOCKS_V4 = os.path.join(BASE_DIR, DETECTOR_CONFIG.get(
    "blocks_v4", "GeoLite2-Country-Blocks-IPv4.csv"))
BLOCKS_V6 = os.path.join(BASE_DIR, DETECTOR_CONFIG.get(
    "blocks_v6", "GeoLite2-Country-Blocks-IPv6.csv"))
LOCATIONS = os.path.join(BASE_DIR, DETECTOR_CONFIG.get(
    "locations", "GeoLite2-Country-Locations-en.csv"))

# Whitelist of allowed countries
# Add/adjust to your needs
TRUSTED_COUNTRIES = set(DETECTOR_CONFIG.get("trusted_countries", []))

# Store last alert time per IP
last_alert_time = {}
ALERT_COOLDOWN = DETECTOR_CONFIG.get("cooldown", 30)  # seconds

# Lookup trees
pt4 = pytricia.PyTricia(32)
pt6 = pytricia.PyTricia(128)

# Maps geoname_id → country ISO code
geoname_to_country = {}

# Loaded flag
_loaded = False


# Lazy load geoip data (06/01/25)
def load_geoip_data():
    global _loaded
    if _loaded:
        return

    # First we load geoname_id → country_iso_code
    try:
        with open(LOCATIONS, newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                geoname_id = row["geoname_id"]
                iso_code = row["country_iso_code"]
                if geoname_id and iso_code:
                    geoname_to_country[geoname_id] = iso_code
    except Exception as e:
        print(f"❌ Failed to load locations: {e}")

    # Then we load IPv4 CIDRs
    try:
        with open(BLOCKS_V4, newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                cidr = row["network"]
                geo_id = row["geoname_id"] or row["registered_country_geoname_id"]
                iso = geoname_to_country.get(geo_id)
                if cidr and iso:
                    pt4[cidr] = iso
    except Exception as e:
        print(f"❌ Failed to load IPv4 blocks: {e}")

    # Finally we load IPv6 CIDRs
    try:
        with open(BLOCKS_V6, newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                cidr = row["network"]
                geo_id = row["geoname_id"] or row["registered_country_geoname_id"]
                iso = geoname_to_country.get(geo_id)
                if cidr and iso:
                    pt6[cidr] = iso
    except Exception as e:
        print(f"❌ Failed to load IPv6 blocks: {e}")

    _loaded = True


# === MAIN FUNCTION ===
# Each detector must override this function
# Returns a warning string if it's coming from an unexpected region, else None
# To test this detector, use a website like baidu.com (CN)
if not DETECTOR_CONFIG.get("enabled", True):
    def detect(packet_info: Dict) -> Optional[str]:
        return None
else:
    def detect(packet_info: Dict) -> Optional[str]:
        load_geoip_data()

        dst_ip = packet_info.get("dst_ip")
        if not dst_ip:
            return None

        try:
            ip_obj = ipaddress.ip_address(dst_ip)
            if ip_obj.version == 4:
                country = pt4.get(dst_ip)
            else:
                country = pt6.get(dst_ip)
        except Exception:
            return None

        if country and country not in TRUSTED_COUNTRIES:
            now = time.time()
            last_seen = last_alert_time.get(dst_ip, 0)
            if now - last_seen < ALERT_COOLDOWN:
                return None  # suppress repeat alert
            last_alert_time[dst_ip] = now
            return f"⚠️ UNEXPECTED REGION: {dst_ip} ({country})"

        return None
