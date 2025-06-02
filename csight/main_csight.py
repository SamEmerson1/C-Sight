import os
import sys
from config import load_config
from pyshark_translator import run_sniffer

# Preset definitions
LEVEL_PROTOCOLS = {
    1: ["TLS", "HTTP", "SSH"],
    2: ["TLS", "HTTP", "SSH", "DNS"],
    3: ["TLS", "HTTP", "SSH", "DNS", "QUIC"]
}

# These are the level-specific detectors
LEVEL_DETECTORS = {
    1: [
        "excessive_tls",
        "malicious_url_access",
        "sensitive_cleartext",
        "ssh_unusual_ports",
        "tls_handshake_rate",
        "unexpected_regions"
    ],
    2: [
        "dns_tunneling_patterns",
        "frequent_nxdomain"
    ],
    3: [
        "abnormal_quic"
    ]
}

CONFIG_PATH = "config.json"


# Apply the level settings, enabling and disabling detectors
def apply_level(config, level, include_ip_owners=False):
    config["enabled_protocols"] = LEVEL_PROTOCOLS[level]
    
    config["user_level"] = level

    for d in config["detectors"]:
        config["detectors"][d]["enabled"] = False

    for l in range(1, level + 1):
        for d in LEVEL_DETECTORS[l]:
            config["detectors"][d]["enabled"] = True

    config["load_ip_owners"] = include_ip_owners

    print(f"Enabled Detectors:")
    for d in config["detectors"]:
        if config["detectors"][d]["enabled"]:
            print(f"   - {d}")
    print(f"Enabled Protocols: {', '.join(config['enabled_protocols'])}")
    if include_ip_owners:
        print("🌐 IP ownership database: ENABLED")
    else:
        print("🌐 IP ownership database: DISABLED")


def show_main_menu():
    print("\nWelcome to C-Sight")
    print("-----------------------")
    print("1. Run C-Sight")
    print("2. Edit Config")
    print("3. Glossary / Info")
    print("4. Exit")
    return input("Select: ").strip()


def show_level_menu():
    print("\nChoose complexity level:")
    print("1. Basic - TLS, HTTP, SSH")
    print("2. Smart - Adds DNS")
    print("3. Full Power - Adds QUIC + IP metadata (optionally)")
    choice = input("Select level (1-3): ").strip()
    if choice in ['1', '2', '3']:
        return int(choice)
    else:
        print("❌ Invalid selection. Please enter 1, 2, or 3.")


# Ask the user if they want to load the IP ownership database
def prompt_ip_owners():
    print("\nWould you like to load the IP ownership database?")
    choice = input("(y/n): ").strip().lower()
    return choice == 'y'


# Start the sniffer in pyshark_translator
def handle_run():
    config = load_config()
    level = show_level_menu()
    include_ip_db = False

    if level == 3:
        include_ip_db = prompt_ip_owners()

    apply_level(config, level, include_ip_db)

    print("\nStarting C-Sight...\n")
    run_sniffer(config)
    print("Done. Exiting C-Sight.")
    sys.exit(0)

# Open the config file, allowing the user to edit it from terminal
def handle_config():
    os.system("nano config.json")


if __name__ == "__main__":
    while True:
        choice = show_main_menu()
        if choice == '1':
            handle_run()
        elif choice == '2':
            handle_config()
        elif choice == '3':
            print("\nGlossary coming soon!")
        elif choice == '4':
            print("Exiting C-Sight.")
            break
        else:
            print("❌ Invalid selection.")
