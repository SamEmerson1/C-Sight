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
        print("📚 IP ownership database: ENABLED")
    else:
        print("📚 IP ownership database: DISABLED")


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


# Glossary page
def handle_glossary():
    glossary_sections = [
        ("📌 FOR DATABASE INFO 📌", [
            ("Refer to my GitHub repo",
             "https://github.com/SamEmerson1/C-Sight?tab=readme-ov-file (Notes section)"),
        ]),
        ("📓 Basics", [
            ("Protocol", "A network protocol used for communication."),
            ("Detector", "A specific feature that can be enabled or disabled."),
            ("Level", "Determines the level of complexity of the logs."),
        ]),
        ("📘 Protocols", [
            ("TLS", "Encrypted protocol used for secure communication (e.g., HTTPS)."),
            ("HTTP", "Unencrypted web traffic, easy to inspect but insecure."),
            ("SSH", "Used for remote terminal access, usually on port 22."),
            ("DNS", "Translates domain names into IP addresses."),
            ("QUIC", "Modern encrypted protocol (used by HTTP/3), runs over UDP."),
        ]),
        ("🧠 Detectors", [
            ("DNS Tunnel Detect",
             "Identifies domains with suspicious patterns like high entropy or long/random subdomains — common in data exfiltration."),
            ("Abnormal QUIC Detect",
             "Spots unexpected QUIC traffic — useful for catching stealthy encrypted connections or malware using HTTP/3."),
            ("Malicious URL Detect",
             "Flags known malicious or phishing URLs based on threat intelligence feeds or heuristics."),
            ("Unexpected Region Detect",
             "Alerts when outbound traffic is sent to countries outside your trusted list — could signal C2 beacons or shady APIs."),
            ("NXDOMAIN Spike Detect",
             "Detects repeated failed DNS lookups (NXDOMAINs), which often indicate malware probing or DGA (domain generation algorithms)."),
            ("Sensitive Cleartext Detect",
             "Watches for credentials, tokens, or PII sent over unencrypted HTTP — major red flag for poor hygiene or leaks."),
            ("Excessive TLS Detect",
             "Flags bursts of outbound TLS connections in short time windows — often seen in beaconing or scanner activity."),
            ("SSH Unusual Ports Detect",
             "SSH traffic outside standard port 22 is suspicious — could be tunneling, misconfig, or attacker footholds."),
            ("TLS Handshake Rate Detect",
             "Monitors rapid TLS handshakes — a sign of scanning, automation, or evasion techniques like JA3 fuzzing."),
        ]),
        ("🛠 Levels", [
            ("Level 1", "Use if you're just watching web traffic. No DNS or QUIC."),
            ("Level 2", "Use if you're watching web traffic and DNS. No QUIC."),
            ("Level 3", "Use if you're watching web traffic, DNS, and QUIC."),
            ("Tip", "The higher the level, the more complex the logs will appear."),
        ])
    ]

    print("\n📚 C-Sight Glossary and Info")
    print("-" * 35)
    for section_title, entries in glossary_sections:
        print(f"\n{section_title}")
        print("-" * len(section_title))
        for name, desc in entries:
            print(f"• {name}: {desc}")
    print("\n🔙 Press Enter to return to the menu.")
    input()


if __name__ == "__main__":
    while True:
        choice = show_main_menu()
        if choice == '1':
            handle_run()
        elif choice == '2':
            handle_config()
        elif choice == '3':
            handle_glossary()
        elif choice == '4':
            print("Exiting C-Sight.")
            break
        else:
            print("❌ Invalid selection.")
