import os
import logging
import time
import platform

# configure logging
logging.basicConfig(
    filename='arp-spoof-detector.log',
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

#extract ARP table, should be system agnostic
def extract_arp_table():
    try:
        system = platform.system()
        if system == 'Windows':
            arp_table = os.popen("arp -a").read()
        elif system == 'Linux' or system == 'Darwin':
            arp_table = os.popen("arp -n").read()
        else:
            logging.error("Unsupported operating system: " + system)
            return {}
    except Exception as e:
        logging.error("Failed to extract ARP table: " + str(e))
        return {}
#take ARP, split in lines, skip broadcast and headers
#should be changed to use regex?
    arp_table_lines = arp_table.splitlines()
    addresses = {}
    for line in arp_table_lines:
        if "ff:ff:ff:ff:ff:ff" in line or "ff-ff-ff-ff-ff-ff" in line:
            continue
        if arp_table_lines.index(line) > 3:
            if "Interface" in line:
                continue
            ip, mac, _type = line.split()
            addresses[ip] = mac

    detect_arp_spoof(addresses)


def detect_arp_spoof(addresses):
    mac_addresses_seen_so_far = []
    logging.info("Starting ARP scan...")
    for mac in addresses.values():
        if mac in mac_addresses_seen_so_far:
            message = "Possible ARP Spoofing detected. The MAC address is: " + mac
            logging.warning(message)
            break
        mac_addresses_seen_so_far.append(mac)

def main_menu():
    while True:
        print("1. Start ARP Spoof Detection")
        print("2. Change interval")
        print("3. Stop ARP Spoof Detection")
        choice = input("Enter your choice: ")

        if choice == '1':
            interval = int(input("Enter interval in seconds: "))
            print("ARP Spoof Detection started...")
            while True:
                extract_arp_table()
                time.sleep(interval)
        elif choice == '2':
            interval = int(input("Enter interval in seconds: "))
        elif choice == '3':
            print("Stopping ARP Spoof Detection...")
            break
        else:
            print("Invalid choice, please try again.")

if __name__ == "__main__":
    main_menu()