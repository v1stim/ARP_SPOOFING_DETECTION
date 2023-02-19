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
    mac_addresses_seen_so_far = {}
    for ip, mac in addresses.items():
        if mac in mac_addresses_seen_so_far:
            message = f"Possible ARP Spoofing detected. MAC: {mac}, IPs: {', '.join(mac_addresses_seen_so_far[mac] + [ip])}"
            logging.warning(message)
        else:
            mac_addresses_seen_so_far[mac] = [ip]

#menu with keyboardInterrupt handling and log closing
def main_menu():
    interval = 60
    try:
        while True:
            print(f"1. Start ARP Spoof Detection with {interval} sec interval")
            print("2. Change interval")
            print("3. Exit")
            choice = input("Enter your choice: ")
            if choice == '1':
                print("ARP Spoof Detection started...")
                logging.info("Starting ARP scan.")
                logging.info(f"Scan interval set to {interval}")
                try:
                    while True:
                        extract_arp_table()
                        time.sleep(interval)
                except KeyboardInterrupt:
                    logging.info("KeyboardInterrupt received, stopping ARP Spoof Detection.")
                    break
            elif choice == '2':
                interval = int(input("Enter interval in seconds: "))
            elif choice == '3':
                print("Stopping ARP Spoof Detection...")
                break
            else:
                print("Invalid choice, please try again.")
    finally:
        logging.shutdown()


if __name__ == "__main__":
    main_menu()
