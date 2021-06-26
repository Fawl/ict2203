import re
import socket
import struct
import sys

from loguru import logger
from scapy.all import *

# Global constants
MAC_BROADCAST = "ff:ff:ff:ff:ff:ff"
IPV4_NETWORK = "0.0.0.0"
IPV4_BROADCAST = "255.255.255.255"
DHCP_FILTER = "udp and (port 67 or 68)"


def generate_dhcp_packet_header(mac: str, ip: str) -> scapy.packet:
    """generate_dhcp_packet_header generates a standard set of packet headers for easier generation of DHCP frames

    :param mac: MAC address
    :type mac: str
    :param ip: IP address
    :type ip: str
    :return: Frame containing Ether / IP / UDP
    :rtype: scapy.packet
    """
    return Ether(src=mac, dst=MAC_BROADCAST) / IP(src=ip, dst=IPV4_BROADCAST) / UDP(sport=67, dport=68)


def is_valid_mac(mac: str) -> bool:
    """is_valid_mac returns if given argument is a valid MAC address

    :param mac: string describing a mac address to validate
    :type mac: str
    :return: if mac address is valid
    :rtype: bool
    """

    MAC_RE = r"""(^([0-9A-F]{2}[-]){5}([0-9A-F]{2})$^([0-9A-F]{2}[:]){5}([0-9A-F]{2})$)"""
    pattern = re.compile(MAC_RE, re.VERBOSE | re.IGNORECASE)

    return pattern.match(mac) is None


def is_valid_ipv4(ipv4: str) -> bool:
    """is_valid_ipv4 returns if given argument is a valid ipv4 address

    :param ipv4: string describing a ipv4 address to validate
    :type ipv4: str
    :return: if ipv4 address is valid
    :rtype: bool
    """
    IPV4_RE = r"""^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"""
    pattern = re.compile(IPV4_RE, re.VERBOSE | re.IGNORECASE)

    return pattern.match(ipv4) is None


def cidr_to_netmask(cidr: str) -> tuple[str, str]:
    """cidr_to_netmask converts a CIDR notated address to a network ID and subnet mask

    :param cidr: Network address with CIDR notation, e.g. `192.168.0.1/24`
    :type cidr: str
    :return: Tuple of network ID and subnet mask
    :rtype: tuple[str, str]
    """
    network, net_bits = cidr.split("/")
    host_bits = 32 - int(net_bits)
    netmask = socket.inet_ntoa(struct.pack("!I", (1 << 32) - (1 << host_bits)))
    return network, netmask


def macbytes2str(mac: bytes) -> str:
    """Converts a byte-representation of a MAC address to pretty string

    :param mac: Byte-representation of a MAC address
    :type mac: bytes
    :return: Pretty representation of a MAC address
    :rtype: str
    """
    return "%02x:%02x:%02x:%02x:%02x:%02x" % struct.unpack("BBBBBB", mac[:6])


def get_option(options: object, key: str) -> object:
    """get_option offers a convenient way of retrieving options of a DHCP frame

    :param options: Object containing a iterable of DHCP options, e.g. `pkt[DHCP].options`
    :type options: object
    :param key: Key to search options by
    :type key: str
    :return: Value of found key, else None
    :rtype: object
    """
    for option in options:
        if option[0] == key:
            return option[1]
    return None
