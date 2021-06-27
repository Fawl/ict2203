"""
ICT2203 Assignment 1B 
LOW WEI YANG (2003120)
JARED MARC SONG KYE-JET (2003109)
KUO EUGENE (2003113)
AMOS NG (2003104)
"""

import ipaddress

from scapy.all import *

from utils import *


class DHCPServer:
    """
    Basic implementation of a DHCP Server.
    """

    def __init__(self, addr: str = "10.20.30.0/29", mac: str = None, gw: str = None):
        """DHCPServer initialisation method

        :param addr: Assignable address pool of DHCP server, defaults to "10.20.30.0/29"
        :type addr: str, optional
        :param mac: MAC address of DHCP server, defaults to first interface
        :type mac: str, optional
        :param gw: Gateway of DHCP leases, defaults to first default route
        :type gw: str, optional
        """
        # Get interface MAC
        if mac is not None and is_valid_mac(mac):
            self._mac = mac
        else:
            self._mac = get_if_hwaddr(conf.iface)

        # Get default route
        if gw is not None and is_valid_ipv4(gw):
            self._default_gateway = gw
        else:
            self._default_gateway = conf.route.route("0.0.0.0")[2]

        # Prepare network addresses
        self._network = list(str(i) for i in ipaddress.ip_network(addr))[1:-1]
        print(self._network)
        self._assignments = dict.fromkeys(self._network, None)

        # Assign first IP to self
        self._ip = next(iter(self._assignments))
        self._assignments[self._ip] = self._mac

        # Set subnet mask
        self._subnet_mask = cidr_to_netmask(addr)[1]

        # Prepare DHCP header
        self._dhcp_header = generate_dhcp_packet_header(self._mac, self._ip)

        # Log
        logger.info("Starting DHCP server!")

    def start(self):
        sniff(filter=DHCP_FILTER, prn=self.dhcp_callback, store=0)

    def show_dhcp_stats(self):
        logger.info("SERVER DHCP BINDINGS:")
        for ip, mac in self._assignments.items():
            if mac is not None:
                logger.info(f"\t{mac} - {ip}")

    def get_leased(self, m: str = None) -> Optional[str]:
        # Check to see if IP has already been leased to MAC
        for ip, mac in self._assignments.items():
            if mac == m:
                return ip

        # If not None, try and return next available unleased IP address
        if m is not None:
            for ip, mac in self._assignments.items():
                if mac is None:
                    return ip

        # Return None
        return None

    def dhcp_callback(self, pkt):
        """
        Callback function to perform regular DHCP server functions.
        Responds with OFFER to DISCOVER.
        Responds with ACK to REQUEST.
        """
        pkt.show()

        if DHCP in pkt:
            if BOOTP in pkt:
                client_mac = pkt[BOOTP].chaddr
                transaction_id = pkt[BOOTP].xid

                # Handle DHCP DISCOVER frames
                if get_option(pkt[DHCP].options, "message-type") == 1:
                    # Get DHCP DISCOVER packet details
                    logger.info(f"TRANSACTION {transaction_id}: DHCP DISCOVER from MAC {client_mac}")

                    # Check if there is an address to lease
                    available_ip = self.get_leased(macbytes2str(client_mac))
                    if available_ip is not None:
                        # Lease to MAC
                        self._assignments[available_ip] = macbytes2str(client_mac)

                        # Prepare & send DHCP OFFER frame
                        bootp = BOOTP(
                            op=2,
                            yiaddr=available_ip,
                            siaddr=self._ip,
                            giaddr=self._ip,
                            chaddr=client_mac,
                            xid=transaction_id,
                        )
                        dhcp = DHCP(
                            options=[
                                ("message-type", "offer"),
                                ("server_id", self._ip),
                                ("broadcast_address", IPV4_BROADCAST),
                                ("router", self._ip),
                                ("subnet_mask", self._subnet_mask),
                                ("lease_time", 3600),
                                "end",
                            ]
                        )
                        DHCP_OFFER_PKT = self._dhcp_header / bootp / dhcp
                        sendp(DHCP_OFFER_PKT, verbose=0)

                        logger.info(f"TRANSACTION {transaction_id}: Sending DHCP OFFER.")
                    else:
                        logger.warning("More DHCP DISCOVER packets incoming, but pool is depleted!")

                # Hande DHCP REQUEST frames
                elif get_option(pkt[DHCP].options, "message-type") == 3:
                    req_ip = get_option(pkt[DHCP].options, "requested_addr")

                    if self._assignments[req_ip] == macbytes2str(client_mac):
                        logger.info(
                            f"TRANSACTION {transaction_id}: DHCP REQUEST from MAC {macbytes2str(client_mac)} for IP {req_ip}"
                        )

                        # Prepare & send DHCP ACK frame
                        bootp = BOOTP(
                            op=3,
                            yiaddr=req_ip,
                            siaddr=self._ip,
                            giaddr=self._ip,
                            chaddr=client_mac,
                            xid=transaction_id,
                        )
                        dhcp = DHCP(
                            options=[
                                ("message-type", "ack"),
                                ("server_id", self._ip),
                                ("broadcast_address", IPV4_BROADCAST),
                                ("router", self._ip),
                                ("subnet_mask", self._subnet_mask),
                                ("lease_time", 3600),
                                "end",
                            ]
                        )
                        DHCP_ACK_PKT = self._dhcp_header / bootp / dhcp
                        sendp(DHCP_ACK_PKT, verbose=0)

                        logger.info(f"TRANSACTION {transaction_id}: Sending DHCP ACK")
                        self.show_dhcp_stats()


def main():
    s = DHCPServer()
    s.start()


if __name__ == "__main__":
    main()
