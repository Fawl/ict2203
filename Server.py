from scapy.all import *
import argparse
from utils import is_valid_IPV4, is_valid_MAC, starve_logger, MAC_BROADCAST, IPV4_BROADCAST

# These variables can be changed to anything depending on ip of server etc...
# SERVERIP = "192.168.0.2"
# CLIENTIP = "192.168.0.6"
# SERVERMAC = "00:0B:CD:AE:9F:C6"
# CLIENTMAC = "00:02:a5:ea:54:20"
# SUBMASK = "255.255.255.0"
# GATEWAY = "192.168.0.254"

# parser = argparse.ArgumentParser(description="Configure network variables")
# parser.add_argument('ClientIP', type=str, help='Set Client IP')
# parser.add_argument('ServerIP', type=str, help='Set Server IP')
# parser.add_argument('ClientMAC', type=str, help='Set Client MAC')
# parser.add_argument('ServerMAC', type=str, help='Set Server MAC')
# parser.add_argument('SubnetMask', type=str, help='Set Subnet Mask')
# parser.add_argument('DefaultGateway', type=str, help='Set Default Gateway')
# args = parser.parse_args()


class DHCPServer():
    '''
    Basic implementation of a DHCP Server.
    '''
    def __init__(self, start_ip: str = None, max_clients: int = 10, own_mac: str = None, own_ip: str = None, subnet_mask: str = None, default_gateway: str = None):
        '''
        Load constants, setup variables and objects.
        - _start_ip          - Defines starting IP address for DHCP pool. Defaults to 10.0.0.2
        - _max_clients       - Defines the maximum number of IP addresses server will lease. Defaults to 10.
        - _own_mac           - Defines custom MAC for this DHCP server. Defaults to legitimate MAC.
        - _own_ip            - Defines custom IP address for this DHCP server. Defaults to legitimate IP.
        - _subnet_mask       - Defines custom subnet mask for this DHCP server. Defaults to /24.
        - _default_gateway   - Defines custom default gateway for this DHCP server. Defaults to legitimate default gateway.
        - _distributed_ips   - Set to hold all IPs leased to clients.
        - _dhcp_mapping      - Holds all DHCP bindings.
        '''
        if start_ip is not None and is_valid_IPV4(start_ip):
            self._start_ip = start_ip
        else:
            self._start_ip = "10.0.0.2"
        self._ip_crib = '.'.join(self._start_ip.split(".")[:-1]) + "."
        self._curr_count = int(self._start_ip.split(".")[-1])

        try:
            self._max_clients = int(max_clients)
        except ValueError:
            self._max_clients = 10

        if own_mac is not None and is_valid_MAC(own_mac):
            self._mac = own_mac
        else:
            self._mac = get_if_hwaddr(conf.iface)

        if own_ip is not None and is_valid_IPV4(own_ip):
            self._ip = own_ip
        else:
            self._ip = get_if_addr(conf.iface)

        if subnet_mask is not None:
            self._subnet_mask = subnet_mask
        else:
            self._subnet_mask = "255.255.255.0"

        if default_gateway is not None and is_valid_IPV4(default_gateway):
            self._default_gateway = default_gateway
        else:
            self._default_gateway =  conf.route.route("0.0.0.0")[2]

        self._distributed_ips = set()
        self._dhcp_mapping = dict()


    def start(self):
        '''
        Driver code
        '''
        sniff(filter="udp and (port 67 or 68)", prn=self.dhcp_callback, store=0)


    def dhcp_callback(self, pkt):
        '''
        Callback function to perform regular DHCP server functions.
        Responds with OFFER to DISCOVER.
        Responds with ACK to REQUEST.
        '''
        pkt.show()
        if pkt[DHCP] and pkt[DHCP].options[0][1] == 1:
            dscvr_mac = pkt[BOOTP].chaddr
            transaction_id = pkt[BOOTP].xid
            starve_logger.info(f"TRANSACTION {transaction_id}:  DHCP DISCOVER from MAC {dscvr_mac}")

            if len(self._distributed_ips) < self._max_clients:
                self._curr_count += 1

                new_ip = f"{self._ip_crib}{self._curr_count}"
                starve_logger.info(f"Leasing new IP: {new_ip}.")

                self._distributed_ips.add(new_ip)
                self._dhcp_mapping[dscvr_mac] = new_ip

                ethernet = Ether(src=self._mac, dst=MAC_BROADCAST)
                ip = IP(src=self._ip, dst=IPV4_BROADCAST)
                udp = UDP(sport=67, dport=68)
                bootp = BOOTP(
                    op=2,
                    yiaddr=new_ip,
                    siaddr=self._ip,
                    giaddr=self._default_gateway,
                    chaddr=dscvr_mac,
                    xid=transaction_id
                )
                dhcp = DHCP(options=[("message-type", "offer"), ("server_id", self._ip), ("broadcast_address", IPV4_BROADCAST), ("router", self._default_gateway), ("subnet_mask", self._subnet_mask), "end"])

                DHCP_OFFER_PKT = ethernet/ip/udp/bootp/dhcp
                sendp(DHCP_OFFER_PKT, verbose=0)

                starve_logger.info(f"TRANSACTION {transaction_id}: Sending DHCP OFFER.")

        elif pkt[DHCP] and pkt[DHCP].options[0][1] == 3:
            print(self._distributed_ips)
            req_ip = pkt[BOOTP].ciaddr
            print(req_ip)
            if req_ip in self._distributed_ips:
                req_mac = pkt[BOOTP].chaddr
                transaction_id = pkt[BOOTP].xid
                starve_logger.info(f"TRANSACTION {transaction_id}:  DHCP REQUEST from MAC {req_mac} for IP {req_ip}")

                ethernet = Ether(src=self._mac, dst="ff:ff:ff:ff:ff:ff")
                ip = IP(src=self._ip, dst=IPV4_BROADCAST)
                udp = UDP(sport=67, dport=68)
                bootp = BOOTP(
                    op=2,
                    yiaddr=req_ip,
                    siaddr=self._ip,
                    giaddr=self._default_gateway,
                    chaddr=req_mac,
                )
                dhcp = DHCP(options=[("message-type", "ack"), ("server_id", self._ip), ("broadcast_address",
                                                                                        IPV4_BROADCAST), ("router", self._default_gateway), ("subnet_mask", self._subnet_mask)])
                DHCP_ACK_PKT = ethernet/ip/udp/bootp/dhcp
                sendp(DHCP_ACK_PKT)

                starve_logger.info(f"TRANSACTION {transaction_id}: Sending DHCP ACK")


def main():
    s = DHCPServer()
    s.start()

if __name__ == '__main__':
    main()
