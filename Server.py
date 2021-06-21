from scapy.all import *
import argparse

# These variables can be changed to anything depending on ip of server etc...
# SERVERIP = "192.168.0.2"
# CLIENTIP = "192.168.0.6"
# SERVERMAC = "00:0B:CD:AE:9F:C6"
# CLIENTMAC = "00:02:a5:ea:54:20"
# SUBMASK = "255.255.255.0"
# GATEWAY = "192.168.0.254"

parser = argparse.ArgumentParser(description="Configure network variables")
parser.add_argument('ClientIP', type=str, help='Set Client IP')
parser.add_argument('ServerIP', type=str, help='Set Server IP')
parser.add_argument('ClientMAC', type=str, help='Set Client MAC')
parser.add_argument('ServerMAC', type=str, help='Set Server MAC')
parser.add_argument('SubnetMask', type=str, help='Set Subnet Mask')
parser.add_argument('DefaultGateway', type=str, help='Set Default Gateway')
args = parser.parse_args()


def detect_dhcp(packet):
    """
    Simple DHCP server:
        If detect DHCP DISCOVER pkt, sends the OFFER pkt

        If detect the DHCP REQUEST pkt, sends the DHCP ACK pkt
    """
    # if DHCP DISCOVER, DHCP OFFER
    if pkt[DHCP] and pkt[DHCP].options[0][1] == 1:
        print("\nReceived DHCP DISCOVER")

        ethernet = Ether(src=args.ServerMAC, dst="ff:ff:ff:ff:ff:ff")
        ip = IP(src=args.ServerIP, dst="255.255.255.255")
        udp = UDP(sport=67, dport=68)
        bootp = BOOTP(
            op=2,
            yiaddr=args.ClientIP,
            siaddr=args.ServerIP,
            giaddr=args.DefaultGateway,
            chaddr=args.ClientMAC,
        )
        dhcp = DHCP(options=[("message-type", "offer"), ("server_id", args.ServerIP), ("broadcast_address",
                                                                                  "255.255.255.255"), ("router", args.DefaultGateway), ("subnet_mask", args.SubnetMask)])

        DHCP_OFFER_PKT = ethernet/ip/udp/bootp/dhcp
        sendp(DHCP_OFFER_PKT)

        print("\nSending DHCP OFFER")

    # if DHCP REQUEST, DHCP ACK
    if pkt[DHCP] and pkt[DHCP].options[0][1] == 3:
        print("\nReceived DHCP REQUEST")

        ethernet = Ether(src=args.ServerMAC, dst="ff:ff:ff:ff:ff:ff")
        ip = IP(src=args.ServerIP, dst="255.255.255.255")
        udp = UDP(sport=67, dport=68)
        bootp = BOOTP(
            op=2,
            yiaddr=args.ClientIP,
            siaddr=args.ServerIP,
            giaddr=args.DefaultGateway,
            chaddr=args.ClientMAC,
        )
        dhcp = DHCP(options=[("message-type", "ack"), ("server_id", args.ServerIP), ("broadcast_address",
                                                                                "255.255.255.255"), ("router", args.DefaultGateway), ("subnet_mask", args.SubnetMask)])
        DHCP_ACK_PKT = ethernet/ip/udp/bootp/dhcp
        sendp(DHCP_ACK_PKT)

        print("\nSending DHCP ACK")


def start():
    """
    Sniff DHCP pkts
    """
    sniff(filter="arp or (udp and (port 67 or 68))", prn=detect_dhcp, store=0)


def main():
    start()


if __name__ == '__main__':
    main()
