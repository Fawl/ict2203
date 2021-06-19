from scapy.all import *

# These variables can be changed to anything depending on ip of server etc...
SERVERIP = "192.168.0.2"
CLIENTIP = "192.168.0.6"
SERVERMAC = "00:0B:CD:AE:9F:C6"
CLIENTMAC = "00:02:a5:ea:54:20"
SUBMASK = "255.255.255.0"
GATEWAY = "192.168.0.254"


def detect_dhcp(packet):
    """
    Simple DHCP server:
        If detect DHCP DISCOVER pkt, sends the OFFER pkt

        If detect the DHCP REQUEST pkt, sends the DHCP ACK pkt
    """
    # if DHCP DISCOVER, DHCP OFFER
    if pkt[DHCP] and pkt[DHCP].options[0][1] == 1:
        print("\nReceived DHCP DISCOVER")

        ethernet = Ether(src=SERVERMAC, dst="ff:ff:ff:ff:ff:ff")
        ip = IP(src=SERVERIP, dst="255.255.255.255")
        udp = UDP(sport=67, dport=68)
        bootp = BOOTP(
            op=2,
            yiaddr=CLIENTIP,
            siaddr=SERVERIP,
            giaddr=GATEWAY,
            chaddr=CLIENTMAC,
        )
        dhcp = DHCP(options=[("message-type", "offer"), ("server_id", SERVERIP), ("broadcast_address",
                                                                                  "255.255.255.255"), ("router", GATEWAY), ("subnet_mask", SUBMASK)])

        DHCP_OFFER_PKT = ethernet/ip/udp/bootp/dhcp
        sendp(DHCP_OFFER_PKT)

        print("\nSending DHCP OFFER")

    # if DHCP REQUEST, DHCP ACK
    if pkt[DHCP] and pkt[DHCP].options[0][1] == 3:
        print("\nReceived DHCP REQUEST")

        ethernet = Ether(src=SERVERMAC, dst="ff:ff:ff:ff:ff:ff")
        ip = IP(src=SERVERIP, dst="255.255.255.255")
        udp = UDP(sport=67, dport=68)
        bootp = BOOTP(
            op=2,
            yiaddr=CLIENTIP,
            siaddr=SERVERIP,
            giaddr=GATEWAY,
            chaddr=CLIENTMAC,
        )
        dhcp = DHCP(options=[("message-type", "ack"), ("server_id", SERVERIP), ("broadcast_address",
                                                                                "255.255.255.255"), ("router", GATEWAY), ("subnet_mask", SUBMASK)])
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
