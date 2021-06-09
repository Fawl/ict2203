from scapy.all import *

INTERFACE = "en0"
SPOOFED_IP = '192.168.1.3'
DESTINATION_IP = '192.168.1.5'
DNS_DESTINATION = '192.168.1.111'


def ping(source, destination, iface):
    """
    Send ICMP pckts
    """
    pkt = IP(src=source, dst=destination)/ICMP()
    srloop(IP(src=source, dst=destination)/ICMP(), iface=INTERFACE)


def send_spoofed_pkts():
    try:
        print("Starting Ping")
        ping(SPOOFED_IP, DESTINATION_IP, iface)
    except KeyboardInterrupt:
        print("Exiting.. ")
        sys.exit(0)


def dnsQuery(source, destination, iface):
    """
    Spoofed DNS query
    """
    pkt = IP(dst=destination, src=source)/UDP()/DNS(rd=1, qd=DNSQR(qname="example.com")) sr1(pkt)


def main():
    try:
        print("Starting Ping")
        dnsQuery(SPOOFED_IP, DNS_DESTINATION, INTERFACE)
    except KeyboardInterrupt:
        print("Exiting.. ")
        sys.exit(0)


if __name__ == '__main__':
    main()
