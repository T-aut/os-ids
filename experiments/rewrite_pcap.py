from scapy.all import PcapReader, PcapWriter, IP, TCP, Ether
import netifaces

input_pcap = "/home/taut/Downloads/Wednesday-workingHours.pcap"
output_pcap = "/home/taut/Downloads/updated_mac.pcap"

iface = "ens160"
mac = netifaces.ifaddresses(iface)[netifaces.AF_LINK][0]['addr']

with PcapReader(input_pcap) as reader, PcapWriter(output_pcap, sync=True) as writer:
    for pkt in reader:
        # Filter non-TCP packets with IP layer
        if IP in pkt and not pkt.haslayer(TCP):
            pkt[IP].dst = "192.168.0.104"
            pkt[Ether].dst = mac  # important!
            del pkt[IP].chksum # force recalculation
            del pkt[Ether].chksum
            writer.write(pkt)
