from scapy.all import PcapReader, PcapWriter, IP, TCP

input_pcap = "/home/taut/Downloads/Wednesday-workingHours.pcap"
output_pcap = "/home/taut/Downloads/updated.pcap"

with PcapReader(input_pcap) as reader, PcapWriter(output_pcap, sync=True) as writer:
    for pkt in reader:
        # Filter non-TCP packets with IP layer
        if IP in pkt and not pkt.haslayer(TCP):
            pkt[IP].dst = "127.0.0.1"
            del pkt[IP].chksum  # force recalculation
            writer.write(pkt)
