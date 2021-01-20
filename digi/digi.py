import pcaper
import elastico
from pprint import pprint


def main():
    sample_file = './samples/sample02.pcapng'
    packets = pcaper.load_packets(pcap_file=sample_file)
    elastico.index_packets(packets)

if __name__ == "__main__":
    main()
