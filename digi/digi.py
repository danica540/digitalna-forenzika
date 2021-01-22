import pcaper
import classifier
import elastico
import argparse


def main():
    parser = argparse.ArgumentParser(description='Digi network analyzer')
    parser.add_argument('--file', '-f',
                        metavar='path',
                        type=str,
                        help='PCAP file path')
    parser.add_argument('--ip', '-a', 
                        metavar='target_ip',
                        type=str,
                        help='Target IP')
    args = parser.parse_args()

    packets = pcaper.load_packets(pcap_file=args.file,
                                  target_address=args.ip)
    classified_packets = classifier.classify(packets=packets,
                                             target_address=args.ip)
    elastico.index_packets(packets)

    print(f"[i] Done. Check http://localhost:5601/s/digi/app/dashboards/digidash#/view/46aedd40-5b6d-11eb-a641-b11f170cc358")

if __name__ == "__main__":
    main()
