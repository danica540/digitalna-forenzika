import subprocess
import os
import json
import tld
import re as regex
from alive_progress import alive_bar
from datetime import datetime
from pprint import pprint


def _is_ip_address(input):
    """Checks if given input is IPv4 address"""
    return regex.match(r'^(\d{1,3}\.){3}\d{1,3}', input)


def _resolve_hostname(hostname):
    """Extract TLD information from hostname"""
    try:
        if _is_ip_address(hostname) or '.local' in hostname:
            return None
        return tld.get_tld(url=hostname,
                           fix_protocol=True,
                           as_object=True)
    except tld.exceptions.TldDomainNotFound:
        print(f"ERROR: Lookup failed for {hostname}")
        return None


def _enrich_packet_info(normalized_packet):
    """Fills TLD info for source/destination"""

    source_tld_info = _resolve_hostname(normalized_packet['source']['host'])
    if source_tld_info:
        normalized_packet['source']['domain'] = source_tld_info.domain
        normalized_packet['source']['subdomain'] = source_tld_info.subdomain
        normalized_packet['source']['fld'] = source_tld_info.fld
    else:
        normalized_packet['source']['domain'] = None
        normalized_packet['source']['subdomain'] = None
        normalized_packet['source']['fld'] = None

    destination_tld_info = _resolve_hostname(
        normalized_packet['destination']['host'])
    if destination_tld_info:
        normalized_packet['destination']['domain'] = destination_tld_info.domain
        normalized_packet['destination']['subdomain'] = destination_tld_info.subdomain
        normalized_packet['destination']['fld'] = destination_tld_info.fld
    else:
        normalized_packet['destination']['domain'] = None
        normalized_packet['destination']['subdomain'] = None
        normalized_packet['destination']['fld'] = None

    return normalized_packet


def _normalize_tshark_packet(packet):
    """Converts tshark json packet to internal representation"""

    packet_properties = packet['_source']['layers']
    timestamp = datetime.fromtimestamp(
        float(packet_properties['frame.time_epoch'][0]))
    protocols = packet_properties['frame.protocols'][0].split(':')
    base_protocol = 'tcp' if 'tcp' in protocols else 'udp'
    app_protocol = protocols[-1]

    if base_protocol == 'tcp':
        source_port = int(packet_properties['tcp.srcport'][0])
        destination_port = int(packet_properties['tcp.dstport'][0])
        data_length = int(packet_properties['tcp.len'][0])
        tcp_sequence = int(packet_properties['tcp.seq'][0])
        tcp_next_sequence = int(packet_properties['tcp.nxtseq'][0])
        stream = int(packet_properties['tcp.stream'][0])
    else:
        source_port = int(packet_properties['udp.srcport'][0])
        destination_port = int(packet_properties['udp.dstport'][0])
        data_length = int(packet_properties['udp.length'][0])
        tcp_sequence = None
        tcp_next_sequence = None
        stream = int(packet_properties['udp.stream'][0])

    if 'ip.len' not in packet_properties.keys():
        pprint(packet)
        exit(1)

    return {
        'timestamp': timestamp,
        'protocols_string': packet_properties['frame.protocols'][0],
        'protocols': protocols,
        'base_protocol': base_protocol,
        'app_protocol': app_protocol,
        'size': {
            'frame_length': int(packet_properties['frame.len'][0]),
            'ip_length': int(packet_properties['ip.len'][0]),
            'data_length': data_length,
        },
        'source': {
            'address': packet_properties['ip.src'][0],
            'host': packet_properties['ip.src_host'][0],
            'port': source_port,
        },
        'destination': {
            'address': packet_properties['ip.dst'][0],
            'host': packet_properties['ip.dst_host'][0],
            'port': destination_port,
        },
        'tcp_sequence': tcp_sequence,
        'tcp_next_sequence': tcp_next_sequence,
        'stream': stream
    }


def load_packets(pcap_file):
    """Loads packets from pcap_file for further analysis"""

    print(f"[i] Filter packets (tshark)")
    with alive_bar(spinner='fish') as bar:
        tshark_output = subprocess.run(["tshark",
                                    f"-r{os.path.abspath(pcap_file)}",
                                    f"-Tjson",
                                    f"-eframe.time_epoch",
                                    f"-eframe.protocols",
                                    f"-eframe.len",
                                    f"-eip.src",
                                    f"-eip.src_host",
                                    f"-eip.dst",
                                    f"-eip.dst_host",
                                    f"-eip.len",
                                    f"-etcp.srcport",
                                    f"-etcp.dstport",
                                    f"-etcp.stream",
                                    f"-etcp.len",
                                    f"-etcp.seq",
                                    f"-etcp.nxtseq",
                                    f"-eudp.srcport",
                                    f"-eudp.dstport",
                                    f"-eudp.stream",
                                    f"-eudp.length",
                                    f"-NmnNtdv",
                                    f"ip && (tcp || udp)"
                                    ],
                                   capture_output=True,
                                   text=True,
                                   check=True)
        filtered_packets = json.loads(tshark_output.stdout)

    print(f"[i] Normalize packets")
    normalized_packets = []
    with alive_bar(len(filtered_packets),bar='filling') as bar:
        for packet in filtered_packets:
            normalized_packets.append(_normalize_tshark_packet(packet))                    # process each item
            bar()                 
   
    print(f"[i] Enrich packets info")
    enriched_packets = []
    with alive_bar(len(normalized_packets),bar='filling') as bar:
        for packet in normalized_packets:
            enriched_packets.append(_enrich_packet_info(packet))                    # process each item
            bar() 

    return enriched_packets
