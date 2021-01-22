import os
from alive_progress import alive_bar
from pprint import pprint

ads_path = os.path.dirname(os.path.realpath(
    __file__)) + "/resources/lookup_lists/ads.hosts"
assets_path = os.path.dirname(os.path.realpath(
    __file__)) + "/resources/lookup_lists/assets.hosts"
ads_hosts = None
assets_hosts = None


def _init():
    """Prepares lookup lists"""
    global ads_hosts, assets_hosts
    print("[i] Init lookup lists")

    print("[i] Assets hosts")
    with alive_bar(bar='filling') as bar:
        assets_hosts = []
        with open(assets_path, 'r') as assets_hosts_file:
            for line in assets_hosts_file:
                assets_hosts.append(line.strip())
                bar()
    print("[i] Ads hosts")
    with alive_bar(bar='filling') as bar:
        ads_hosts = []
        with open(ads_path, 'r') as ads_hosts_file:
            for line in ads_hosts_file:
                ads_hosts.append(line.strip())
                bar()


def _classify_host(hostname):

    if not hostname:
        return 'unknown'

    is_ads = any(ads_host in hostname for ads_host in ads_hosts)
    if is_ads:
        return 'ads'

    is_asset = any(asset_host in hostname for asset_host in assets_hosts)
    if is_asset:
        return 'asset'

    return 'site'


def _analyze_packet(packet, target_address):
    global ads_hosts, assets_hosts

    source_address = packet['source']['address']
    destination_address = packet['destination']['address']
    packet['classification'] = {}

    if source_address == target_address:
        packet['classification']['traffic_direction'] = 'outgoing'
        packet['classification']['type'] = _classify_host(
            packet['destination']['host'])
        # TODO: Improve detection
        packet['classification']['site'] = packet['destination']['domain']
    elif destination_address == target_address:
        packet['classification']['traffic_direction'] = 'receiving'
        packet['classification']['type'] = _classify_host(
            packet['source']['host'])
        # TODO: Improve detection
        packet['classification']['site'] = packet['source']['domain']
    else:
        print(f"[e] Unmatched traffic_direction")
        packet['classification']['traffic_direction'] = 'unknown'
        packet['classification']['type'] = 'unknown'
        packet['classification']['site'] = 'unknown'


def classify(packets, target_address):
    """Classify packets into type category"""
    print("[i] Classifying packets")

    _init()

    print("[i] Analyzing packets")
    with alive_bar(len(packets), bar='filling') as bar:
        for packet in packets:
            _analyze_packet(packet, target_address)
            bar()
    return packets
