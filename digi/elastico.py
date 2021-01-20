import json
from alive_progress import alive_bar
from elasticsearch import Elasticsearch, ElasticsearchException

es_client = Elasticsearch(
    hosts=[{'host': 'localhost', 'port': 9200}])

es_index = "digi"
es_index_mapping = {
    "settings": {
        "index.mapping.ignore_malformed": True
    },
    "mappings": {
        "properties": {
            "timestamp": {"type": "date", "format": "strict_date_optional_time_nanos"},
            "protocol_string": {"type": "text"},
            "base_protocol": {"type": "keyword"},
            "app_protocol": {"type": "keyword"},
            "size": {
                "properties": {
                    "frame_length": {"type": "integer"},
                    "ip_length": {"type": "integer"},
                    "data_length": {"type": "integer"}
                }
            },
            "source": {
                "properties": {
                    "address": {"type": "ip"},
                    "host": {"type": "keyword"},
                    "port": {"type": "integer"},
                    "domain": {"type": "keyword"},
                    "subdomain": {"type": "keyword"},
                    "fld": {"type": "keyword"}
                }
            },
            "destination": {
                "properties": {
                    "address": {"type": "ip"},
                    "host": {"type": "keyword"},
                    "port": {"type": "integer"},
                    "domain": {"type": "keyword"},
                    "subdomain": {"type": "keyword"},
                    "fld": {"type": "keyword"}
                }
            },
            "tcp_sequence": {"type": "integer"},
            "tcp_next_sequence": {"type": "integer"},
            "stream": {"type": "integer"}
        }
    }
}


def _verify_connection():
    """Check if ES is reachable"""
    print(f"[i] Check ES connection")
    if not es_client.ping():
        raise ConnectionError("ES instance is unavailable")


def _create_index():
    """Configure ES index"""
    if es_client.indices.exists(es_index):
        return
    print(f"[i] \tCreate ES index: {es_index}")
    es_client.indices.create(es_index, json.dumps(es_index_mapping))


def _remove_index():
    """Removes ES index"""
    if es_client.indices.exists(es_index):
        print(f"[i] \tRemove ES index: {es_index}")
        es_client.indices.delete(es_index)


def _recreate_index():
    """Remove all data from index"""
    print(f"[i] Recreate ES index: {es_index}")
    _remove_index()
    _create_index()


def _init():
    """Reconfigures ES and Kibana resources"""
    print(f"[i] Init ES")
    _verify_connection()
    _recreate_index()


def index_packets(packets):
    """Index packets in ES index"""
    _init()

    print(f"[i] Index network packets in ES")
    with alive_bar(len(packets),bar='filling') as bar:
        for packet in packets:
            es_client.index(index=es_index,
                            body=packet)
            bar()
    print(f"[i] Index completed")
