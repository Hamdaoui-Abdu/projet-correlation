import argparse
import json
from pathlib import Path

from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk



def load_json(file_path):
    """
    Load the correlation result produced by correlator.py.
    """

    file_path = Path(file_path)

    if not file_path.exists():
        raise FileNotFoundError(f"JSON file not found: {file_path}")

    with file_path.open("r", encoding="utf-8") as file:
        return json.load(file)



def flatten_matched_event(event):
    """
    A 'matched' event looks like:
        {"correlation_status": ..., "sysmon": {...}, "pcap": {...}, ...}

    Kibana works best with a flat document, so we merge the
    sysmon and pcap sub-objects into one dictionary, prefixing
    each field to avoid name collisions (both sides could have
    a field with the same name).
    """

    flat = {
        "correlation_status": event.get("correlation_status"),
        "time_delta_seconds": event.get("time_delta_seconds"),
        "direction": event.get("direction"),
        "mitre_technique_id": event.get("mitre_technique_id"),
        "mitre_technique_name": event.get("mitre_technique_name"),
        "suspicion_score": event.get("suspicion_score"),
        "severity": event.get("severity"),
    }

    sysmon = event.get("sysmon", {})
    for key, value in sysmon.items():
        flat[f"sysmon_{key}"] = value

    pcap = event.get("pcap", {})
    for key, value in pcap.items():
        flat[f"pcap_{key}"] = value

    # @timestamp is required by Elasticsearch/Kibana to place
    # the event on the timeline: reuse the Sysmon side's value
    flat["@timestamp"] = sysmon.get("@timestamp")

    return flat


def flatten_simple_event(event):
    """
    A 'sysmon_only' or 'pcap_only' event is already flat
    (produced directly by sysmon_parser.py or pcap_parser.py,
    then enriched by correlator.py). Nothing to merge here.
    """

    return event



def build_actions(events, index_name, flatten_function):
    """
    Turn a list of event dictionaries into the format expected
    by Elasticsearch's bulk helper: one dict per document, with
    the target index and the document body.
    """

    for event in events:
        document = flatten_function(event)

        yield {
            "_index": index_name,
            "_source": document,
        }



def build_client(host, user, password, verify_certs):
    """
    Create an authenticated Elasticsearch client.
    """

    client = Elasticsearch(
        host,
        basic_auth=(user, password),
        verify_certs=verify_certs,
    )

    if not client.ping():
        raise ConnectionError(
            f"Could not reach Elasticsearch at {host}. "
            "Check the host, credentials and certificate settings."
        )

    return client


def main():

    parser = argparse.ArgumentParser(
        description="Index correlated DFIR events into Elasticsearch."
    )

    parser.add_argument(
        "--input",
        required=True,
        help="Correlation result JSON file produced by correlator.py",
    )

    parser.add_argument(
        "--index",
        default="dfir-events",
        help="Target Elasticsearch index name (default: dfir-events)",
    )

    parser.add_argument(
        "--host",
        default="https://10.0.3.20:9200",
        help="Elasticsearch host URL (default: https://10.0.3.20:9200)",
    )

    parser.add_argument(
        "--user",
        default="elastic",
        help="Elasticsearch username (default: elastic)",
    )

    parser.add_argument(
        "--password",
        required=True,
        help="Elasticsearch password for the given user",
    )

    parser.add_argument(
        "--no-verify-certs",
        action="store_true",
        help="Disable TLS certificate verification (lab use only, self-signed cert)",
    )

    args = parser.parse_args()

    print(f"[+] Loading correlation results from {args.input}...")
    data = load_json(args.input)

    matched = data.get("matched", [])
    sysmon_only = data.get("sysmon_only", [])
    pcap_only = data.get("pcap_only", [])

    print(f"[+] Matched events: {len(matched)}")
    print(f"[+] Sysmon-only events: {len(sysmon_only)}")
    print(f"[+] PCAP-only events: {len(pcap_only)}")

    print()
    print(f"[+] Connecting to Elasticsearch at {args.host}...")
    client = build_client(
        host=args.host,
        user=args.user,
        password=args.password,
        verify_certs=not args.no_verify_certs,
    )
    print("[+] Connection successful.")

    print()
    print(f"[+] Indexing into '{args.index}'...")

    all_actions = list(build_actions(matched, args.index, flatten_matched_event))
    all_actions += list(build_actions(sysmon_only, args.index, flatten_simple_event))
    all_actions += list(build_actions(pcap_only, args.index, flatten_simple_event))

    success_count, errors = bulk(client, all_actions, raise_on_error=False)

    print()
    print("========== INDEXING RESULTS ==========")
    print(f"[+] Documents indexed successfully: {success_count}")
    print(f"[+] Documents with errors: {len(errors)}")

    if errors:
        print("[!] First few errors:")
        for error in errors[:5]:
            print(f"    - {error}")



if __name__ == "__main__":
    main()
  
