import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from scapy.all import PcapReader, IP, IPv6, TCP, UDP


# ============================================================
# 1. TIMESTAMP NORMALIZATION
# ============================================================

def format_timestamp(packet_time):
    """
    Convert the packet timestamp to ISO 8601 UTC format.
    """

    timestamp = datetime.fromtimestamp(
        float(packet_time),
        tz=timezone.utc
    )

    return timestamp.isoformat().replace("+00:00", "Z")


# ============================================================
# 2. IP EXTRACTION
# ============================================================

def extract_ip_addresses(packet):
    """
    Extract source and destination IP addresses.
    Supports IPv4 and IPv6.
    """

    if IP in packet:
        return (
            packet[IP].src,
            packet[IP].dst
        )

    if IPv6 in packet:
        return (
            packet[IPv6].src,
            packet[IPv6].dst
        )

    return None, None


# ============================================================
# 3. TRANSPORT LAYER EXTRACTION
# ============================================================

def extract_transport(packet):
    """
    Extract transport protocol and ports.
    Currently supports TCP and UDP.
    """

    if TCP in packet:
        return (
            "tcp",
            packet[TCP].sport,
            packet[TCP].dport
        )

    if UDP in packet:
        return (
            "udp",
            packet[UDP].sport,
            packet[UDP].dport
        )

    return None, None, None


# ============================================================
# 4. PARSE A SINGLE PACKET
# ============================================================

def parse_packet(packet):
    """
    Convert one Scapy packet into the normalized project schema.
    """

    src_ip, dst_ip = extract_ip_addresses(packet)

    # Ignore packets without IP
    if src_ip is None or dst_ip is None:
        return None

    protocol, src_port, dst_port = extract_transport(packet)

    # Ignore non-TCP/UDP traffic in this first version
    if protocol is None:
        return None

    event = {
        "@timestamp": format_timestamp(packet.time),
        "event_source": "pcap",
        "src_ip": src_ip,
        "src_port": int(src_port),
        "dst_ip": dst_ip,
        "dst_port": int(dst_port),
        "protocol": protocol
    }

    return event


# ============================================================
# 5. PARSE COMPLETE PCAP
# ============================================================

def parse_pcap(pcap_path):
    """
    Read a PCAP file packet by packet and normalize
    all TCP/UDP IP packets.
    """

    events = []

    with PcapReader(str(pcap_path)) as packets:

        for packet_number, packet in enumerate(
            packets,
            start=1
        ):

            try:
                event = parse_packet(packet)

                if event is None:
                    continue

                event["packet_number"] = packet_number

                events.append(event)

            except Exception as error:

                print(
                    f"[!] Failed to parse packet "
                    f"{packet_number}: {error}"
                )

    return events


# ============================================================
# 6. SAVE JSON
# ============================================================

def save_json(events, output_path):
    """
    Save normalized events to a JSON file.
    """

    output_path = Path(output_path)

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with output_path.open(
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            events,
            file,
            indent=4,
            ensure_ascii=False
        )


# ============================================================
# 7. COMMAND LINE
# ============================================================

def main():

    parser = argparse.ArgumentParser(
        description=(
            "Parse PCAP network traffic "
            "into normalized JSON events."
        )
    )

    parser.add_argument(
        "--input",
        required=True,
        help="Input PCAP/PCAPNG file"
    )

    parser.add_argument(
        "--output",
        required=True,
        help="Output normalized JSON file"
    )

    args = parser.parse_args()

    input_path = Path(args.input)

    if not input_path.exists():

        raise FileNotFoundError(
            f"PCAP file not found: {input_path}"
        )

    print(
        f"[+] Parsing PCAP: "
        f"{input_path}"
    )

    events = parse_pcap(
        input_path
    )

    save_json(
        events,
        args.output
    )

    print()
    print("========== RESULTS ==========")

    print(
        f"[+] Parsed network events: "
        f"{len(events)}"
    )

    print(
        f"[+] Output file: "
        f"{args.output}"
    )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()
