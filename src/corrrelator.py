import argparse
import json
from datetime import datetime, timezone
from pathlib import Path


def load_json(file_path):
    """
    Load events from a JSON file.
    """

    file_path = Path(file_path)

    if not file_path.exists():
        raise FileNotFoundError(
            f"JSON file not found: {file_path}"
        )

    with file_path.open("r", encoding="utf-8") as file:
        events = json.load(file)

    return events



def parse_timestamp(value):
    """
    Convert an ISO 8601 timestamp into a timezone-aware datetime.
    """

    if not value:
        return None

    value = str(value).strip()

    if value.endswith("Z"):
        value = value[:-1] + "+00:00"

    try:
        timestamp = datetime.fromisoformat(value)

        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(
                tzinfo=timezone.utc
            )

        return timestamp

    except ValueError:
        return None



def time_difference(event1, event2):
    """
    Return the absolute time difference between two events
    in seconds.
    """

    timestamp1 = parse_timestamp(event1.get("@timestamp"))
    timestamp2 = parse_timestamp(event2.get("@timestamp"))

    if timestamp1 is None or timestamp2 is None:
        return None

    delta = abs((timestamp1 - timestamp2).total_seconds())

    return delta



def normalize_protocol(protocol):
    if protocol is None:
        return None
    return str(protocol).lower().strip()


def normalize_port(port):
    if port in (None, ""):
        return None
    try:
        return int(port)
    except (ValueError, TypeError):
        return None



def network_match(sysmon_event, pcap_event):
    """
    Compare network fields between one Sysmon event
    and one PCAP event.
    """

    sys_protocol = normalize_protocol(sysmon_event.get("protocol"))
    pcap_protocol = normalize_protocol(pcap_event.get("protocol"))

    if sys_protocol != pcap_protocol:
        return None

    s_src_ip = sysmon_event.get("src_ip")
    s_dst_ip = sysmon_event.get("dst_ip")
    s_src_port = normalize_port(sysmon_event.get("src_port"))
    s_dst_port = normalize_port(sysmon_event.get("dst_port"))

    p_src_ip = pcap_event.get("src_ip")
    p_dst_ip = pcap_event.get("dst_ip")
    p_src_port = normalize_port(pcap_event.get("src_port"))
    p_dst_port = normalize_port(pcap_event.get("dst_port"))

    direct = (
        s_src_ip == p_src_ip
        and s_dst_ip == p_dst_ip
        and s_src_port == p_src_port
        and s_dst_port == p_dst_port
    )

    reverse = (
        s_src_ip == p_dst_ip
        and s_dst_ip == p_src_ip
        and s_src_port == p_dst_port
        and s_dst_port == p_src_port
    )

    if direct:
        return "direct"

    if reverse:
        return "reverse"

    return None



def find_best_match(sysmon_event, pcap_events, used_pcap_indexes, tolerance=2.0):
    """
    Find the closest unused PCAP event matching one Sysmon
    network event.
    """

    best_match = None
    best_delta = None
    best_direction = None
    best_index = None

    for index, pcap_event in enumerate(pcap_events):

        if index in used_pcap_indexes:
            continue

        direction = network_match(sysmon_event, pcap_event)

        if direction is None:
            continue

        delta = time_difference(sysmon_event, pcap_event)

        if delta is None:
            continue

        if delta > tolerance:
            continue

        if best_delta is None or delta < best_delta:
            best_match = pcap_event
            best_delta = delta
            best_direction = direction
            best_index = index

    return (best_match, best_delta, best_direction, best_index)



def correlate_events(sysmon_events, pcap_events, tolerance=2.0):
    """
    Correlate Sysmon events with PCAP events.
    """

    matched = []
    sysmon_only = []
    used_pcap_indexes = set()

    for sysmon_event in sysmon_events:

        has_network = (
            sysmon_event.get("src_ip") is not None
            and sysmon_event.get("dst_ip") is not None
            and sysmon_event.get("src_port") is not None
            and sysmon_event.get("dst_port") is not None
            and sysmon_event.get("protocol") is not None
        )

        if not has_network:
            sysmon_only.append(sysmon_event)
            continue

        (best_match, best_delta, best_direction, best_index) = find_best_match(
            sysmon_event, pcap_events, used_pcap_indexes, tolerance
        )

        if best_match is not None:
            correlated_event = {
                "correlation_status": "matched",
                "time_delta_seconds": best_delta,
                "direction": best_direction,
                "sysmon": sysmon_event,
                "pcap": best_match
            }
            matched.append(correlated_event)
            used_pcap_indexes.add(best_index)
        else:
            sysmon_only.append(sysmon_event)

    pcap_only = []
    for index, pcap_event in enumerate(pcap_events):
        if index not in used_pcap_indexes:
            pcap_only.append(pcap_event)

    return (matched, sysmon_only, pcap_only)



def build_process_tree(sysmon_events):
    """
    Build a mapping of pid -> list of direct child events,
    based on ppid/pid relationships.

    Also attaches, on each event, the command_line of its
    parent process (when known), so a reader can see the
    lineage without having to look up the parent separately.
    """

    # Index: pid -> event that CREATED this process (Event ID 1)
    process_by_pid = {}

    for event in sysmon_events:
        if event.get("event_id") == 1 and event.get("pid"):
            process_by_pid[event["pid"]] = event

    # Index: pid -> list of every event produced by that pid
    # (process creation, network, file, registry... anything
    # Sysmon logged under that same process)
    events_by_pid = {}

    for event in sysmon_events:
        pid = event.get("pid")
        if pid is None:
            continue
        events_by_pid.setdefault(pid, []).append(event)

    # Enrich each event with information about its parent process
    for event in sysmon_events:
        ppid = event.get("ppid")
        parent_process = process_by_pid.get(ppid)

        if parent_process is not None:
            event["parent_process_name"] = parent_process.get("process_name")
            event["parent_command_line"] = parent_process.get("command_line")
        else:
            event["parent_process_name"] = None
            event["parent_command_line"] = None

        # Direct children of this event's own pid (if it is
        # itself a process), useful to see what it spawned
        pid = event.get("pid")
        if pid is not None and event.get("event_id") == 1:
            children = [
                child for child in sysmon_events
                if child.get("ppid") == pid and child is not event
            ]
            event["child_event_count"] = len(children)
        else:
            event["child_event_count"] = None

    return sysmon_events


# Each rule: (technique_id, technique_name, function that
# returns True if the event matches)

def _has(text, keyword):
    return keyword in (text or "").lower()


MITRE_RULES = [
    (
        "T1059.001",
        "PowerShell",
        lambda e: _has(e.get("command_line"), "-encodedcommand")
    ),
    (
        "T1105",
        "Ingress Tool Transfer",
        lambda e: _has(e.get("command_line"), "invoke-webrequest")
        or _has(e.get("command_line"), "downloadstring")
    ),
    (
        "T1547.001",
        "Registry Run Keys / Startup Folder",
        lambda e: _has(e.get("target_object"), "\\run\\")
    ),
    (
        "T1053.005",
        "Scheduled Task",
        lambda e: _has(e.get("command_line"), "schtasks")
    ),
    (
        "T1046",
        "Network Service Discovery",
        lambda e: e.get("event_source") == "pcap"
        and e.get("packet_number") is not None
    ),
]


def map_mitre_technique(event):
    """
    Try every MITRE rule against this event and return the
    first match. Returns (technique_id, technique_name) or
    (None, None) when nothing matches.
    """

    for technique_id, technique_name, rule in MITRE_RULES:
        try:
            if rule(event):
                return technique_id, technique_name
        except Exception:
            continue

    return None, None



SCORE_RULES = [
    (lambda e: _has(e.get("command_line"), "-encodedcommand"), 40),
    (lambda e: _has(e.get("command_line"), "public"), 20),
    (lambda e: _has(e.get("command_line"), "system"), 25),
    (lambda e: _has(e.get("command_line"), "schtasks"), 15),
    (lambda e: _has(e.get("target_object"), "\\run\\"), 20),
    (lambda e: _has(e.get("command_line"), "invoke-webrequest"), 15),
]


def calculate_suspicion_score(event):
    """
    Sum every matching rule's weight into a single score.
    """

    score = 0

    for rule, weight in SCORE_RULES:
        try:
            if rule(event):
                score += weight
        except Exception:
            continue

    return score


def score_to_severity(score):
    """
    Convert a numeric score into a human-readable category.
    """

    if score >= 70:
        return "critical"
    elif score >= 40:
        return "high"
    elif score >= 15:
        return "medium"
    else:
        return "low"



def enrich_event(event):
    """
    Attach mitre_technique_id, mitre_technique_name,
    suspicion_score and severity to a single event dict.
    Works whether the event is a plain Sysmon/PCAP event or
    a matched {sysmon, pcap} correlation object.
    """

    # For matched events, score based on the Sysmon side
    # (it carries the process/command context); the PCAP side
    # alone rarely has enough context to score meaningfully.
    target_for_scoring = event.get("sysmon", event)

    technique_id, technique_name = map_mitre_technique(target_for_scoring)
    score = calculate_suspicion_score(target_for_scoring)
    severity = score_to_severity(score)

    event["mitre_technique_id"] = technique_id
    event["mitre_technique_name"] = technique_name
    event["suspicion_score"] = score
    event["severity"] = severity

    return event


def enrich_all(matched, sysmon_only, pcap_only):
    matched = [enrich_event(e) for e in matched]
    sysmon_only = [enrich_event(e) for e in sysmon_only]
    pcap_only = [enrich_event(e) for e in pcap_only]
    return matched, sysmon_only, pcap_only



def build_output(matched, sysmon_only, pcap_only):
    output = {
        "summary": {
            "matched": len(matched),
            "sysmon_only": len(sysmon_only),
            "pcap_only": len(pcap_only),
            "critical": sum(
                1 for e in (matched + sysmon_only)
                if e.get("severity") == "critical"
            ),
            "high": sum(
                1 for e in (matched + sysmon_only)
                if e.get("severity") == "high"
            ),
        },
        "matched": matched,
        "sysmon_only": sysmon_only,
        "pcap_only": pcap_only
    }

    return output



def save_json(data, output_path):
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as file:
        json.dump(data, file, indent=4, ensure_ascii=False)


def main():

    parser = argparse.ArgumentParser(
        description=(
            "Correlate Sysmon and PCAP events, build the process "
            "tree, map MITRE ATT&CK techniques and compute a "
            "suspicion score."
        )
    )

    parser.add_argument("--sysmon", required=True, help="Normalized Sysmon JSON file")
    parser.add_argument("--pcap", required=True, help="Normalized PCAP JSON file")
    parser.add_argument("--output", required=True, help="Output correlation JSON file")
    parser.add_argument(
        "--tolerance",
        type=float,
        default=2.0,
        help="Maximum time difference in seconds between Sysmon and PCAP events (default: 2.0)"
    )

    args = parser.parse_args()

    print("[+] Loading Sysmon events...")
    sysmon_events = load_json(args.sysmon)

    print("[+] Loading PCAP events...")
    pcap_events = load_json(args.pcap)

    print(f"[+] Sysmon events loaded: {len(sysmon_events)}")
    print(f"[+] PCAP events loaded: {len(pcap_events)}")

    print()
    print("[+] Building process tree (PID/PPID)...")
    sysmon_events = build_process_tree(sysmon_events)

    print("[+] Starting network correlation...")
    (matched, sysmon_only, pcap_only) = correlate_events(
        sysmon_events, pcap_events, args.tolerance
    )

    print("[+] Mapping MITRE ATT&CK techniques and scoring events...")
    (matched, sysmon_only, pcap_only) = enrich_all(matched, sysmon_only, pcap_only)

    result = build_output(matched, sysmon_only, pcap_only)
    save_json(result, args.output)

    print()
    print("========== CORRELATION RESULTS ==========")
    print(f"[+] Matched events: {len(matched)}")
    print(f"[+] Sysmon-only events: {len(sysmon_only)}")
    print(f"[+] PCAP-only events: {len(pcap_only)}")
    print(f"[+] Critical severity events: {result['summary']['critical']}")
    print(f"[+] High severity events: {result['summary']['high']}")
    print(f"[+] Output file: {args.output}")



if __name__ == "__main__":
    main()
