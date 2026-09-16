from lxml import etree
import argparse
import json
from pathlib import Path


NS = {
    "ns": "http://schemas.microsoft.com/win/2004/08/events/event"
}


# ============================================================
# 1. PARSE SYSMON XML
# ============================================================

def parser_sysmon(chemin_fichier):

    parser = etree.XMLParser(recover=True)

    tree = etree.parse(
        chemin_fichier,
        parser=parser
    )

    evenements = []


    for event in tree.findall(".//ns:Event", NS):

        # ----------------------------------------------------
        # Event ID
        # ----------------------------------------------------

        event_id_element = event.find(
            ".//ns:EventID",
            NS
        )

        if event_id_element is None:
            continue

        event_id = event_id_element.text


        # ----------------------------------------------------
        # Timestamp
        # ----------------------------------------------------

        time_element = event.find(
            ".//ns:TimeCreated",
            NS
        )

        timestamp = None

        if time_element is not None:
            timestamp = time_element.get(
                "SystemTime"
            )


        # ----------------------------------------------------
        # Extract all EventData fields
        # ----------------------------------------------------

        data = {}

        for d in event.findall(
            ".//ns:Data",
            NS
        ):

            nom = d.get("Name")

            if nom:
                data[nom] = d.text


        # ----------------------------------------------------
        # Build normalized event
        # ----------------------------------------------------

        evenement = {

            "@timestamp": timestamp,

            "event_source": "sysmon",

            "event_id": int(event_id),

            "host": data.get(
                "Computer"
            ),

            # Process information
            "pid": data.get(
                "ProcessId"
            ),

            "ppid": data.get(
                "ParentProcessId"
            ),

            "process_name": data.get(
                "Image"
            ),

            "command_line": data.get(
                "CommandLine"
            ),

            # Network information
            "src_ip": data.get(
                "SourceIp"
            ),

            "src_port": data.get(
                "SourcePort"
            ),

            "dst_ip": data.get(
                "DestinationIp"
            ),

            "dst_port": data.get(
                "DestinationPort"
            ),

            "protocol": data.get(
                "Protocol"
            ),

            # File / Registry information
            "target_filename": data.get(
                "TargetFilename"
            ),

            "target_object": data.get(
                "TargetObject"
            ),

            "details": data.get(
                "Details"
            )
        }


        evenements.append(
            evenement
        )


    return evenements


# ============================================================
# 2. SAVE JSON
# ============================================================

def save_json(
    evenements,
    output_path
):

    output_path = Path(
        output_path
    )

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with output_path.open(
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            evenements,
            f,
            indent=4,
            ensure_ascii=False
        )


# ============================================================
# 3. MAIN
# ============================================================

def main():

    parser = argparse.ArgumentParser(
        description=(
            "Parse Sysmon XML logs "
            "into normalized JSON events."
        )
    )


    parser.add_argument(
        "--input",
        required=True,
        help="Input Sysmon XML file"
    )


    parser.add_argument(
        "--output",
        required=True,
        help="Output normalized JSON file"
    )


    args = parser.parse_args()


    input_path = Path(
        args.input
    )


    if not input_path.exists():

        raise FileNotFoundError(
            f"Sysmon XML file not found: "
            f"{input_path}"
        )


    print(
        f"[+] Parsing Sysmon XML: "
        f"{input_path}"
    )


    evenements = parser_sysmon(
        input_path
    )


    save_json(
        evenements,
        args.output
    )


    print()
    print("========== RESULTS ==========")

    print(
        f"[+] Parsed Sysmon events: "
        f"{len(evenements)}"
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
