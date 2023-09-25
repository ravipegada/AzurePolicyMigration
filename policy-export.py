# Written by: Predrag Petrovic, Consulting Director <ppetrovic@paloaltonetworks.com>
# Purpose: This script is written to export the firewall policy from Azure Firewall
# and use Expedition2 to perform the conversion.

import csv, json, uuid, argparse, re

parser = argparse.ArgumentParser(description='Azure Firewall Export Script')

parser.add_argument('-if', '--infile', type=str, help='Input JSON file', required=True)

args = parser.parse_args()

# remove characters from name if required

def regex_sanitize(string):
    match = re.search(repattern, string)
    if match:
        result = match.group()
        result = result.rstrip("\/ ')]").lstrip('/')
        return result

# sanitize the name according to palo alto naming conventions

def sanitize_name(input_data):
    input_data = input_data[:63]
    input_data =re.sub("[^A-Z,0-9,\s]", "", input_data,0,re.IGNORECASE)
    return input_data

# read the json file

def read_json_file(file_path):
    with open(file_path, 'r') as file:
        data = json.load(file)
    return data

json_data = read_json_file(args.infile)

# Function to extract the ruleCollectionName without the resource ID prefix
def extract_rule_collection_name(rule_collection_name):
    return rule_collection_name.split("/")[-1]

# Function to extract the ruleCollectionGroupName without the full resource name and reference
def extract_rule_collection_group_name(rule_collection_group_name):
    return rule_collection_group_name.split("/")[-1].strip('\')]')

def clean_ip_groups(ip_groups):
    cleaned_groups = []
    for group in ip_groups:
        group_name = group.strip("[parameters('ipGroups_").strip("_externalid')]")
        cleaned_groups.append(group_name)
    return cleaned_groups

# Function to flatten the rules and extract required fields
def extract_rules(rule_collection_group, rules_list, results):
    for rule_collection in rules_list:
        action_type = rule_collection.get("action", {}).get("type", "")
        for rule in rule_collection["rules"]:
            protocol_parts = [f"{proto['protocolType']}:{proto['port']}" for proto in rule.get("protocols", [])]
            rule_entry = {
                "ruleCollectionGroupPriority": rule_collection_group.get("properties", {}).get("priority", ""),
                "ruleCollectionPriority": rule_collection.get("priority", ""),
                "ruleCollectionGroupName": extract_rule_collection_group_name(rule_collection_group.get("name", "")),
                "ruleCollectionName": extract_rule_collection_name(rule_collection.get("name", "")),
                "ruleName": rule.get("name", ""),
                "ruleType": rule.get("ruleType", ""),
                "ruleAction": action_type,
                "sourceAddress": ",".join(rule.get("sourceAddresses", [])),
                "sourceGroup": ",".join(clean_ip_groups(rule.get("sourceIpGroups", []))),
                "protocol": ",".join(protocol_parts),
                "destinationPorts": ",".join(port for port in rule.get("destinationPorts", [])),
                "destinationAddress": ",".join(rule.get("destinationAddresses", [])),
                "destinationGroup": ",".join(clean_ip_groups(rule.get("destinationIpGroups", []))),
                "destinationFqdn": ",".join(rule.get("destinationFqdns", [])),
                "translatedPort": rule.get("translatedPort", ""),
                "translatedAddress": rule.get("translatedAddress", ""),
                "fqdnTags": ",".join(rule.get("fqdnTags", [])),
                "webCategories": ",".join(rule.get("webCategories", [])),
                "targetFqdns": ",".join(rule.get("targetFqdns", [])),
                "targetUrls": ",".join(rule.get("targetUrls", [])),
                "ipProtocols": ",".join(rule.get("ipProtocols", [])),  # Add the ipProtocols field
                "UUID": str(uuid.uuid4()),  # Generate a unique UUID for each row
            }
            results.append(rule_entry)

# List to store the extracted results
exported_rules = []

# Extract rules from rule collection groups and sort based on priorities
for resource in json_data.get("resources", []):
    if resource["type"] == "Microsoft.Network/firewallPolicies/ruleCollectionGroups":
        extract_rules(resource, resource["properties"]["ruleCollections"], exported_rules)

# Sort the rules by ascending order of ruleCollectionGroupPriority followed by ruleCollectionPriority
exported_rules.sort(key=lambda x: (x["ruleCollectionGroupPriority"], x["ruleCollectionPriority"]))

# CSV file path
csv_file_path = "firewall_rules_export.csv"

# Write the data to CSV file
with open(csv_file_path, mode="w", newline="") as csv_file:
    fieldnames = [
        "ruleCollectionGroupPriority",
        "ruleCollectionPriority",
        "ruleCollectionGroupName",
        "ruleCollectionName",
        "ruleName",
        "ruleType",
        "ruleAction",
        "sourceAddress",
        "sourceGroup",
        "protocol",
        "destinationPorts",
        "destinationAddress",
        "destinationGroup",
        "destinationFqdn",
        "translatedPort",
        "translatedAddress",
        "fqdnTags",
        "webCategories",
        "targetFqdns",
        "targetUrls",
        "ipProtocols",  # Include the ipProtocols field in the CSV
        "UUID",  # Include the UUID field in the CSV
    ]
    writer = csv.DictWriter(csv_file, fieldnames=fieldnames, delimiter=";")
    writer.writeheader()
    writer.writerows(exported_rules)

print(f"Firewall rules exported to '{csv_file_path}' successfully.")

# Extract sourceAddress and destinationAddress and create a deduplicated list
addresses = set()
tcp_ports = set()
udp_ports = set()
addressGroups = set()
fqdns = set()

for rule in exported_rules:
    fqdns.update(rule.get("destinationFqdn", "").strip().split(','))

with open("fqdns.txt", mode="w") as fqdn_file:
    fqdn_file.write("\n".join(fqdn for fqdn in fqdns if fqdn.strip()))

print(f"Deduplicated FQDNs extracted and saved to 'fqdns.txt' successfully.")

for rule in exported_rules:
    if isinstance(rule["sourceAddress"], list):
        for addr in rule["sourceAddress"]:
            if addr.strip() != '*':
                addresses.update(addr.strip().split(','))
    else:
        if rule["sourceAddress"].strip() != '*':
            addresses.update(rule["sourceAddress"].strip().split(','))

    if isinstance(rule["destinationAddress"], list):
        for addr in rule["destinationAddress"]:
            if addr.strip() != '*':
                addresses.update(addr.strip().split(','))
    else:
        if rule["destinationAddress"].strip() != '*':
            addresses.update(rule["destinationAddress"].strip().split(','))

# Write the deduplicated addresses to addresses.txt file
with open("addresses.txt", mode="w") as addresses_file:
    addresses_file.write("\n".join(addr for addr in addresses if addr.strip()))

print(f"Deduplicated sourceAddress and destinationAddress extracted and saved to 'addresses.txt' successfully.")

# extract the data in ports
for rule in exported_rules:
    destination_ports = rule["destinationPorts"]
    protocols = rule.get("ipProtocols", "Any").split(",") if "ipProtocols" in rule else ["Any"]

    if isinstance(destination_ports, str):
        destination_ports = destination_ports.strip()
        if destination_ports != '*':
            ports_list = destination_ports.split(',')
            for port in ports_list:
                port = port.strip()
                if "Any" in protocols or "TCP" in protocols:
                    tcp_ports.add(port)
                if "Any" in protocols or "UDP" in protocols:
                    udp_ports.add(port)

with open("tcp_ports.txt", mode="w") as tcp_ports_file:
    tcp_ports_file.write("\n".join(port for port in tcp_ports))

with open("udp_ports.txt", mode="w") as udp_ports_file:
    udp_ports_file.write("\n".join(port for port in udp_ports))

print("TCP and UDP ports extracted and saved to 'tcp_ports.txt' and 'udp_ports.txt' successfully.")

# Address Groups

for rule in exported_rules:
    if isinstance(rule["sourceGroup"], list):
        for addr in rule["sourceGroup"]:
            if addr.strip() != '*':
                addressGroups.update(addr.strip().split(','))
    else:
        if rule["sourceGroup"].strip() != '*':
            addressGroups.update(rule["sourceGroup"].strip().split(','))

    if isinstance(rule["destinationGroup"], list):
        for addr in rule["destinationGroup"]:
            if addr.strip() != '*':
                addressGroups.update(addr.strip().split(','))
    else:
        if rule["destinationGroup"].strip() != '*':
            addressGroups.update(rule["destinationGroup"].strip().split(','))

# Write the deduplicated groups to groups.txt file
with open("groups.txt", mode="w") as addresses_file:
    addresses_file.write("\n".join(addr for addr in addressGroups if addr.strip()))

print(f"Deduplicated sourceGroups and destinationGroups extracted and saved to 'groups.txt' successfully.")
