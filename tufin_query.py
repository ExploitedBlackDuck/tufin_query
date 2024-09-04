import os
import sys
import lxml.etree as ET
import requests
import urllib3
import csv
import pandas as pd
from datetime import datetime
import logging
import argparse
from typing import List, Dict, Any
from requests.exceptions import RequestException

# Suppress the InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class TufinScriptConfig:
    def __init__(self):
        self.RULE_SEARCH_COUNT = 100
        self.SEARCH_TYPES = ['source', 'destination']
        self.CONFIG_FILE = "search_targets.txt"
        self.REMOVE_TEMP_CSV = True
        self.TUFIN_URL = os.getenv("TUFN_URL", "your_url")
        self.USERNAME = os.getenv("TUFN_USERNAME", "your_username")
        self.PASSWORD = os.getenv("TUFN_PASSWORD", "your_password")

config = TufinScriptConfig()

def setup_logging(log_filename: str = 'tufin_script.log') -> None:
    """Setup logging for the script."""
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s - %(levelname)s - %(message)s',
                        handlers=[
                            logging.FileHandler(log_filename),
                            logging.StreamHandler()
                        ])

    global audit_logger, group_logger, rule_logger

    audit_logger = logging.getLogger("audit_logger")
    audit_logger.setLevel(logging.INFO)
    audit_handler = logging.FileHandler("tufin_audit.log")
    audit_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
    audit_logger.addHandler(audit_handler)

    group_logger = logging.getLogger("group_logger")
    group_logger.setLevel(logging.DEBUG)
    group_handler = logging.FileHandler("tufin_group_info.log")
    group_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
    group_logger.addHandler(group_handler)

    rule_logger = logging.getLogger("rule_logger")
    rule_logger.setLevel(logging.DEBUG)
    rule_handler = logging.FileHandler("tufin_rule_info.log")
    rule_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
    rule_logger.addHandler(rule_handler)

def log_message(message: str, level: int = logging.INFO) -> None:
    """Logs messages with timestamps to both the console and a log file."""
    logging.log(level, message)
    print(message)

def safe_find_text(element: ET.Element, tag_name: str) -> str:
    """Safely find text within an XML element, returning 'N/A' if not found."""
    tag = element.find(tag_name)
    return tag.text if tag is not None else "N/A"

def retrieve_and_save_groups(st_api: requests.Session, device_id: str, device_name: str) -> None:
    """Retrieve all groups for a device and save them to a CSV file if the data is not empty."""
    log_message(f"Retrieving and saving groups for device ID {device_id} (Name: {device_name})")
    
    try:
        response = st_api.get(f'{config.TUFIN_URL}/securetrack/api/devices/{device_id}/network_objects?type=group&show_members=true')
        response.raise_for_status()

        groups = []
        root = ET.fromstring(response.content)
        for group in root.xpath('.//network_object[@xsi:type="networkObjectGroupDTO"]', 
                                namespaces={'xsi': 'http://www.w3.org/2001/XMLSchema-instance'}):
            group_uid = safe_find_text(group, 'uid')
            group_name = safe_find_text(group, 'name')
            for member in group.findall('.//member'):
                member_uid = safe_find_text(member, 'uid')
                groups.append({
                    'group_uid': group_uid,
                    'group_name': group_name,
                    'member_uid': member_uid
                })
        
        if groups:
            df = pd.DataFrame(groups)
            csv_filename = f"groups_device_{device_id}.csv"
            df.to_csv(csv_filename, index=False)
            log_message(f"Saved group data to {csv_filename}")
        else:
            log_message(f"No groups found for device ID {device_id} (Name: {device_name}), skipping CSV creation.")

    except RequestException as e:
        log_message(f"Error during API request: {e}", level=logging.ERROR)
    except ET.ParseError as e:
        log_message(f"Error parsing XML: {e}", level=logging.ERROR)
    except Exception as e:
        log_message(f"An unexpected error occurred: {e}", level=logging.ERROR)

def find_groups_containing_network_objects(network_objects: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Find unique groups containing the specified network objects."""
    log_message("Searching for network objects in groups")

    all_groups = {} 
    for csv_file in os.listdir('.'):
        if csv_file.startswith('groups_device_') and csv_file.endswith('.csv'):
            try:
                df = pd.read_csv(csv_file)
                device_id = csv_file.split('_')[2].replace('.csv', '')
                for _, row in df.iterrows():
                    group_uid = row['group_uid']
                    if group_uid not in all_groups:
                        all_groups[group_uid] = {
                            'name': row['group_name'],
                            'device_id': device_id,
                            'members': set() 
                        }
                    all_groups[group_uid]['members'].add(row['member_uid'])
            except pd.errors.EmptyDataError:
                log_message(f"Skipping empty CSV file: {csv_file}", level=logging.WARNING)
            except Exception as e:
                log_message(f"Error reading {csv_file}: {e}", level=logging.ERROR)

    unique_groups = []
    for network_object in network_objects:
        object_uid = network_object['uid']
        for group_uid, group_data in all_groups.items():
            if object_uid in group_data['members']:
                unique_groups.append({
                    'uid': group_uid,
                    'name': group_data['name'],
                    'device_id': group_data['device_id'],
                    'device_name': network_object.get('device_name', 'Unknown Device')
                })
                group_logger.info(f"Found network object UID {object_uid} in group: {group_data['name']} (UID: {group_uid})")

    return unique_groups

def retrieve_network_objects(st_api: requests.Session, search_target: str) -> List[Dict[str, Any]]:
    """Retrieve all network objects and return them as a list of dictionaries."""
    log_message(f"Retrieving all network objects containing {search_target}")
    try:
        response = st_api.get(f'{config.TUFIN_URL}/securetrack/api/network_objects/search',
                              params={"filter": "text", "ip": search_target, "exact_match": "true"})

        response.raise_for_status()

        network_objects = []
        root = ET.fromstring(response.content)
        for obj in root.findall('.//network_object'):
            uid = safe_find_text(obj, 'uid')
            name = safe_find_text(obj, 'name')
            device_id = safe_find_text(obj, 'device_id')
            ip = safe_find_text(obj, 'ip')
            if ip == search_target or name == search_target:
                network_objects.append({"uid": uid, "name": name, "device_id": device_id})

        log_message(f"Retrieved {len(network_objects)} network objects matching {search_target}")
        return network_objects

    except RequestException as e:
        log_message(f"Error during API request: {e}", level=logging.ERROR)
    except ET.ParseError as e:
        log_message(f"Error parsing XML: {e}", level=logging.ERROR)
    except Exception as e:
        log_message(f"An unexpected error occurred: {e}", level=logging.ERROR)
    
    return []

def search_rules_by_network_objects(uids_with_names_and_devices: List[Dict[str, Any]], 
                                    st_api: requests.Session, 
                                    search_type: str, 
                                    all_device_ids: List[str], 
                                    device_id_to_name: Dict[str, str]) -> List[Dict[str, Any]]:
    """Search for security rules by network objects across all device IDs using the REST API."""
    rules_output = [] 
    total_rule_count = 0
    processed_rule_uids = set()

    for obj in uids_with_names_and_devices:
        uid = obj['uid']
        name = obj['name']
        for device_id in all_device_ids:
            device_name = device_id_to_name.get(device_id, 'Unknown Device') 
            log_message(f"Searching for rules with {search_type} network object UID: {uid} (name: {name}) on device ID: {device_id}")

            params = {
                "search_text": f"{search_type}:{name}",
                "count": config.RULE_SEARCH_COUNT,
                "start": 0
            }

            try:
                response = st_api.get(f"{config.TUFIN_URL}/securetrack/api/rule_search/{device_id}", params=params)
                response.raise_for_status()

                if response.text.strip():
                    root = ET.fromstring(response.content)
                    rule_count = int(root.findtext('.//count', '0'))
                    total_rule_count += rule_count

                    if rule_count > 0:
                        rules = []
                        for rule in root.findall('.//rule'):
                            rule_uid = rule.findtext('uid', 'None')

                            if rule_uid in processed_rule_uids:
                                log_message(f"Skipping duplicate rule: UID={rule_uid}")
                                continue

                            processed_rule_uids.add(rule_uid)

                            rule_entry = {
                                "Device ID": device_id,
                                "Device Name": device_name,
                                "Network Object": name,
                                "Rule UID": rule_uid,
                                "Rule Name": rule.findtext('name', 'None'),
                                "Rule Number": rule.findtext('rule_number', 'None'),
                                "Action": rule.findtext('action', 'None'),
                                "Comment": rule.findtext('comment', 'No comment')
                            }

                            rules.append(rule_entry)
                            rules_output.append(rule_entry) 

                        df = pd.DataFrame(rules)
                        csv_filename = f"{name}_{search_type}_rules_device_{device_id}.csv".replace(" ", "_").replace("/", "_")
                        df.to_csv(csv_filename, index=False)
                        log_message(f"Saved {len(rules)} rules to {csv_filename}")
                        rule_logger.info(f"Saved {len(rules)} rules to {csv_filename}")

            except RequestException as e:
                if e.response is not None and e.response.status_code == 404:
                    log_message(f"No rules found for {search_type} network object UID: {uid} (name: {name}) on device ID: {device_id}")
                else:
                    log_message(f"Error occurred while searching for rules on device {device_id}: {e}", level=logging.ERROR)
            except ET.ParseError as e:
                log_message(f"Failed to parse XML response for device {device_id}: {e}", level=logging.ERROR)

    logging.info(f"Total rule count for {search_type}: {total_rule_count}")
    return rules_output

def output_to_csv(filename: str, data: List[Dict[str, Any]]) -> None:
    """Output the final results to a CSV file."""
    if data:
        log_message(f"Writing results to {filename}")
        df = pd.DataFrame(data)
        df.to_csv(filename, index=False)
        log_message(f"Final results saved to {filename}")
    else:
        log_message(f"No data to write to {filename}, skipping file creation.")

def cleanup_temp_csv() -> None:
    """Remove all temporary CSV files generated during the script's execution."""
    if config.REMOVE_TEMP_CSV:
        log_message("Cleaning up temporary CSV files")
        for csv_file in os.listdir('.'):
            if csv_file.startswith('groups_device_') and csv_file.endswith('.csv'):
                try:
                    os.remove(csv_file)
                    log_message(f"Removed temporary file: {csv_file}")
                except Exception as e:
                    log_message(f"Error removing file {csv_file}: {e}", level=logging.ERROR)

def load_search_targets(config_file: str) -> List[str]:
    """Load a list of IPs or FQDNs to search from a configuration file."""
    if not os.path.exists(config_file):
        log_message(f"Configuration file {config_file} not found. Exiting.")
        sys.exit(1)

    with open(config_file, 'r') as file:
        targets = [line.strip() for line in file if line.strip()]
    
    log_message(f"Loaded {len(targets)} search targets from {config_file}")
    return targets

def main():
    parser = argparse.ArgumentParser(description="Tufin Security Rule Search Script")
    parser.add_argument("--config", default=config.CONFIG_FILE, help="Path to the configuration file")
    parser.add_argument("--output", default="tufin_rules_output.csv", help="Name of the output CSV file")
    parser.add_argument("--keep-temp", action="store_true", help="Keep temporary CSV files")
    args = parser.parse_args()

    config.CONFIG_FILE = args.config
    config.REMOVE_TEMP_CSV = not args.keep_temp

    setup_logging()

    tufin_st_xml = requests.session()
    tufin_st_xml.verify = False
    tufin_st_xml.headers.update({'Content-type': 'application/xml'})
    tufin_st_xml.auth = requests.auth.HTTPBasicAuth(config.USERNAME, config.PASSWORD)

    try:
        search_targets = load_search_targets(config.CONFIG_FILE)

        devices_response = tufin_st_xml.get(f'{config.TUFIN_URL}/securetrack/api/devices')
        devices_response.raise_for_status()
        devices_xml = ET.fromstring(devices_response.content)

        all_device_ids = [safe_find_text(device, 'id') for device in devices_xml.findall("./device")]
        device_id_to_name = {safe_find_text(device, 'id'): safe_find_text(device, 'name') for device in devices_xml.findall("./device")}

        log_message("Retrieving and saving groups for all devices")
        for device in devices_xml.findall("./device"):
            device_id = safe_find_text(device, 'id')
            device_name = safe_find_text(device, 'name')
            retrieve_and_save_groups(tufin_st_xml, device_id, device_name)

        all_rules_output = []
        for target in search_targets:
            network_objects = retrieve_network_objects(tufin_st_xml, target)

            if network_objects:
                unique_groups = find_groups_containing_network_objects(network_objects)
                
                for search_type in config.SEARCH_TYPES:
                    rules = search_rules_by_network_objects(
                        network_objects + unique_groups, 
                        tufin_st_xml, 
                        search_type, 
                        all_device_ids, 
                        device_id_to_name
                    )
                    all_rules_output.extend(rules)

        output_to_csv(args.output, all_rules_output)

        if config.REMOVE_TEMP_CSV:
            cleanup_temp_csv()

    except RequestException as e:
        log_message(f"API request error: {e}", level=logging.ERROR)
    except ET.ParseError as e:
        log_message(f"XML parsing error: {e}", level=logging.ERROR)
    except Exception as e:
        log_message(f"General error occurred: {e}", level=logging.ERROR)

    log_message("Script completed.")

if __name__ == "__main__":
    main()