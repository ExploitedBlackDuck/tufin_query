# Tufin Security Rule Search Script

## Overview

This Python script automates the process of searching for security rules in Tufin SecureTrack based on specified network objects. It interacts with the Tufin API to retrieve network objects, find associated groups, and search for security rules across multiple devices.

## Features

- Retrieves network objects based on IP addresses or FQDNs
- Searches for groups containing the specified network objects
- Finds security rules associated with the network objects and groups
- Supports searching in both source and destination fields of rules
- Outputs results to CSV files for easy analysis
- Provides detailed logging for audit and troubleshooting purposes

## Prerequisites

- Python 3.7 or higher
- Access to a Tufin SecureTrack instance
- Tufin API credentials

## Installation

1. Clone this repository or download the script files.

2. Install the required Python packages:

   ```
   pip install -r requirements.txt
   ```

## Configuration

1. Set up environment variables for Tufin API access:
   - `TUFN_URL`: URL of your Tufin instance (e.g., "https://tufin.fw.ray.com")
   - `TUFN_USERNAME`: Your Tufin API username
   - `TUFN_PASSWORD`: Your Tufin API password

2. Create a configuration file (default: `search_targets.txt`) with the list of IP addresses or FQDNs to search, one per line.

## Usage

Run the script using the following command:

```
python tufin_script.py [--config CONFIG_FILE] [--output OUTPUT_FILE] [--keep-temp]
```

Arguments:
- `--config`: Path to the configuration file (default: `search_targets.txt`)
- `--output`: Name of the output CSV file (default: `tufin_rules_output.csv`)
- `--keep-temp`: Keep temporary CSV files (default: False)

## Output

The script generates several output files:
- `tufin_rules_output.csv`: Main output file containing all found security rules
- `tufin_script.log`: General script execution log
- `tufin_audit.log`: Audit log for tracking script actions
- `tufin_group_info.log`: Log of group information
- `tufin_rule_info.log`: Log of rule information

## Troubleshooting

- Check the log files for detailed information about script execution and any errors encountered.
- Ensure your Tufin API credentials are correct and have the necessary permissions.
- Verify that the network objects you're searching for exist in your Tufin environment.

## Security Note

This script handles sensitive information. Ensure that you follow your organization's security policies when using and storing API credentials and output files.

## Contributing

Contributions to improve the script are welcome. Please submit a pull request or open an issue to discuss proposed changes.

## License

[Specify the license under which this script is distributed]
