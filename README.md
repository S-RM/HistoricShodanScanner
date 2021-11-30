# Historic Shodan Scanner

Historic Shodan Scanner is a simply Python utility that takes a range of IP addresses and queries Shodan for its historic Port and CVE data. This is useful to quickly assess the exposure of a Public IP estate during a cyber security incident.

## Requirements

Historic Shodan Scanner requires the following modules:

- shodan
- IPNetwork

You will need to activate your Shodan API integration prior to running the script, for example, by running `shodan init [API_TOKEN]`.

## Acknowledgements

All credit to development goes to [@Luke-Dyer](https://github.com/Luke-Dyer) and [@AidanStrong](https://github.com/AidanStrong) for supporting.

# Usage

- Input the IP ranges you want to scan in ranges.txt
- Run the script
- Scan_result.csv will contain a timeline of identified events
