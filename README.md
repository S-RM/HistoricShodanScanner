# Historic Shodan Scanner

Historic Shodan Scanner is a simply Python utility to take a range of IP addresses and query Shodan for its historic Port and CVE data. This is useful to quickly assess the exposure of a Public IP estate during a cyber security incident.

## Requirements

Historic Shodan Scanner requires the following modules:

- shodan
- IPNetwork

## Acknowledgements

All credit to development goes to [@Luke-Dyer](https://github.com/Luke-Dyer) and [@AidanStrong](https://github.com/AidanStrong) for supporting.

# Usage

- Input the IP ranges you want to scan in ranges.txt
- Run the script
- Scan_result.csv will contain historic data on vulnerabilities, in the format: IP|DATE|TIME|PORT|CVEs
