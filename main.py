#!/usr/bin/env python
# Import code libraries
import shodan
from netaddr import IPNetwork
import os
from decouple import config

# Get the API from a config file, if it exists
try:
    API_KEY = config('API')
# If .env doesn't exist, ask for the key
except:
    API_KEY = input("Please enter your Shodan API key")

# If .env does exist but is blank, ask for key
if not API_KEY:
    API_KEY = input("Please enter your Shodan API key")

# Read text file, ignore newline characters. This is stored in 'ranges'.
ranges = [line.rstrip() for line in open('ranges.txt')]

# Create the API object
api = shodan.Shodan(API_KEY)

lineCount = 0
# Open the results csv now so not to overrite later
with open("scan_result.csv", 'w', newline='') as file:
    firstLine = "IP,DATE,TIME,PORT,CVE\n"
    file.write(firstLine)
    # Take the first ip range from the text we read in.
    for iprange in ranges:
        lineCount += 1
        if iprange == "":
            continue
        try:
            IPNetwork(iprange)
        except:
            print(iprange, "is not a valid IP range.")
            print("Please remove or correct this range at line", lineCount, "and run the script again.")
            quit()
        # For every ip within the ip range
        for ip in IPNetwork(iprange):
            try:
                print("scanning", ip, "...")
                # Call API function on IP, including history
                result = api.host(str(ip), history=True)
                data = result["data"]
                for objects in result["data"]:
                    timestamp = objects['timestamp'].split("T")[0] + "," + objects['timestamp'].split("T")[1].split(".")[0]
                    # Line = IP, DATE, TIME, PORT, CVE
                    line = str(ip) + "," + timestamp + "," + str(objects["port"]) + ","
                    # Append CVE vulnerabilities to end of line, if none are found catch the error and append nothing
                    try:
                        vulns = str(list(objects['vulns'].keys())).replace(',','.')
                    except KeyError:
                        vulns = ""
                    line = line + vulns + "\n"
                    file.write(line)
                print("Historic results found for", ip)
            except shodan.APIError:
                pass
print("Script ran successfully, please check scan_result.csv")