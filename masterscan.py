# Import code libraries
import shodan
from netaddr import IPNetwork

apiKey = input("Please enter your Shodan api key: ")
# API KEY IN HERE
api = shodan.Shodan(apiKey)

# Read text file, ignore newline characters. This is stored in 'ranges'.
ranges = [line.rstrip() for line in open('ranges.txt')]

# Open the results csv now so not to overrite later
with open("scan_result.csv", 'w', newline='') as file:
    # Take the first ip range from the text we read in.
    for iprange in ranges:
        # For every ip within the ip range
        for ip in IPNetwork(iprange):
            try:
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
                    print(line)
                    file.write(line)
            except shodan.APIError:
                pass
print("Script ran successfully, please check scan_result.csv")