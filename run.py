import json

from nesspy.Connect import ConnectionManager
from nesspy.Parser import Scan, Host, Finding


# Read login parameters (host, username, password)
# e.g., (localhost:8834, testusr, pw)
with open('config.json', 'r') as infile:
    config = json.load(infile)

# Communicate with the backend via the connection manager
nessus = ConnectionManager(**config)

# Show the scans saved in the backend
scans = nessus.list_scans()
#print(scans)

# Show the xml of a scan
xml_string = nessus.export_scan(8)
#print(xml[0:200])

# Parse the scan
scan = Scan(xml_string)
# Access the scan as a pandas DataFrame
df = scan.df
# Export the scan as a .csv table
scan.to_csv(path="./example.csv")

# Logout
nessus.logout()
print('Example script is done.')
