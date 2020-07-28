import json

from nesspy.Connect import ConnectionManager


# Read login parameters (host, username, password)
# e.g., (localhost:8834, testusr, pw)
with open('config.json', 'r') as infile:
    config = json.load(infile)

# Communicate with the backend via the connection manager
nessus = ConnectionManager(**config)

# Show the scans saved in the backend
scans = nessus.list_scans()
print(scans)

# Show the xml of a scan
xml = nessus.export_scan(8)
print(xml[0:200])

# Export a scan as a csv file
#

# Logout
nessus.logout()
print('Done')
