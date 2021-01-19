import json
import datetime
import os 

from nesspy.Connect import ConnectionManager
from nesspy.Parser import Scan, Host, Finding


# Read login parameters (host, username, password)
# e.g., (localhost:8834, testusr, pw)
with open('config.json', 'r') as infile:
    config = json.load(infile)

# Communicate with the backend via the connection manager
nessus = ConnectionManager(**config)

# List the scans saved in the backend
scan_list = nessus.list_scans()
print(scan_list)

# Find latest completed automatic scan by age
scan_times = [entry[2] if entry[-1] == 'completed'  # this excludes unfinished, running scans 
                       # and 'auto' in entry[1].lower()  # naming convention, exclude manual scans
                       else -1 
                       for entry in scan_list] 
print(scan_times)
latest_scan_time = max(scan_times)
print(latest_scan_time)

# Select latest finished scan with "auto" in scan name
for entry in scan_list:
   if entry[2] == latest_scan_time: 
      latest_scan_id = entry[0]
      latest_scan_name = entry[1]
      break

try:
    int(latest_scan_id)
except:
    print('No Scan was found. Is nessusd running?')
    exit()

# Export the scan as an xml string (in memory)
xml_string = nessus.export_scan(latest_scan_id)

# Logout
nessus.logout()

# Parse the scan
scan = Scan(xml_string=xml_string)

# Export the scan to csv
date_time = datetime.datetime.fromtimestamp(latest_scan_time)
time_string = date_time.strftime("%Y-%m-%dT%H-%M-%S")
out_file_name = latest_scan_name.lower().replace(" ", "-") + "_" +  time_string + ".csv"
log_path = "./data"
out_path = os.path.join(log_path, out_file_name)
scan.to_csv(path=out_path, header=False)
print(f'Successfully written "{latest_scan_name}" to {out_path} !')

# Export scan to [label=value, ...] log format
out_file_name = latest_scan_name.lower().replace(" ", "-") + "_" +  time_string + ".log"
out_path = os.path.join(log_path, out_file_name)
scan.to_log(path=out_path, header=False)
print(f'Successfully written "{latest_scan_name}" to {out_path} !')
