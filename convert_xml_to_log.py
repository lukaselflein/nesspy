import datetime
import os 
import sys

from nesspy.Parser import Scan, Host, Finding

if False:
    in_file_name = './test.xml'
    with open(in_file_name, 'rb') as in_file:
        xml_string = in_file.read()

else:
    xml_string = ''
    for line in sys.stdin:
        xml_string += line

xml_string = bytes(xml_string, 'utf-8')

# Parse the scan
scan = Scan(xml_string=xml_string)

# Export the scan to csv
out_file_name = 'manually_exported_scan.log'

#log_path = "/var/log/nessus/"
log_path = "./data"
out_path = os.path.join(log_path, out_file_name)
scan.to_log(path=out_path, header=False)

print(f'Successfully converted scan xml to {out_path} !')
