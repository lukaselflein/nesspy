# nesspy
Automated Nessus vulnerability scanning

# Overview
Since Nessus 6, automation of the Nessus scanner is very limited.
This project uses the limited capabilities of the shipped API to build an automated workflow for vulnerability management.

The API is abstracted into Python objects, all http requests are handled in the background.

# Usage
Set up a connection to the nessus backend by providing your login credentials in the `config.json` file:
``` python
    from nesspy import ConnectionManager
    with open('config.json', 'r') as infile:
        config = json.load(infile)
    nessus = ConnectionManager(**config)
```
List all scans saved in the backedn
``` python
    scans = nessus.list_scans()
    print(scans)
```    
|    | id |                  name | creation_date |    status
| -- |:--:| ---------------------:| ------------- | --------:
| 0  |  8 | My Basic Network Scan |    1595850410 | completed
| 1  | 11 |             Discovery |    1595589928 | completed

Export a .nessus/xml file
``` python
    xml = nessus.export_scan(8)
    print(xml)
```

Export a .csv file
``` python
    from nessus_parser import parser
    cvs = parser(xml)
    print(csv)
```

# Setup
1. Install & run the Nessus Scanner on your local machine.
2. Start/schedule a vulnerability scan on the webinterface (default: https://localhost:8834)
3. Run the export automation script
4. Run the parser scripts to generate a sanitized .csv file
5. Import the .csv into your favorite monitoring platform (tested with Splunk)

# Status
Under active development, limited functionality.

# Dependencies
Nessus 8.x
Python 3.x
packages from requirements.txt

# Contributions
This package builds on previous work:

Autonessus is a python2 cli-interface to nessus
https://github.com/redteamsecurity/AutoNessus
