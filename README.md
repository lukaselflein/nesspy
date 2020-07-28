# nesspy
Automated Nessus vulnerability scanning

# Overview
Since Nessus 6, automation of the Nessus scanner is very limited.
This project uses the limited capabilities of the shipped API to build an automated workflow for vulnerabilitd management.

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
