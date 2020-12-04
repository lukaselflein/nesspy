import requests
import json
import sys
import argparse
import time

class ConnectionManager:
    """Connects to Nessus."""

    def __init__(self, username, password, host="https://localhost:8834", 
                 verify=False, *args, **kwargs):
        """Initiate connecion to Nessus Backend.
        Requires login credentials.
        """
        self.host = host  # Location of the nessus server
        # Nessus user account
        self.username = username
        self.password = password

        # Check/do not check SSL
        self.verify = verify
        # Disable Warning when not verifying SSL certs.
        if not verify:
            requests.packages.urllib3.disable_warnings()

        # Login to get a session token
        self.token = ''  # needed for the login
        self.token = self.login()

        # Cache all scans saved on nessus
        self.scan_list = self.list_scans()

    def connect(self, method, resource, data=None, params=None):
        """Send a http request to the nessus backend.

        The stored token is used for authentication, provided data is
        converted to json and attached to the request.
        Returns the data in the response.
        Raises a RuntimeError if the response code signals failure.
        """
        # construct the URL
        url = self.host + resource

        # Write the auth token (if any) into the header
        headers = {'X-Cookie': f'token={self.token}',
                   'content-type': 'application/json'}

        data = json.dumps(data)

        if method == 'POST' :
            response = requests.post(url, headers=headers, verify=self.verify, data=data)
        elif method == 'PUT':
            response = requests.put(url, headers=headers, verify=self.verify, data=data)
        elif method == 'DELETE':
            response = requests.delete(url, headers=headers, verify=self.verify, data=data)
        elif method == 'GET':
            response = requests.get(url, headers=headers, verify=self.verify, params=params)
        else:
            raise RuntimeError(f'Unsupported HTTP method: {method}')

        # Exit if there is an error.
        if response.status_code != 200:
            error = response.json()
            message = f'HTTP request returned status {response.status_code}: {error["error"]}'
            raise RuntimeError(message)

        # When downloading a scan we need the raw contents not the JSON data.
        if 'download' in resource:
            return response.content

        # All other responses should be JSON data. Return raw content otherwise.
        try:
            return response.json()
        except ValueError:
            return response.content

    def login(self):
        """Authenticate against Nessus backend.
        Save token for future connections.
        """
        login = {'username': self.username, 'password': self.password}
        r = self.connect(method='POST', resource='/session', data=login)
        return r['token']

    def logout(self):
        """Logout of Nessus."""
        response = self.connect(method='DELETE', resource='/session')
        return 'Logged Out'

    def list_scans(self):
        """List scans with their IDs. 
        
        Returns a panads DataFrame.
        """
        scan_list = []
        data = self.connect(method='GET', resource='/scans/')
        for scan in data['scans']:
            scan_list.append([scan['id'], scan['name'], scan['creation_date'], scan['status']])
        return scan_list

    def export_scan(self, scan_id):
        """Export a scan from the backend to an xml string."""

        # Check if Scan ID exists
        if scan_id not in [line[0] for line in self.scan_list]:
            raise RuntimeError(f"ID {scan_id} not in scans.")

        # First, we need to request an export from nessus
        data = {'format': 'nessus'}
        response = self.connect(method='POST', resource=f'/scans/{scan_id}/export', data=data)
        file_id = response['file']

        # Wait for nessus to finish exporting the scan
        export_status_route = f'/scans/{scan_id}/export/{file_id}/status'
        max_wait = 60  # seconds
        print('Waiting for nessus export ...')
        for seconds in range(max_wait):
            response = self.connect(method='GET', resource=export_status_route)
            status = response['status']

            if status != 'loading':
                print(f'{status} ({seconds} s)')
                break
            print(f'{status}  ', end="\r")
            time.sleep(1)

        # When the export has finished loading, download the xml file
        download_route = f'/scans/{scan_id}/export/{file_id}/download'
        scan_xml = self.connect(method='GET', resource=download_route)
        return scan_xml

    def export_latest(self):
        """Return a xml-string representation of the most recent scan."""
        # Search for the latest scan in the metadata
        latest_timestamp = max([line[2] for line in self.scan_list])
        latest_scan_id = [line[0] for line in self.scan_list if line[2] >= latest_timestamp][0]
        # Get the scan corresponding to the ID from the metadat
        latest_scan_xml = self.export_scan(scan_id=latest_scan_id)

        return latest_scan_xml


if __name__ == '__main__':

    # Read login parameters (host, username, password)
    # e.g., (localhost:8834, testusr, pw)
    with open('config.json', 'r') as infile:
        config = json.load(infile)

    # Communicate with the backend via the connection manager
    nessus = ConnectionManager(**config)
    scans = nessus.list_scans()
    print(scans)
    xml = nessus.export_scan(8)
    print(xml[0:200])
    print(nessus.logout())

    print('Done')
