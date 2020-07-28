import requests
import json
import sys
import argparse
import time
import pandas as pd

# Disable Warning when not verifying SSL certs.
requests.packages.urllib3.disable_warnings()

def build_url(resource):
    return '{0}{1}'.format(url, resource)

def connect(method, resource, data=None, params=None, token=''):
    """
    Send a request

    Send a request to Nessus based on the specified data. If the session token
    is available add it to the request. Specify the content type as JSON and
    convert the data to JSON format.
    """
    headers = {'X-Cookie': 'token={0}'.format(token),
               'content-type': 'application/json'}

    data = json.dumps(data)

    if method == 'POST':
        r = requests.post(build_url(resource), data=data, headers=headers, verify=verify)
    elif method == 'PUT':
        r = requests.put(build_url(resource), data=data, headers=headers, verify=verify)
    elif method == 'DELETE':
        r = requests.delete(build_url(resource), data=data, headers=headers, verify=verify)
    else:
        r = requests.get(build_url(resource), params=params, headers=headers, verify=verify)

    # Exit if there is an error.
    if r.status_code != 200:
        e = r.json()
        print (e['error'])
        sys.exit()

    # When downloading a scan we need the raw contents not the JSON data.
    if 'download' in resource:
        return r.content

    # All other responses should be JSON data. Return raw content if they are
    # not.
    try:
        return r.json()
    except ValueError:
        return r.content


def login(usr, pwd):
    # Login to Nessus.

    login = {'username': usr, 'password': pwd}
    data = connect('POST', '/session', data=login)
    return data['token']


def get_policies():
    """Get scan policies. """
    data = connect('GET', '/editor/policy/templates')
    policy_df = pd.DataFrame(data['templates'])
    return policy_df


def get_scans(token):
    """List scans with their IDs. 
    
    Returns a panads DataFrame.
    """

    status_dict = {}
    name_dict = {}
    data = connect('GET', '/scans/', token=token)
    scan_df = pd.DataFrame(data['scans'])
    scan_df = scan_df[['id', 'name', 'creation_date', 'status']]

    return scan_df


def get_history_ids(sid):
    """Get history ids

    Create a dictionary of scan uuids and history ids so we can lookup the
    history id by uuid. 
    """
    data = connect('GET', '/scans/{0}'.format(sid))
    temp_hist_dict = dict((h['history_id'], h['status']) for h in data['history'])
    temp_hist_dict_rev = {a:b for b,a in temp_hist_dict.items()}
    try:
        for key,value in temp_hist_dict_rev.items():
            print (key)
            print (value)
    except:
        pass
    #return dict((h['uuid'], h['history_id']) for h in data['history'])


def get_scan_history(sid, hid):
    """Scan history details

    Get the details of a particular run of a scan.
    """
    params = {'history_id': hid}
    data = connect('GET', '/scans/{0}'.format(sid), params)
    return data['info']


def get_status(sid):
    """Get the status of a scan by the sid."""

    time.sleep(3) # sleep to allow nessus to process the previous status change
    scan_df = get_scans()
    # TODO: extract the correct status


def launch(sid):
    # Launch the scan specified by the sid.

    data = connect('POST', '/scans/{0}/launch'.format(sid))
    return data['scan_uuid']

def pause(sid):
    # Pause the scan specified by the sid.
    connect('POST', '/scans/{0}/pause'.format(sid))
    return

def resume(sid):
    # Resume the scan specified by the sid.
    connect('POST', '/scans/{0}/resume'.format(sid))
    return

def stop(sid):
    # Resume the scan specified by the sid.
    connect('POST', '/scans/{0}/stop'.format(sid))
    return

def logout():
    # Logout of Nessus.
    print('Logging Out...')
    connect('DELETE', '/session')
    print('Logged Out')
    exit()


def generate_api_key(token):
    headers = {'X-Cookie': 'token={0}'.format(token),
               'content-type': 'application/json'}

    data = json.dumps(None)

    r = requests.put('https://localhost:8834/session/keys', data=data, headers=headers, verify=verify)

    print(r.json())


def export_scan(scan_id, token):

    data = {'format': 'nessus'}
    response = connect('POST', f'/scans/{scan_id}/export', data=data, token=token)
    file_id = response['file']

    export_status_route = f'/scans/{scan_id}/export/{file_id}/status'
    # Wait for nessus to finish exporting the scan
    max_wait = 60  # seconds
    for seconds in range(max_wait):
        time.sleep(1)
        response = connect('GET', export_status_route, token=token)
        status = response['status']
        print(status)
        if status != 'loading':
            break

    download_route = f'/scans/{scan_id}/export/{file_id}/download'
    scan_xml = connect('GET', download_route, token=token)
    return scan_xml


if __name__ == '__main__':

    with open('config.json', 'r') as infile:
        config = json.load(infile)

    url = config['url']
    verify = config['verify']
    token = config['token']
    username = config['username']
    password = config['password']

    print(username, password)

    print('Logging in...')
    try:
        token = login(username, password)
    except: 
        raise RuntimeError('Unable to login.')
    print('Login successful.\n\n')
    
    scans_df = get_scans(token)
    print(scans_df)

    scan_xml = export_scan(scan_id=8, token=token)

    print(scan_xml[0:100])
    
    print('Done')

