import ipaddress
import datetime
import csv
import io
import lxml.etree

def parse(xml_file_path = "./scan.xml", skip_empty_cvss=False):
    """Parse nessus xml export, extract vulneraibility information.

    Arguments:
        xml_file_path: path to the nessus xml export file
    Returns:
        a list of dicts containing vulnerability information

    The nessus xml structure goes like:

                       NessusClientData_v2
                          |            |
                       Report        Policy
                          |       
                      ReportHost 
                     |          |
              ReportItem  HostProperties
              |        |
     plugin_output  plugin_name 
    """

    # List information that will be parsed
    parse_properties = ['host-ip', 'host-rdns', 'operating-system', 'HOST_END_TIMESTAMP' ,
                        'sinfp-ml-prediction']
    parse_properties += ['port', 'protocol','cve', 'cvss_base_score', 'plugin_name',
                         'exploit_available', 'plugin_modification_date']
    parse_properties += ['description']

    finding_list = []
    for event, element in lxml.etree.iterparse(
            xml_file_path,
            events=('start', 'end'),
            tag=('ReportHost', 'ReportItem', 'HostProperties')):

        # A new host
        if event == 'start' and element.tag == 'ReportHost':
            # Initialize empty structure to store findings
            finding = {}
            for key in parse_properties:
                finding[key] = None

        # Extract host-specific details
        # E.g., <HostProperties><tag name="host-rdns">_gateway</tag>...</HostProperties>
        if event == 'end' and element.tag == 'HostProperties':
            # search through <tag name=...></tag> children
            for child in element:
                if 'name' in child.attrib.keys():
                    key = child.attrib['name']
                    if key in finding.keys():
                        finding[key] = child.text

        # Get the vulnerability details
        elif  element.tag == 'ReportItem':
            # The start of a report item (finding) contains port info
            # e.g., <ReportItem port="80" svc_name="http?" protocol="tcp" ... >
            if event =='start':
                # Values in the start tag
                for key in finding.keys():
                    if key in element.attrib.keys():
                        finding[key] = element.attrib[key]

            # The body of the report item contains the rest of the infos
            elif event =='end':
                    # Each property is encoded like <plugin_name>Nessus SYN scanner</plugin_name>
                    for child in element:
                        if child.tag in finding.keys():
                            finding[child.tag] = child.text

        # Do skip saving the finding if appropriate
        if skip_empty_cvss:
            if finding[cvss] is None:
                continue

        # Save the finding
        finding_list += [finding.copy()]

    return finding_list


def dict_to_log_string(finding_dict):
    """Export the vulnerabilities to a default log file.
       Format is comma seperated like property=value, prob2=val2"""
    return ', '.join([f"""'{key}'='{finding_dict[key]}'""" for key in finding_dict.keys()])


def to_logfile(finding_list, logfile_path):
    """Save list of vulnerability-dicts to file."""
    log_strings = [dict_to_log_string(d) for d in finding_list]
    out_string = '\n'.join(log_strings)

    with open(logfile_path, 'w') as out_file:
        out_file.write(out_string)


if __name__ == '__main__':
    finding_list = parse(xml_file_path = "./scan.xml")
    to_logfile(finding_list=finding_list, logfile_path='test.log')
