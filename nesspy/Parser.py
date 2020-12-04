import ipaddress
import datetime
import csv

from lxml import etree as elmtree


class Scan:
    """A nessus vulnerability scan.

    It consists of multiple hosts, where findings (CVE) are reported.
    The scan can be exported in different formats (xml, csv, ..).
    """

    def __init__(self, xml_string=None, xml_file_path=None):
        """Set up a new scan, process xml input."""
        self.hosts = []

        # Handle xml input
        if xml_string is not None:
            if xml_file_path is None:
                self.xml_file_path = "./scan.xml"
                # TODO: This is somewhat ugly, file should not be written by default.
                # Try to default to reading from string, and only write to file if called.
                with open(self.xml_file_path, 'wb') as xml_file:
                   xml_file.write(xml_string)
            else:
                raise ValueError('Empty Scan initiated.')

        self.parse_xml()
        self.header_list = None
        self.findings = self.hosts_to_table()

    def parse_xml(self):
        """Read xml structure, convert into hosts/findings."""
        xml_source = self.xml_file_path
        for event, element in elmtree.iterparse(
                xml_source,
                events=('start', 'end'),
                tag=('ReportHost', 'ReportItem', 'HostProperties')):

            if event == 'start':

                if element.tag == 'ReportHost':
                    host = None
                    hostname = element.attrib['name']

            elif event == 'end':
                if element.tag == 'HostProperties':
                    host_ip = handle_host(element, hostname)
                    for child in element:
                        if child.attrib == 'a':
                            pass
                    scan_time = element[-2]
                    if host_ip is not None:
                        fully_qualified_domain_name = hostname
                        simple_hostname = fully_qualified_domain_name.split('.')[0]

                        host = Host(ip=host_ip, dns=simple_hostname)
                        host.fqdn = fully_qualified_domain_name
                        self.hosts += [host]

                elif element.tag == 'ReportItem':
                    finding = handle_finding(element)
                    if finding is not None:
                        # TODO: this is not safe, report could be about other host
                        finding.scan_date = datetime.datetime.fromtimestamp(int(scan_time.text))

                        host.findings.add(finding)
        self.hosts = set(self.hosts)

    def hosts_to_table(self):
        """Convert abstract host and finding objects into a table of strings."""
        hosts = self.hosts
        host_table = []
        finding_table = []

        for host in hosts:
            host_table += [[host.dns, host.ip]]
            for finding in list(host.findings):
                finding_table += [[finding.scan_date,
                                   host.ip, 
                                   host.dns,
                                   finding.cve, 
                                   finding.cvss, 
                                   finding.exploit,
                                   finding.plugin_name, 
                                   finding.plugin_mod_date,
                                  ]]

        self.host_table = host_table
        self.finding_table = finding_table
        self.header_list = ['scan_date', 'ip', 'dns', 'cve', 'cvss', 
                       'exploit', 'plugin_name', 'plugin_mod_date']

        return finding_table

    def to_csv(self, path, *args, **kwargs):
        """Export the DataFrame to a .csv file"""
        with open(path, 'w', newline='') as csvfile:
            exporter = csv.writer(csvfile, delimiter=',',
                                  quotechar='"', quoting=csv.QUOTE_MINIMAL)
            # Write 
            exporter.writerow(self.header_list)
            for row in self.finding_table:
                exporter.writerow(row)


class Host():
    """An asset/computer in a network. Has an IP-Address, DNS, and findings/vulnerabilities."""
    def __init__(self, ip=None, dns=None):
        """Validate input and set up empty containers."""
        # validate ip 
        if ip is not None:
            try:
                ipaddress.ip_address(ip)
            except:
                raise ValueError(f'{ip} is invalid IP-Address.')

        # validated ip
        self.ip = ip
        # host name
        self.dns = dns
        # fully qualified domain name
        self.fqdn = dns

        # List of findings
        self.findings = set()

    def __str__(self):
        """Pretty print as 192.168.1.100, example.homenet.de"""
        string = f'{self.ip}, {self.dns}'
        return string


class Finding():
    """A finding reported by nessus.

    This may be a vulnerability, or just information like open ports.
    """
    def __init__(self, cve = None, cvss = None, 
                 plugin_name = None, description = None,
                 plugin_mod_date = None, exploit = None, 
                 scan_date = None):
        self.cve = cve
        self.cvss = cvss
        self.plugin_name = plugin_name
        self.description = description
        self.plugin_mod_date = plugin_mod_date
        self.exploit = exploit
        self.scan_date = scan_date


def handle_finding(element, exclude_info=False):
    """Iterate through xml tags and write interesting tags to finding object."""

    # Set to True to exclude informational notices (open ports etc)
    if exclude_info:
        if int(element.attrib['severity']) == 0:
            return None

    # Create a new finding object
    finding = Finding()
    # Write interesting tags into finding object
    for child in element:
        if child.tag == 'description':
            finding.description = child.text
        elif child.tag == 'cve':
            finding.cve = child.text
        elif child.tag == 'plugin_name':
            finding.plugin_name = child.text
        elif child.tag == 'cvss_base_score':
            finding.cvss = child.text
        elif child.tag == 'exploit_available':
            finding.exploit = child.text
        elif child.tag == 'plugin_modification_date':
            date = child.text.replace('/', '-')
            finding.plugin_mod_date = date
        elif child.tag == 'HOST_END_TIMESTAMP':
            finding.scan_date = child.text
    return finding


def handle_host(host_element, hostname):
    for host_prop_tag in host_element.iterchildren():
        if 'name' in host_prop_tag.attrib.keys():
            host_prop_name = host_prop_tag.attrib['name']
            host_prop_tag = host_prop_tag.text
            if host_prop_name == 'host-ip':
                host_ip = host_prop_tag
                return host_ip
    return None
