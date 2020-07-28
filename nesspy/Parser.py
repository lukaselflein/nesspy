
class Scan:
    """A nessus vulnerability scan.
    Can be coverted to different formats.
    """

    def __init__(self, xml):
        self.xml = xml
        self.df = None

    def export_xml(self, path='./scan.nessus'):
        with open(path, 'w') as outfile:
            outfile.write(self.xml)

    def export_csv(self, path='./scan.csv'):
        self.df.to_csv(path)

    def __str__(self):
        return self.xml[0:100]


