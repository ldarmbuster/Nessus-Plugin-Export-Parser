## Nessus Plugin XML Export Parser

##### This script compares a list of CVEs to a Nessus Plugin XML Export file and writes, to a report file, each matched Plugin ID with its matched CVEs and associated IAVs. It uses [xml.dom.pulldom](https://docs.python.org/3/library/xml.dom.pulldom.html) from the Standard Python Library so only a supported base Python 3 install is required. 

##### Required Items:
1. Standard plugins.xml export file
2.  Text file containing CVE IDs (e.g. CVE-2020-12345) where each line has only one CVE ID. Other strings can be on the same line but they need to be separated by whitespace
  * The lines are split on whitespace, selects the first string which needs to be the CVE ID, adds XML tags, and then stores the string in a set.
  
##### Steps to run:
1. Ensure required items are present in the script's directory.
2. Run using Python 3.3 or above (tested with Python 3.8.2)
  * The script runs very fast; takes around 1 minute with a set of 200 CVEs and 9 million lines in the XML export
3. Find report in nessus_plugin_report.txt
