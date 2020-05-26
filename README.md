## Nessus Plugin XML Export Parser

##### This script compares a list of CVEs to a Nessus Plugin XML Export file and writes, to a report file, each matched Plugin ID with its matched CVEs and associated IAVs.

##### Required Items:
1. Standard plugins.xml export file
2. List of CVEs where each line has only one CVE and other strings are separated by whitespace
  * The lines are split on whitespace, selects the first string, adds XML tags, and then stores the string in a set.
  
##### Steps to run:
1. Ensure required items are present in the script directory.
2. Run using Python 3.3 or above (tested with Python 3.8.2)
  * The script runs very fast; takes around 1 minute with a set of 200 CVEs and 9 million lines in the XML export
3. Find report in nessus_plugin_report.txt
