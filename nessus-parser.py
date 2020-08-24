#!/usr/bin/python

###Nessus Parser
#Written by Lee and Agatha Armbuster

from xml.dom import pulldom


def main():

    def plugin_parser():
        
        event_stream = pulldom.parse('XML Export File')
        cve_list = open('CVE List File', 'r')
        nessus_plugin_report = open('nessus_plugin_report.txt', 'w+')


        cve_xml_set=set([])
        for line in cve_list:
            cve_line_split = line.split()
            cve_xml = '<cve>' + cve_line_split[0] + '</cve>'
            cve_xml_set.add(cve_xml)
    

        for event, node in event_stream:
            
            if event == pulldom.START_ELEMENT and node.tagName == 'script_id':
                event_stream.expandNode(node)
                script_id_node_toxml = node.toxml()
            
            if event == pulldom.START_ELEMENT and node.tagName == 'cves':
                event_stream.expandNode(node)
                cves_node_toxml = node.toxml()
                for cve_xml in cve_xml_set:
                    if cve_xml in cves_node_toxml:
                        cve_match_boolean = True
                        script_id_no_tag = script_id_node_toxml.replace('<script_id>', '')
                        script_id_no_tag = script_id_no_tag.replace('</script_id>', '')
                        nessus_plugin_report.write('\n')
                        nessus_plugin_report.write('Nessus ID: ')
                        nessus_plugin_report.write(script_id_no_tag)
                        nessus_plugin_report.write('\n')
                        nessus_plugin_report.write('CVEs:')
                        nessus_plugin_report.write('\n')
                        for cve_xml in cve_xml_set:
                            if cve_xml in cves_node_toxml:
                                cve_no_tag = cve_xml.replace('<cve>', '')
                                cve_no_tag = cve_no_tag.replace('</cve>', '')
                                nessus_plugin_report.write(cve_no_tag)
                                nessus_plugin_report.write('\n')
                            else:
                                continue
                        break                 
                    else:
                        continue

            if event == pulldom.START_ELEMENT and node.tagName == 'xref' and cve_match_boolean == True:
                event_stream.expandNode(node)
                xref_node_toxml = node.toxml()
                if xref_node_toxml.startswith('<xref>IAV') == True:
                    xref_no_tag = xref_node_toxml.replace('<xref>', '')
                    xref_no_tag = xref_no_tag.replace('</xref>', '')
                    nessus_plugin_report.write(xref_no_tag)
                    nessus_plugin_report.write('\n')
                else:
                    continue
            
            if event == pulldom.END_ELEMENT and node.tagName == 'xrefs':      
                cve_match_boolean = False     
            
            else:
                continue


    plugin_parser()


if __name__ == "__main__":
    main()
