"""
This script is intended to list all the scan results with the expected format:

 {
   project_name: xxxx,
   SID: xxxx,
   vuln_name: xxxx,
   result: {
        state:  xxx,
        status: xxx
   },
   date: xxxxx
}

If a SID is not present in the new scan, it will update the status to be "Fixed"
"""
import time
import xmltodict
import json

from pathlib import Path

from CheckmarxPythonSDK.CxRestAPISDK import TeamAPI
from CheckmarxPythonSDK.CxRestAPISDK import ProjectsAPI
from CheckmarxPythonSDK.CxRestAPISDK import ScansAPI


def create_fixed_elements (prev_list, current_list, date):
"""
If a SID doesn't exist in a new scan (compared to the last scan), the SID was 'Fixed' or removed.
Copy all the info from the previous element but change the status to Fixed.
Also update the date of the scan
"""
    for i in prev_list:
        for j in current_list:
            found = False

            if (i['SID'] == j['SID']):
                found = True
                break

        if found != True:
            newElement = {}
            newElement['project_name'] = i['project_name']
            newElement['SID'] = i['SID']
            newElement['name'] = i['name'] 

            status = {}
            status['state'] = i['result']['state']
            status['status'] = "Fixed"

            newElement['result'] = status
            newElement['date'] = date
            current_list.append(newElement)

def parse_xml (doc):
"""
Parsing the XML output to form an element with the following format:

 {
   project_name: xxxx,
   SID: xxxx,
   vuln_name: xxxx,
   result: {
        state:  xxx,
        status: xxx
   },
   date: xxxxx
},
"""
    if doc and 'CxXMLResults' in doc:
        vulnList = []

        xml_results = doc['CxXMLResults']

        if xml_results and 'Query' in xml_results:
            for query in xml_results['Query']:
                results = query['Result']
                list_results = []
                if isinstance(results, list):
                    list_results = results
                else:
                    list_results.append(results)
                for result in list_results:
                    vulnElement = {}

                    vulnElement['project_name'] = xml_results["@ProjectName"]

                    vulnElement['SID'] = result["Path"]["@SimilarityId"]
                    
                    vulnElement['name'] = query["@name"]

                    status = {}
                    status['state'] = result["@state"]
                    status['status'] = result["@Status"]

                    vulnElement['result'] = status

                    vulnElement['date'] = xml_results["@ScanStart"]

                    vulnList.append(vulnElement)

        return (vulnList, xml_results["@ScanStart"])

    return [], "ERROR" 

def get_project_results(file):
"""
- Get a list of all the projects
- Get a list of all the Finished scans for each project
- Get the results of the scan in an XML format
- Parse through the results to create an element
- Check to see if there are any elements that don't exist, if they don't, create a fixed element
- Add the element to the report list that is conveted to a json string on return
"""
    scan_api = ScansAPI()
    projects_api = ProjectsAPI()
    report = []

    projects = projects_api.get_all_project_details()

    for project in projects:
        current_scan_results = []
        last_scan_results = []

        scans = scan_api.get_all_scans_for_project(project.project_id, "Finished")
        scans.reverse()

        for scan in scans:
            scan_report = scan_api.register_scan_report(scan.id, "XML")

            if scan_report and scan_report.report_id:
                
                while not scan_api.is_report_generation_finished(scan_report.report_id):
                    time.sleep(1)

                report_content = scan_api.get_report_by_id(scan_report.report_id)

                if report_content:
                    document = xmltodict.parse(report_content, force_list={'Query'})

                    if document:
                        current_scan_results, date = parse_xml (document)
                        if last_scan_results:
                            create_fixed_elements(last_scan_results, current_scan_results, date)
                        report.append(current_scan_results)
                        
                    else:
                        print ("[ERROR] document parsing failed for " + str(scan.id))
                else:
                    print ("[ERROR] report content failed for " + str(scan.id))
            else:
                print ("[ERROR] scan report not found for " + str(scan.id))

            last_scan_results = current_scan_results

    return (json.dumps(report))

if __name__ == "__main__":
"""
Create a file that we can output the results to

"""

    file = open("list_of_vulns.json","w")

    json_str = get_project_results(file)

    file.write (json_str)

    file.close()
