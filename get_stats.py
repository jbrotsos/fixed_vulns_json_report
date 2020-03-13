"""
1. get token (auth header)
2. get team id
3. create project with default configuration, will get project id
4. set remote source setting to git
5[optional]. set issue tracking system as jira by id
6. set data retention settings by project id
7. define SAST scan settings
8. create new scan, will get a scan id
9. get scan details by scan id
10[optional]: get scan queue details by scan id
11[optional]. get statistics results by scan id
12. register scan report
13. get report status by id
14. get report by id
15[optional]. filter report results

---
1. get token (auth header)
2. get list of projects
3. get list of scans for each project

"""
import time
import xmltodict
import json

from pathlib import Path

from CheckmarxPythonSDK.CxRestAPISDK import TeamAPI
from CheckmarxPythonSDK.CxRestAPISDK import ProjectsAPI
from CheckmarxPythonSDK.CxRestAPISDK import ScansAPI




def create_fixed_elem (prev_list, current_list, date):
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
# {
#   project_name: xxxx,
#   SID: xxxx,
#   vuln_name: xxxx,
#   result: {
#        state:  xxx,
#        status: xxx
#   },
#   date: xxxxx
# },

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

def get_project_results(file):
    scan_api = ScansAPI()
    projects_api = ProjectsAPI()
    report = []
    current_scan_results = []
    last_scan_results = []

    projects = projects_api.get_all_project_details()

    for project in projects:

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
                        create_fixed_elem(last_scan_results, current_scan_results, date)
                        report.append(current_scan_results)
                        
                    else:
                        print ("[ERROR] document parsing failed for " + str(scan.id))
                else:
                    print ("[ERROR] report content failed for " + str(scan.id))
            else:
                print ("[ERROR] scan report not found for " + str(scan.id))


    file.write (json.dumps(report))

    last_scan_results = current_scan_results 


if __name__ == "__main__":

    file = open("list_of_vulns.json","w")

    get_project_results(file)

    file.close()
