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

It uses Checkmarx's support Python SDK.

"""
import time
import xmltodict
import json
import argparse
import datetime

from pathlib import Path

from CheckmarxPythonSDK.CxRestAPISDK import TeamAPI
from CheckmarxPythonSDK.CxRestAPISDK import ProjectsAPI
from CheckmarxPythonSDK.CxRestAPISDK import ScansAPI

def create_fixed_elements (prev_list, current_list, scan_start_date):
    """
    If a SID doesn't exist in a new scan (compared to the last scan), the SID was 'Fixed' or removed.
    Copy all the info from the previous element but change the status to Fixed.
    Also update the date of the scan.  """

    for prev in prev_list:
        found = False
   
        for current in current_list:
            if (prev['SID'] == current['SID']):
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
            newElement['date'] = scan_start_date
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

def get_project_results(user_startdate, user_enddate):
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

    projects = projects_api.get_all_project_details()

    filename = str(time.strftime("%Y%m%d-%H%M%S")) +  "_list_of_vulns.json"
    file = open(filename,"w")

    for project in projects:

        print ("Scanning project: " + project.name + "... ")

        current_scan_results = []
        last_scan_results = []
        report = []

        try:
            scans = scan_api.get_all_scans_for_project(project.project_id, "Finished")
            scans.reverse()
        except:
            print ("Exception found when getting list of scans for project: " + project.name)
        

        for scan in scans:

            if (debug):
                print ("Starting report for scan: " + str(scan.id) + " at " + str(datetime.datetime.now()))

            # convert scan date from ISO 8601

            if "." in scan.date_and_time.finished_on:
                scan_date = datetime.datetime.strptime(scan.date_and_time.finished_on, "%Y-%m-%dT%H:%M:%S.%f")
            else:
                scan_date = datetime.datetime.strptime(scan.date_and_time.finished_on, "%Y-%m-%dT%H:%M:%S")

            # if no start date entered or if the scan start date is greater than the user start date entered
            # or 
            # if no end date entered or if the scan start date is less than the user end date entered

            if (not user_startdate or scan_date > user_startdate) and (not user_enddate or scan_date < user_enddate):
                try:
                    scan_report = scan_api.register_scan_report(scan.id, "XML")

                    if scan_report and scan_report.report_id:
                        
                        while not scan_api.is_report_generation_finished(scan_report.report_id):
                            time.sleep(1)

                        report_content = scan_api.get_report_by_id(scan_report.report_id)

                        if report_content:
                            document = xmltodict.parse(report_content, force_list={'Query'})

                            if document:
                                current_scan_results, scan_start_date = parse_xml (document)
                                if last_scan_results:
                                    create_fixed_elements(last_scan_results, current_scan_results, scan_start_date)
                                report.append(current_scan_results)
                                
                            else:
                                print ("[ERROR] document parsing failed for " + str(scan.id))
                        else:
                            print ("[ERROR] report content failed for " + str(scan.id))
                    else:
                        print ("[ERROR] scan report not found for " + str(scan.id))

                    last_scan_results = current_scan_results
                except:
                    print ("Exception when getting report of scan (possibly scan didn't run because no code changes): " + str(scan.id) + " / project: " + project.name)

            if (debug):
                print ("Ending report for scan: " + str(scan.id) + " at " + str(datetime.datetime.now()))

        print ("Finished")

        reportStr = json.dumps(report)

        if (reportStr != "[]"):
            file.write (json.dumps(report))

    file.close()

    return ()

def valid_date(s):
    """
    Validate the date passed as argument
    """

    try:
        return datetime.datetime.strptime(s, "%Y-%m-%d")
    except ValueError:
        msg = "Not a valid date: '{0}'.".format(s)
        raise argparse.ArgumentTypeError(msg)

if __name__ == "__main__":
    """
    Read in arguments if passed
    """

    parser = argparse.ArgumentParser()

    parser.add_argument("--startdate", help="The Start Date - format YYYY-MM-DD", 
                    required=False, 
                    type=valid_date)

    parser.add_argument("--enddate", help="The End Date - format YYYY-MM-DD", 
                    required=False,
                    type=valid_date)

    parser.add_argument('--debug', help='Print debug info', 
                    action='store_true', 
                    default=False)

    args = parser.parse_args()

    user_startdate = args.startdate
    user_enddate = args.enddate
    debug = args.debug

    get_project_results(user_startdate, user_enddate)
