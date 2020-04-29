# fixed_vulns_json_report

# Notice
Please use Python3

# Quick Start
```
$ git clone https://github.com/jbrotsos/fixed_vulns_json_report.git
```
```
$ pip install -r requirments.txt
```

Next, set up configuration (in e.g. ~/.Checkmarx/config.ini, or C:\\Users\\Administrator\\.Checkmarx\\config.ini)
```buildoutcfg
[checkmarx]
base_url = http://localhost:80
username = ******
password = ******
grant_type = password
scope = sast_rest_api
client_id = resource_owner_client
client_secret = 014DF517-39D1-4453-B7B3-9930C563627C
url =  %(base_url)s/cxrestapi
scan_preset = Checkmarx Default
configuration = Default Configuration
team_full_name = /CxServer
max_try = 3
```
# Optional Arguments

* --startdate
* --enddate

Must be in format of YEAR-MONTH-DAY


# Example
```Shell
cd fixed_vulns_json_report
python get_stats.py --startdate 2020-01-01 --enddate 2020-12-31
```

