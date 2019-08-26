#!/usr/bin/python
import requests
import json
import hashlib
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# nessus rest api script to download smb vul machines only.

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

scan_ids = []
url = "https://localhost:8834"
auth_token = ""


def request_login():
    headers = {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'X-Requested-With': 'XMLHttpRequest',
        'Content-Type': 'application/json',
        'Connection': 'close'
    }
    data = '{"username":"admin","password":"admin@559"}'
    r = requests.post(url+'/session', headers=headers, data=data, verify=False)
    resp_json = json.loads(r.text)
    return resp_json['token']


auth_token = request_login()
headers = {"Connection": "close", "Accept": "application/json",
           "X-Cookie": "token="+auth_token, "Content-Type": "application/json"}
response = requests.get(url+'/scans', headers=headers, verify=False)
scans_json = json.loads(response.text)
for scan in scans_json['scans']:
    scan_ids.append(scan['id'])
scan_ids = ['103', '105']


def get_counts(id):
    resp = requests.get(url+'/scans/'+str(id), headers=headers, verify=False)
    resp_json = json.loads(resp.text)
    num_hosts = resp_json['info']['hostcount']
    return num_hosts


def get_host_details(scan_id, host_id):
    m = hashlib.md5()
    for i in range(host_id):
        resp = requests.get(url+'/scans/'+str(id)+'/hosts/' +
                            str(i), headers=headers, verify=False)
        try:
            vulns = ""
            resp_json = json.loads(resp.text)
            #scan_time = resp_json['info']['host_start']
            hostname = resp_json['info']['netbios-name']
            host_ip = resp_json['info']['host-ip']
            host_os = resp_json['info']['operating-system'].replace(
                "\n", " or ")
            for i in resp_json['vulnerabilities']:
                vulns = vulns + ',' + str(i['plugin_name'])+str("\n")
            result = hostname+','+host_ip+','+host_os+vulns
            m.update(result)
            print m.hexdigest()+','+result
        except Exception, e:
            pass


            #print str(e)
        # write to file
        # m.update(str(resp_json))
        # file = m.hexdigest()
        # with open(file, 'w') as outfile:
        #     json.dump(resp_json, outfile)
print scan_ids
for id in scan_ids:
    scan_counts = get_counts(id)
    get_host_details(id, scan_counts)
