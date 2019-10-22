
# Coded by Exploit Monk / October 2019
# You can use this script for funs or commerical (if commerical, must supply me with coffee per execute :D)

import json

xdict = {}
xdict['cves'] = []

# filename to parse
filename = input("Filename: ")

print("début...")



with open(filename, 'r') as f:
    data = json.load(f)

    for entry in data["CVE_Items"]:
            cve_id = entry['cve']['CVE_data_meta']['ID']  # get CVE
            cve_source = entry['cve']['CVE_data_meta']['ASSIGNER']  # get SOURCE

            # if CWE exist, grab
            try:
                cve_cwe = entry['cve']['problemtype']['problemtype_data'][0]['description'][0]['value']
            except:
                cve_cwe = ""

            # if references exists, grab
            cve_refs = []
            for url in entry['cve']['references']['reference_data']:
                ref = url['url']
                cve_refs.append(ref)

            # if description exists, grab
            try:
                cve_description = entry['cve']['description']['description_data'][0]['value']
            except:
                cve_description = ""

            # if impact V3 exists, grab
            try:
                cve_cvss3_vector = entry['impact']['baseMetricV3']['cvssV3']['vectorString']
                cve_cvss3_base = entry['impact']['baseMetricV3']['cvssV3']['baseScore']
            except:
                cve_cvss3_base = ''
                cve_cvss3_vector = ''

            # if impact V2 exists, grab
            try:
                cve_cvss2_vector = entry['impact']['baseMetricV2']['cvssV2']['vectorString']
                cve_cvss2_base = entry['impact']['baseMetricV2']['cvssV2']['baseScore']
            except:
                cve_cvss2_base = ''
                cve_cvss2_vector = ''
            
            # if publish date, grab
            try:
                publishedDate = entry['publishedDate']
            except:
                publishedDate = ''

            # if modifed date, grab    
            try:
                lastModifiedDate = entry['lastModifiedDate']
            except:
                lastModifiedDate = ''

            # prepare JSON
            xdict['cves'].append({
            'cve':  cve_id,
            'source': cve_source,
            'cwe': cve_cwe,
            'capec': '',
            'published': publishedDate,
            'modified': lastModifiedDate,
            'score3': cve_cvss3_base,
            'score2': cve_cvss2_base,
            'vector3': cve_cvss3_vector,
            'vector2': cve_cvss2_vector,
            'description':cve_description,
            'solution': '',
            'reference': cve_refs})


# standard JSON output
with open('cves-parsed.json', 'w', newline='\n') as outfile:
    json.dump(xdict['cves'], outfile)


# QUICK FIX! | - output file for MONGO DB (Bulk Upload JSONL)
with open("cves-parsed.json", "r") as read_file:
    data = json.load(read_file)

result = [json.dumps(record) for record in data]
with open('cves-parsed-mongodb.json', 'w') as obj:
    for i in result:
        obj.write(i+'\n')



print("output: cves-parsed.json, cves-parsed-mongodb.json")
