import json

gl_results = {
    "version": "2.0.0",
    "vulnerabilities": [],
    "remediations": [],
    "dependency_files": []
}

with open("sca-results.json", "r") as r:
    results_json = json.load(r)
    results = results_json['records']
    
    fileName = ""
    packageManager = ""

    for findings in results:
        if 'graphs' in findings:
            for i in findings['graphs']:
                #Find the package manager
                if i['directs'][0]['coords']['coordinateType'] != None:
                    packageManager = i['directs'][0]['coords']['coordinateType']
                    pass
                else:
                    fileName = "Package Manager not found."
                
                #Find filename in the report
                print(i['directs'][0]['filename'])
                if i['directs'][0]['filename'] != None:
                    fileName = i['directs'][0]['filename']
                    break
                else:
                    fileName = "File not found."
        else:
            print("No Graphs available")
        

        #Find the vulnerabilities and build the json doc
        if 'vulnerabilities' in findings:
            for issue in findings['vulnerabilities']:
                
                #Add CVE to the actual number from the report
                if issue['cve'] != None:
                    cve = "CVE-" + issue['cve']
                else:
                    cve = "No CVE found"
                
                #Translate the CVSS score to Gitlabs severity.
                if float(issue['cvssScore']) == 0.0:
                    severity = "Info"
                elif float(issue['cvssScore']) >= 0.1 and  float(issue['cvssScore']) < 4.0:
                    severity = "Low"
                elif float(issue['cvssScore']) >= 4.0 and  float(issue['cvssScore']) < 7.0:
                    severity = "Medium"
                elif float(issue['cvssScore']) >= 7.0 and  float(issue['cvssScore']) < 9.0:
                    severity = "High"
                elif float(issue['cvssScore']) >= 9.0:
                    severity = "Critical"

                if len(issue['libraries']) != 0:
                    #Map the vulnerability to the library
                    ref = issue['libraries'][0]['_links']['ref']
                    new_ref = ref.split('/')
                    library = int(new_ref[4]) - 1
                    
                    #Assign variables that would've been in library
                    versionRange = issue['libraries'][0]['details'][0]['versionRange']
                    
                    #Checks there's no empty values
                    if issue['libraries'][0]['details'][0]['patch'] != "" and issue['libraries'][0]['details'][0]['patch'] != None:
                        patchUrl = issue['libraries'][0]['details'][0]['patch']
                    else: 
                        patchUrl = 'https://www.sourceclear.com'
                    
                    if issue['_links']['html'] != "" and issue['_links']['html'] != None:
                        refUrl = issue['_links']['html']
                    else:
                        refUrl = 'https://www.sourceclear.com'

                    #Upgrade version text for the report based on inputs.
                    if issue['libraries'][0]['details'][0]['updateToVersion'] != None:
                        updateVersion = "Upgrade to version " + issue['libraries'][0]['details'][0]['updateToVersion'] + "."
                    else:
                        updateVersion = "Unknown"
                else:
                    #Defaults if no Library information is available.
                    versionRange = 'Version Range Not Available'
                    patchUrl = 'https://www.sourceclear.com'
                    refUrl = 'https://www.sourceclear.com'
                
                #Covers any cases where the bugTrackerUrl is null, which breaks the schema
                if findings['libraries'][library]['bugTrackerUrl'] != None:
                    bugTrackerUrl = findings['libraries'][library]['bugTrackerUrl']
                else:
                    bugTrackerUrl = 'https://www.sourceclear.com'


                #Add the results to new JSON format
                gl_results["vulnerabilities"].append({
                    "id": findings['libraries'][library]['versions'][0]['sha1'],
                    "category": "dependency_scanning",
                    "name": issue['title'] + " in " + findings['libraries'][library]['name'],
                    "message": issue['title'] + " in " + findings['libraries'][library]['name'],
                    "description": cve + ". " + issue['overview'],
                    "severity": severity,
                    "solution": updateVersion,
                    "scanner": {
                        "id": "srcclr",
                        "name": "SourceClear"
                    },
                    "location": {
                        "file": fileName,
                        "dependency": {
                            "package": {
                                "name": findings['libraries'][library]['coordinate1'] + ":" + findings['libraries'][library]['coordinate2']
                            },
                            "version": findings['libraries'][library]['versions'][0]['version']
                        }
                    },
                    "identifiers": [
                        {
                            "type": "Veracode Agent Based SCA",
                            "name": findings['libraries'][library]['language'] +  ' - ' + findings['libraries'][library]['name'] + ' - VERSIONS: ' + versionRange + ' - ' + cve,
                            "value": findings['libraries'][library]['language'] +  ' - ' + findings['libraries'][library]['name'] + ' - VERSIONS: ' + versionRange + ' - ' + cve,
                            "url": bugTrackerUrl
                        }
                    ],
                    "links": [
                        {
                            "url": patchUrl
                        },
                        {
                            "url": refUrl
                        }
                    ]
                })
                #Add remediations
                gl_results["remediations"].append({
                    "fixes": [
                        {
                            "id": findings['libraries'][library]['versions'][0]['sha1'],
                        }
                    ],
                    "summary": updateVersion,
                    "diff": "Information not available."
                })

                #Add to the Dependency list
                gl_results["dependency_files"].append({
                    "path": fileName,
                    "package_manager": packageManager,
                    "dependencies": [
                        {
                            "package": {
                                "name": findings['libraries'][library]['name']
                            },
                            "version": findings['libraries'][library]['versions'][0]['version']
                        }
                    ]
                })

                # Output results on the console. 
                print("Issue found: " + issue['title'] + " in " + findings['libraries'][library]['name'])
        else: 
            print("There are no vulnerabilities")  

with open("srcclr-report.json", "w") as f:
    f.write(json.dumps(gl_results, indent=4))

# TODO
# Output unmatched libraries to identify any possible vulnerabilities we may be missing.
