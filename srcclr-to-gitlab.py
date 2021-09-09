import json

gl_results = {
    "version": "2.0",
    "vulnerabilities": []
}

with open("sca-results.json", "r") as r:
    results_json = json.load(r)
    results = results_json['records']

    for findings in results:
        if 'vulnerabilities' in findings:
            for issue in findings['vulnerabilities']:
                
                #Add CVE to the actual number from the report
                if issue['cve'] != None:
                    cve = "CVE-" + issue['cve']
                else:
                    cve = "No CVE found"
                
                #Upgrade version text for the report based on inputs.
                if issue['libraries'][0]['details'][0]['updateToVersion'] != None:
                    updateVersion = "Upgrade to version " + issue['libraries'][0]['details'][0]['updateToVersion'] + "."
                else:
                    updateVersion = "Unknown"
                
                #Translate the CVSS score to Gitlabs severity.
                if float(issue['cvssScore']) == 0.0:
                    severity = "Informational"
                elif float(issue['cvssScore']) >= 0.1 and  float(issue['cvssScore']) < 4.0:
                    severity = "Low"
                elif float(issue['cvssScore']) >= 4.0 and  float(issue['cvssScore']) < 7.0:
                    severity = "Medium"
                elif float(issue['cvssScore']) >= 7.0 and  float(issue['cvssScore']) < 9.0:
                    severity = "High"
                elif float(issue['cvssScore']) >= 9.0:
                    severity = "Critical"

                #Map the vulnerability to the library
                ref = issue['libraries'][0]['_links']['ref']
                new_ref = ref.split('/')
                library = int(new_ref[4])
                versions = new_ref[6]

                #Add the results to new JSON format
                gl_results["vulnerabilities"].append({
                    "id": findings['libraries'][library]['versions'][0]['sha1'],
                    "category": "dependency_scanning",
                    "name": issue['title'] + " in " + findings['libraries'][library]['name'],
                    "message": issue['title'] + " in " + findings['libraries'][library]['name'],
                    "description": cve + ". " + issue['overview'],
                    "severity": severity,
                    "solution": "Upgrade to version " + issue['libraries'][0]['details'][0]['updateToVersion'] + ".",
                    "scanner": {
                        "id": "srcclr",
                        "name": "SourceClear"
                    },
                    "location": {
                        "file": "",
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
                            "name": findings['libraries'][library]['language'] +  ' - ' + findings['libraries'][library]['name'] + ' - VERSIONS: ' + issue['libraries'][0]['details'][0]['versionRange'] + ' - ' + cve,
                            "value": findings['libraries'][library]['language'] +  ' - ' + findings['libraries'][library]['name'] + ' - VERSIONS: ' + issue['libraries'][0]['details'][0]['versionRange'] + ' - ' + cve,
                            "url": findings['libraries'][library]['bugTrackerUrl']
                        }
                    ],
                    "links": [
                        {
                            "url": issue['libraries'][0]['details'][0]['patch']
                        },
                        {
                            "url": issue['_links']['html']
                        }
                    ],
                    "remediations": [
                        {
                            "fixes": [
                                {
                                    "id": findings['libraries'][library]['versions'][0]['sha1'],
                                }
                            ],
                            "summary": "Upgrade to version " + issue['libraries'][0]['details'][0]['updateToVersion'] + ".",
                            "diff": ""
                        }
                    ]
                }) 
        else: 
            print("There are no vulnerabilities")   

with open("srcclr-report.json", "w") as f:
    f.write(json.dumps(gl_results, indent=4))

# TODO
# Output results on the console. 
# Output unmatched libraries to identify any possible vulnerabilities we may be missing.
