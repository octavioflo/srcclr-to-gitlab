import json

# Builds a shell of the Gitlab report
# TODO: add link to the report schema
gl_results = {
    "version": "14.0.4",
    "vulnerabilities": [],
    "remediations": [],
    "dependency_files": []
}

# Check that 'report' is not None or empty
def is_none_or_null_check(report, string) -> str:
    if report is not None and report != "":
        return report
    else:
        return string

# Takes the cvss score from the veracode report, then converts that 
# More generic severity level that Gitlab consumes
def severity_level(cvss_score) -> str:
    if float(cvss_score) == 0.0:
        severity = "Info"
    elif float(cvss_score) >= 0.1 and  float(cvss_score) < 4.0:
        severity = "Low"
    elif float(cvss_score) >= 4.0 and  float(cvss_score) < 7.0:
        severity = "Medium"
    elif float(cvss_score) >= 7.0 and  float(cvss_score) < 9.0:
        severity = "High"
    elif float(cvss_score) >= 9.0:
        severity = "Critical"
    
    return severity


with open("sca-results.json", "r") as r:
    results_json = json.load(r)
    results = results_json['records']

    for findings in results:
        if findings['graphs']:
            package_manager = findings['graphs'][0]['directs'][0]['coords']['coordinateType'] if findings['graphs'][0]['directs'][0]['coords']['coordinateType'] else "Package Manager not found."
            file_name = findings['graphs'][0]['directs'][0]['filename'] if findings['graphs'][0]['directs'][0]['filename'] else "File not found."
        else: 
            print('No graph results')
            package_manager = ""
            file_name = ""
        
        if findings['libraries']:
            '''
            Loops through the libraries in the report and appends them to Gitlabs
            report with the appropriate information. This piece is what populates the 
            Dependency list feature in gitlab.
            
            '''
            for single_library in findings['libraries']:
                coordinate_one = single_library['coordinate1']
                coordinate_two = single_library['coordinate2']
                library_current_version = single_library['versions'][0]['version']
                library_iid = single_library
                if len(single_library['versions'][0]['licenses']) != 0:
                    direct_or_transitive_status = single_library['versions'][0]['licenses'][0]['fromParentPom']
                else:
                    direct_or_transitive_status = False #defaulting to false, false being transitive.
                
                gl_results["dependency_files"].append({
                            "path": file_name,
                            "package_manager": package_manager,
                            "dependencies": [
                                {
                                    "package": {
                                        "name": coordinate_one + ":" + coordinate_two
                                    },
                                    "version": library_current_version,
                                    "iid": library_iid,
                                    "direct": direct_or_transitive_status
                                }
                            ]
                        })


        else:
            print('No libraries found in the report.')

        if findings['vulnerabilities']:
            '''
            Loops through the vulnerabilities in the report and appends them to Gitlabs
            report with the appropriate information. This also generates a report 
            
            '''
            print("===== SCA SCAN HAS FOUND VULNERABILITIES =====")
            for issue in findings['vulnerabilities']:
                '''
                    In some cases there's no library information in the vulnerability. 
                    This handles that case and defines generic variables.
                '''
                if len(issue['libraries']) != 0:
                    '''
                        Mapping vulnerability to the library
                        TODO: ensure the correct vulnerability is being reported. 
                        Seems to be an issue where some are incorrect.
                    '''
                    ref = issue['libraries'][0]['_links']['ref']
                    new_ref = ref.split('/')
                    library_index = int(new_ref[4]) - 1 #remove this -1
                    print(library_index)
                    
                    # Assign variables that require a library information in the vulnerability.
                    library_sha = findings['libraries'][library_index]['versions'][0]['sha1']
                    issue_message = issue['title'] + " in " + findings['libraries'][library_index]['name']
                    library_current_version = findings['libraries'][library_index]['versions'][0]['version']
                    coordinate_one = findings['libraries'][library_index]['coordinate1']
                    coordinate_two = findings['libraries'][library_index]['coordinate2']                    
                    patch_url = is_none_or_null_check(issue['libraries'][0]['details'][0]['patch'], 'https://www.sourceclear.com')
                    reference_url = is_none_or_null_check(issue['_links']['html'], 'https://www.sourceclear.com')
                    bug_tracker_url = is_none_or_null_check(findings['libraries'][library_index]['bugTrackerUrl'], 'https://www.sourceclear.com')

                    if len(findings['libraries'][library_index]['versions'][0]['licenses']) != 0:
                        direct_or_transitive_status = findings['libraries'][library_index]['versions'][0]['licenses'][0]['fromParentPom']
                    else:
                        direct_or_transitive_status = False #defaulting to false, false being transitive.

                    # Upgrade version text for the report based on inputs.
                    if issue['libraries'][0]['details'][0]['updateToVersion']:
                        update_version = "Upgrade to version " + issue['libraries'][0]['details'][0]['updateToVersion'] + "."
                    elif issue['libraries'][0]['details'][0]['fixText'] != "":
                        update_version = issue['libraries'][0]['details'][0]['fixText']
                    else:
                        update_version = "No update version provided."
                else:
                    # Providing defaults if no Library information is available. Typically not the case.
                    library_sha = library_index = ""
                    issue_message = issue['title']
                    library_current_version = "No library information found in the report for this issue."
                    coordinate_one = coordinate_two = "null"
                    patch_url = reference_url = bug_tracker_url = 'https://www.sourceclear.com'

                description = issue['overview']
                cve = "CVE-" + issue['cve'] if issue['cve'] else "CVE-0000-0000"
                
                # Add the vulnerabilities to the gitlab report.
                gl_results["vulnerabilities"].append({
                    "id": library_sha,
                    "category": "dependency_scanning",
                    "name": issue_message,
                    "message": issue_message,
                    "description": description,
                    "cve": library_sha,
                    "severity": severity_level(issue['cvssScore']),
                    "solution": update_version,
                    "scanner": {
                        "id": "srcclr",
                        "name": "SourceClear"
                    },
                    "location": {
                        "file": file_name,
                        "dependency": {
                            "package": {
                                "name": coordinate_one + ":" + coordinate_two
                            },
                            "version": library_current_version,
                            "iid": library_index,
                            "direct": direct_or_transitive_status
                        }
                    },
                    "identifiers": [
                        {
                            "type": "cve",
                            "name": cve,
                            "value": cve,
                            "url": bug_tracker_url
                        }
                    ],
                    "links": [
                        {
                            "url": patch_url
                        },
                        {
                            "url": reference_url
                        }
                    ]
                })

                # Add remediations to the report
                gl_results["remediations"].append({
                    "fixes": [
                        {
                            "cve": library_sha,
                        }
                    ],
                    "summary": update_version,
                    "diff": "Information not available."
                })

                # Output results on the console.
                if  library_index != "null":
                    print("ISSUE FOUND: " + issue_message)
                else:
                    print("ISSUE FOUND: " + issue['title'])
        else: 
            print("There are no vulnerabilities")


    '''
        In some cases there are unmatched libraries in the report. 
        This essentially outputs any libraries where the scanner couldn't resolve the version of the library.
    '''
    if 'unmatchedLibraries' in findings and len(findings['unmatchedLibraries']) != 0:
        print("")
        print("")
        print("===== SCA SCAN HAS FOUND SOME UNMATCHED LIBRARIES =====")
        print("ACTION REQUIRED: Please add a version to the following libraries to get results.")
        for unmatched_library in findings['unmatchedLibraries']:
            coordinate_one = unmatched_library['coordinate1'] if unmatched_library['coordinate1'] else "null"
            coordinate_two = unmatched_library['coordinate2'] if unmatched_library['coordinate2'] else "null"
            print("- " + coordinate_one + ":" + coordinate_two)
        print("")


with open("gl-dependancy-scan-report.json", "w") as f:
    f.write(json.dumps(gl_results, indent=4))
