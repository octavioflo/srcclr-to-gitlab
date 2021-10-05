# SourceClear SCA Agent Results to Gitlab Dashboard

This repo contains a python script that converts Veracode's SourceClear Agent results into a format that's consumable by Gitlab. Example shown below on how one could use the python script in an after_script.

Example .gitlab-ci.yml 
---
```
stages:
    - scan

sca-scan:
    image: maven:3.6.0-jdk-8
    stage: scan
    script:
        - curl -sSL https://download.sourceclear.com/ci.sh | bash -s scan . --update-advisor --json sca-results.json
    after_script:
        - python srcclr-to-gitlab.py
    artifacts:
        reports:
            dependency_scanning: srcclr-report.json
        paths:
            - sca-results.json
            - srcclr-report.json
        when: always
    allow_failure: false
```
