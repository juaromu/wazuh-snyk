## Intro

Wazuh and Snyk (snyk.io) integration to scan Docker image vulnerabilities.

Snyk will help you find and automatically fix vulnerabilities in your code, open source dependencies, containers, and infrastructure as code.

In this integration we'll use Snyk’s CLI to scan for vulnerabilities in the Docker images and all their dependencies.

NOTE: Wazuh can use all the features available in an agent to monitor [Docker servers](https://documentation.wazuh.com/current/docker-monitor/monitoring_docker_server.html) and it can also monitor [container activity.](https://documentation.wazuh.com/current/docker-monitor/monitoring_containers_activity.html) With the Snyk integration we aim at finding vulnerable packages included in the Docker images that might put the containerised applications at risk.


## Snyk CLI

Snyk runs as a single binary, no installation required.

The Linux binary can be found [here](https://static.snyk.io/cli/latest/snyk-linux)

This [article](https://snyk.io/learn/docker-security-scanning/) from Snyk’s documentation explains how to use Snyk’s CLI for Docker security.


## Wazuh Capability:

Wodle Command configured to run periodic security scans in all Docker images used in the host.

[Jq ](https://stedolan.github.io/jq/)is used in the agent (Docker host) to filter and parse the Snyk CLI output. 

Wazuh remote commands execution must be enabled (Docker host).


## Workflow



1. Bash script to be run via wodle command will list all Docker images in the system and will run Snyk’s CLI to spot known vulnerabilities in all the packages used to build the image.
2. The JSON output will be appended to the active responses log file.
3. Detection rules in Wazuh manager will trigger alerts based on the scan results.

Remote commands execution must be enabled in the agent (Docker host), file “local_internal_options.conf”:


```
# Wazuh Command Module - If it should accept remote commands from the manager
wazuh_command.remote_commands=1
```


Edit /var/ossec/etc/shared/**_your_linux_docker_group_**/agent.conf and add the remote command:


```
<wodle name="command">
  <disabled>no</disabled>
  <tag>snyk-scan</tag>
  <command>/usr/bin/bash /var/ossec/wodles/command/snyk_scan.sh</command>
  <interval>24h</interval>
  <ignore_output>yes</ignore_output>
  <run_on_start>yes</run_on_start>
  <timeout>0</timeout>
</wodle>
```


Content of “snyk_scan.sh”:


```
################################
### Script to run Snyk CLI Vuln Scan on Docker Images
### Aurora Networks Managed Services
### https://www.auroranetworks.net
### info@auroranetworks.net
################################
##########
# docker image list --> Obtain the list of Docker Images in the system
# The Snyk Scan is run on each image detected in the system
# Minimum Severity = Medium (change severity threshold if required)
# The scan result is appended to active-responses.log
##########
#!/bin/bash
# Static active response parameters
# Static active response parameters
LOCAL=`dirname $0`
#------------------------- Active Response Log File -------------------------#

LOG_FILE="/var/ossec/logs/active-responses.log"

#------------------------- Main workflow --------------------------#
#------------------------- Function to run scan on Docker Image --------------------------#
snyk_execution(){
  docker_image=$1
  /opt/snyk/snyk-linux container test "$docker_image" --json --severity-threshold=medium | jq '.vulnerabilities' | jq ".[] | {packageName, severity, id, name, version, nearestFixedInVersion, dockerfileInstruction, dockerBaseImage, nvdSeverity, publicationTime, malicious, title, cvssScore, identifiers}" | jq -c '.'
}
#------------------------- Get Docker Images and call scan function --------------------------#
docker_images_list=( $(/bin/docker image ls | tail -n +2 | awk '{ print $1 }') )
#------------------------- Append Scan Outoput to Active Response Log  --------------------------#
for docker_image in "${docker_images_list[@]}"
do
  snyk_output=$(snyk_execution $docker_image)
    if [[ $snyk_output != "" ]]
    then
        # Iterate every detected rule and append it to the LOG_FILE
        while read -r line; do
            echo $line >> ${LOG_FILE}
            sleep 0.1
        done <<< "$snyk_output"
    fi
   >> ${LOG_FILE}
  sleep 0.3
done
```


NOTE: The script above assumes that:



* The Snyk binary has been placed in “/opt/snyk/”
* The minimum severity for the vulnerabilities found is “medium”.
* Jq has been installed in the agent (used to filter and parse Snyk CLI output).

Snyk Scan detection rules:


```
<!--
  -  SNYK Docker Image Scan Rules
-->
<group name="vulnerability-detector,snyk,">
    <rule id="96600" level="10">
        <decoded_as>json</decoded_as>
        <field name="packageName">\.+</field>
        <field name="severity">medium</field>
        <description>Snyk: Alert - Vulnerable Packages - $(packageName)</description>
        <options>no_full_log</options>
    </rule>
    <rule id="96601" level="12">
        <decoded_as>json</decoded_as>
        <field name="packageName">\.+</field>
        <field name="severity">high</field>
        <description>Snyk: Alert - Vulnerable Packages - $(packageName)</description>
        <options>no_full_log</options>
    </rule>
</group>
```


Alert example:


```

{
  "timestamp":"2021-11-11T14:46:45.108+1100",
  "rule":{
     "level":10,
     "description":"Snyk: Alert - Vulnerable Packages - systemd-libs",
     "id":"96600",
     "firedtimes":104,
     "mail":false,
     "groups":[
        "vulnerability-detector",
        "snyk"
     ]
  },
  "agent":{
     "id":"014",
     "name":"jromero-deepin",
     "ip":"192.168.252.128"
  },
  "manager":{
     "name":"tactical"
  },
  "id":"1636602405.473630425",
  "decoder":{
     "name":"json"
  },
  "data":{
     "id":"SNYK-RHEL8-SYSTEMDLIBS-1328746",
     "packageName":"systemd-libs",
     "severity":"medium",
     "name":"systemd-libs",
     "version":"239-45.el8_4.3",
     "nearestFixedInVersion":"null",
     "dockerfileInstruction":"null",
     "dockerBaseImage":"null",
     "nvdSeverity":"critical",
     "publicationTime":"2021-07-26T07:55:08.624573Z",
     "malicious":"false",
     "title":"Information Exposure",
     "cvssScore":"9.800000",
     "identifiers":{
        "ALTERNATIVE":[
          
        ],
        "CVE":[
           "CVE-2018-20839"
        ],
        "CWE":[
           "CWE-200"
        ]
     }
  },
  "location":"/var/ossec/logs/active-responses.log"
}

```
