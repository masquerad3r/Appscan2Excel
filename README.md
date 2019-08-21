# AppScan_Parser
## Overview
The AppScan parser tool has been made to facilitate faster reporting during penetration testing exercises. This helps the pentesters focus more on the testing aspect of their projects and reduces the cumbersome and repetitive task of making customized client reports.

This python script simply takes two command line arguments:
* XML report 
* [Scan log file](https://www.ibm.com/support/knowledgecenter/en/SSPH29_9.0.1/com.ibm.help.common.infocenter.aps/r_Log_Scan.html)

## Information Extracted
### From XML Report
* Vulnerability Name
* Vulnerability Description
* Recommendations
* Affected URLs

### From Log File
* Visited URLs
* Skipped URLs
* Vulnerabilities found (the affected URL and the vulnerable parameter)
* Login endpoints
* Logout endpoints

## Running the tool
### Prerequisites
The tool runs on **python 3.7.x** installation.


Required Module: **xlsxwriter**

The same can be installed by using [pip](https://pypi.org/project/pip/):
```
pip install xlsxwriter
```

If both python 2.x and 3.x are installed, then:
```
pip3 install xlsxwriter
```

### Command
Tool expects the command in the following order:
```
python AppScan_parser.py <xml file name> <log file name>
```
If both python 2.x and 3.x are installed:
```
python3 AppScan_parser.py <xml file name> <log file name>
```

## Screenshot
The below screenshot shows a sample output.

![](https://github.com/masquerad3r/AppScan_Parser/blob/master/sample_shot.png)
