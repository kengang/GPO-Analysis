GPO User Group Policy Parsing Scripts
These scripts are designed to help users parse GPO User group policy gpsvc.log files and Group Policy Preferences (GPP) client-side extension performance logs on Windows. The scripts will output detailed information on how long policies are applied for each user logon session, including:

Total duration of policy application
Time taken to search and download the group policies
Time spent in each Client-Side Extension (CSE) process
Additionally, the GPPRefer log will provide insights into how much time each policy spends within each Client-Side Extension processing.

Log Files
The following log files are processed by these scripts:

GPPREF_User.log
Gpsvc.log
GroupPolicy-Operational.evtx
