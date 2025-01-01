# SOAR-Automation-Project
## Introduction

With advancements in technology security professionals now have the ability to detect and automate responses to certain events/alerts via a SOAR (Security Orchestration Automation and Response). This Project demonstrates setting up this process utilizing open-source technologies; Wazuh, TheHive, and Shuffle (the SOAR platform)


<!---![alt text](https://github.com/TrayJames/SOAR-Automation-Project/blob/main/assets/1SOC_Automation.png?raw=true) --->

![EEG Band Discovery](/assets/1SOC_Automation.png)
*Diagram of Orchestration Dataflow*

## Starting Point/Setup
As starting point for this project I:
1. Created a new Windows 10 VM using Virtual Box and installed Sysmon.
2. Created two Ubuntu 22.04 servers in the cloud via Digital Ocean. One for Wazuh and the other for TheHive
3. Created Firewall Inbound rules to only allow TCP UDP and ICMP(ping) packets from my home machine IP
4. Configured both Wazuh and TheHive and got both services started.
5. Connected the Windows 10 VM to Wazuh as an agent.
6. Installed mimikatz on the Windows 10 VM as an example of malicious software being installed.

The following screenshots detail the steps that occurred after this setup:

## Event Trigger and Rule Setup

*Sysmon Logged mimikatz installation*
![EEG Band Discovery](/assets/SysmonDetectedMimikatzInstall.png)

*Wazuh received log from Sysmon on mimikatz installation*
![EEG Band Discovery](/assets/MitreWazuhDetection.png)

*Created new custom rule for sysmon events having an ID of 1. Rule looks for mimikat.exe originalFileName with a MITRE id of T1003 indicating Credential dumping* 
![EEG Band Discovery](/assets/CreatingWazuhCustomRules.png)
