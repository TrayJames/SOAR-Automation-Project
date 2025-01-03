# SOAR-Automation-Project
## Introduction

With advancements in technology security professionals now have the ability to detect and automate responses to certain events/alerts via a SOAR (Security Orchestration Automation and Response). This Project demonstrates setting up this process utilizing free and open-source technologies; Wazuh, TheHive, and Shuffle (the SOAR platform)


<!---![alt text](https://github.com/TrayJames/SOAR-Automation-Project/blob/main/assets/1SOC_Automation.png?raw=true) --->

*Diagram of SOC Automation Dataflow*
![EEG Band Discovery](/assets/1SOC_Automation.png)

## Starting Point/Setup
As a starting point for this project I:
1. Created a new Windows 10 VM using Virtual Box and installed Sysmon.
2. Created two Ubuntu 22.04 servers in the cloud via Digital Ocean. One for Wazuh and the other for TheHive
3. Created Firewall Inbound rules to only allow TCP UDP and ICMP(ping) packets from my home machine IP
4. Configured both Wazuh and TheHive and got both services started.
5. Connected the Windows 10 VM to Wazuh as an agent.
6. Installed mimikatz on the Windows 10 VM as an example of malicious software being installed.

The following screenshots detail the steps that occurred after this setup:

## Event Trigger and Rule Setup

*Sysmon Logged mimikatz execution*
![EEG Band Discovery](/assets/SysmonDetectedMimikatzInstall.png)

*Wazuh received log from Sysmon about mimikatz execution*
![EEG Band Discovery](/assets/MitreWazuhDetection.png)

*Created new custom rule for sysmon events having an ID of 1. Rule looks for mimikatz.exe originalFileName with a MITRE id of T1003 indicating Credential dumping* 
![EEG Band Discovery](/assets/CreatingWazuhCustomRules.png)

*Renamed mimikatz.exe to this_a_safe_program.exe and ran it. Despite this Wazuh still captured and flaged the event in accordance to the newly created rule. This is because it is looking at the original filename instead of the image name* 
![EEG Band Discovery](/assets/NewRuleMimikatzCapture.png)

## Orchestration and Notification Setup
*Edited Wazuh Configuration to forward json when the rule for the mimikatz event I created is triggered this will be captured by the webhook in shuffle* 
![EEG Band Discovery](/assets/WazuhAutomationConfiguration.png)

*Start of Shuffle workflow. Created a webhook that will capture Wazuhs response in shuffle*
![EEG Band Discovery](/assets/ShuffleWebhook.png)

*Webhook successfully captured Wazuhs response in Shuffle. Within Wazhuhs response is a hash of mimikatz. The following is regex used to parse this SHA256 hash from Wazuhs response*
![EEG Band Discovery](/assets/ParsedHashWithRegex.png)

*After SHA256 hash is extracted a virus total app is connected to the workflow. Authenticating using a virus total API key the workflow now forwards the parsed out hash from the Wazuh response to Virustotal to be evaluated*
![EEG Band Discovery](/assets/AddVirusTotalToWorkflow.png)

*The Response virus total returned from the hashed value we sent to it via its API. As you can see the hash evaluates to mimikatz*
![EEG Band Discovery](/assets/ShuffleVirusTotalOutput.png)

*Setting up the TheHive Incident Response workflow. A request is created in Shuffle that will be sent to the Hive to create an alert using a Hive API Key. The below shows this request was successfully received by TheHive and a new alert is created*
  ![EEG Band Discovery](/assets/SetupHiveWorkflowAlertCreatedSuccessfully.png)

*The generated alert as it is presented in the TheHive alert Summary*
  ![EEG Band Discovery](/assets/TheHiveAlertSummary.png)

*Adding Email functionality in the workflow. After we create an alert in TheHive we will send an email to the SOC analyst about the alert *
  ![EEG Band Discovery](/assets/WorkFlowEmailSentSetup.png)

*Email about the alert is successfully sent and received*
  ![EEG Band Discovery](/assets/EmailSuccessfullySentAndReceived.png)

## Active Response Setup

Bellow details setting up Wazuh Active response in which a user will be prompted with options as to what to do when an SSH brute force is detected. This time the above workflow is using a Ubuntu VM instead of a Windows VM. To be clear the automation workflow will follow a similar pattern as above: 

1. An SSH brute force will occur on our Ubuntu VM.
2. Wazuh will send an alert to Shuffle.
3. Shuffle will parse out the IP address within the alert response
4. The IP address will be submitted to VirusTotal be evaluated and see if it is malicious
5. The output from VirusTotal will generate an alert to theHive and send an email to the SOC analyst.
6. The SOC analyst will receive a report about the event and will be prompted with response options.
7. Based on what the SOC analyst's response is an action will be performed by Wazuh 

The starting point for the Active Response Setup will start by configuring action rules in Wazuh:

*Setting up action-response in Wazuh; The action-response 'firewall-drop' will block the IP we specify for a particular agent or list of agents *
  ![EEG Band Discovery](/assets/WazuhActiveResponseSetup.png)

*An attempt to brute force SSH was discovered by Wazuh*
  ![EEG Band Discovery](/assets/SSHBruteForce.png)


*Alert is sent to Shuffle by Wazuh and is received successfully*
  ![EEG Band Discovery](/assets/ShuffleCaptureBruteForce.png)

  

*Add a new app to the workflow to Authenticate to the Wazuh API. This API is what will be used when we want to change add an active response in Wazuh*
  ![EEG Band Discovery](/assets/AuthenticateWazuhAPI.png)


*IP from the alert Wazuh sent is passed to virus total via its API. Bellow is Virustotals response*
  ![EEG Band Discovery](/assets/VirusTotalIPAnalysis.png)



