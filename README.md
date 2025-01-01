# SOAR-Automation-Project
## Introduction

With advancements in technology security professionals now have the ability to detect and automate responses to certain events/alerts via a SOAR (Security Orchestration Automation and Response). This Project demonstrates setting up this process utilizing open-source technologies; Wazuh, TheHive, and Shuffle (the SOAR platform)

## Starting Point/Setup
To Setup this project I:
1. Created a new Windows 10 VM using Virtual Box and installed Sysmon on it.
2. Created two Ubuntu 22.04 servers in the cloud via Digital Ocean. One for Wazuh and other for TheHive
3. Created Firewall Inbound rules to only allow TCP UDP and ICMP(ping) packets from my home machine IP
4. Configured both Wazuh and TheHive and got both services started. 

The following screenshots detail steps that occurred after this setup:

## Orchestration Implementation



