Splunk Integration with Juniper SRX Firewall Configurations for Policy Whitelisting and DNS Correlation
Overview
Welcome to the repository dedicated to integrating Splunk with Juniper SRX firewall configurations. This project automates the synchronization and analysis of firewall policies, syslog data, and DNS configurations using Splunk. By leveraging field extractions, advanced report correlation techniques, and regex patterns, this integration enhances network security and operational efficiency. The primary focus is on maintaining policy whitelisting and correlating firewall configurations with DNS records.

Features
Field Extractions: Configure Splunk to extract relevant data from Juniper SRX firewall configurations and syslog messages.
Report Correlation: Implement advanced techniques to correlate firewall policies with syslog events and DNS configurations.
Regex Patterns: Includes regex patterns for parsing various aspects of Juniper SRX configurations (NAT types, address books, policies).
Key Achievements
Utilized advanced report correlation techniques to validate firewall policies across multiple data sources.
Overcame challenges related to discrepancies between syslog messages and firewall configurations, enhancing data accuracy and operational reliability.
Automated the correlation of firewall configurations with DNS records to prepare asset management reports for Internet access criteria (static NAT, DNAT, SNAT, security policies).
Challenges and Strategy
Challenge
I was tasked with creating a list of Internet access criteria (static NAT, DNAT, SNAT, security policies) and related DNS records based on each owner (our customers).

Strategy
Implemented field extraction methods to extract relevant fields from Juniper SRX firewall configuration files and compare them with real syslog traffic.
Leveraged Splunk as an automation tool to continuously monitor and pull configurations, storing them in an index for regex and field extraction operations.
