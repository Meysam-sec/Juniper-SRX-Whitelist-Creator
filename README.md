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
////////////////////////////////////////////////////////////Regexes\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
Regex Patterns for Splunk Field Extractions
Overview: These regex patterns are configured within Splunk's UI for field extractions from Juniper SRX firewall configurations.
Usage Instructions:
Log in to your Splunk instance.
Navigate to Settings > Fields > Field Extractions.
Create a new field extraction or modify an existing one based on the regex patterns provided below.
Regex Patterns:
Regex #1
NAT Type:
^set[\w_\s]+security\snat\s(?<nat_type>[\w-/]+\s)
Regex #2:
Destination Nat:
^set\s([\w\s-_]+)nat\sdestination\s(?:rule-set\s(?<dst_rule_set_name>[\w-_\d/]+)\srule\s(?<dst_rule_name>[\d-/\w_]+)\s((?:match\sdestination-address\s(?<dst_nat_address>[\d./]+))|(?:match\ssource-address\s(?<dst_nat_src_address>[\d./]+))|(?:match\sapplication\s(?<dst_nat_application>[\d./]+))|(?:then\sdestination-nat\spool\s(?<poolname>[\d\w-./]+))))|(?:pool\s(?<poolname1>[\w-_/]+)\saddress\s(?<dst_pool_ip>[\d./]+))
Regex #3:
Static NAT:
^set\s([\w\s-_]+)nat\sstatic\srule-set\sStaticNAT\srule\s(?<static_nat_rule_name>[\w-\d./]+)\s(?:then\sstatic-nat\sprefix\s(?<static_nat_rule_ip>[\d./]+)|(?:match\sdestination-address\s(?<real_public_ip>[\d.//]+))|(?:match\ssource-address\s(?<source_ip>[\d./]+)))
Regex #4:
Address book and address-set:
^set[\s\w-]+saddress\s(?<addressbookname>[\d\w-./]+)\s(?<realip>[\d.-\w\s/]+)
^['set'|'deactive'][\w-\s]+security address-book[\w-\s]+address-set\s(?<addressset>[\w-\d.]+)\saddress\s(?<addressbook>[\w-\d./]+)
Regex #5:
Regexes for policies:
Destination address: ^['set'|'deactive'][\w-\s]+match\sdestination-address\s(?<dstip>[\w-\d./]+)
Source zone / Destination zone: ^['set'|'deactive'][\w-\s]+from-zone\s(?<fromzone>[\w-\d.]+)
Policy Name: ^['set'|'deactive'][\w-\s]+policy\s(?<policyname>[\w-\d.]+)
Applications: ^['set'|'deactive'][\w-\s]+application\s(?<applications>[\w-\d]+)
