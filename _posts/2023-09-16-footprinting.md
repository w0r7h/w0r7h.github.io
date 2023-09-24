---
layout: post
title: Footprinting
categories:
- Information
tags:
- Enumeration
- Footprinting
- Cloud Security

date: 2023-09-16 17:50 +0100
---

## Enumeration Principles

`Our goal is not to get at the systems but to find all the ways to get there.`

| Nº | Principle                                                              |
|----|------------------------------------------------------------------------|
| 1  | There is more than meets the eye. Consider all points of view.         |
| 2  | Distinguish between what we see and what we do not see.                |
| 3  | There are always ways to gain more information. Understand the target. |


## Enumeration Methodology

|          **Layer**         |                                               **Description**                                              |                                       **Information Categories**                                       |
|:----------------------:|:------------------------------------------------------------------------------------------------------:|:--------------------------------------------------------------------------------------------------:|
| 1. Internet Presence   | Identification of internet presence and externally accessible infrastructure.                          | Domains, Subdomains, vHosts, ASN, Netblocks, IP Addresses, Cloud Instances, Security Measures      |
| 2. Gateway             | Identify the possible security measures to protect the company's external and internal infrastructure. | Firewalls, DMZ, IPS/IDS, EDR, Proxies, NAC, Network Segmentation, VPN, Cloudflare                  |
| 3. Accessible Services | Identify accessible interfaces and services that are hosted externally or internally.                  | Service Type, Functionality, Configuration, Port, Version, Interface                               |
| 4. Processes           | Identify the internal processes, sources, and destinations associated with the services.               | PID, Processed Data, Tasks, Source, Destination                                                    |
| 5. Privileges          | Identification of the internal permissions and privileges to the accessible services.                  | Groups, Users, Permissions, Restrictions, Environment                                              |
| 6. OS Setup            | Identification of the internal components and systems setup.                                           | OS Type, Patch Level, Network config, OS Environment, Configuration files, sensitive private files |

- **Layer No.1**: Internet Presence: The goal of this layer is to identify all possible target systems and interfaces that can be tested. 
- **Layer No.2**: Gateway: The goal is to understand what we are dealing with and what we have to watch out for.
- **Layer No.3**: Accessible Services: This layer aims to understand the reason and functionality of the target system and gain the necessary knowledge to communicate with it and exploit it for our purposes effectively.
- **Layer No.4**: Processes: The goal here is to understand these factors and identify the dependencies between them.
- **Layer No.5**: Privileges: It is crucial to identify these and understand what is and is not possible with these privileges.
- **Layer No.6**: OS Setup: The goal here is to see how the administrators manage the systems and what sensitive internal information we can glean from them.

## Domain Information

Domain Information is the process of scrutinize the entire presence of a company in the Internet.
Here we can use OSINT to passively gather information about the company in the web. The first thing we should do is look at the company's website and analyse what kinds of services the company provides. 

The first point of presence that we can look up is the SSL certificate used by the company in their website. Knowing the domain we can use [tools](https://crt.sh/) to get the subdomains and further analyse them. 

We can also output the results in JSON format: `$ curl -s https://crt.sh/\?q\=inlanefreight.com\&output\=json | jq .`
We can also have them filtered by the unique subdomains: `$ curl -s https://crt.sh/\?q\=inlanefreight.com\&output\=json | jq . | grep name | cut -d":" -f2 | grep -v "CN=" | cut -d'"' -f2 | awk '{gsub(/\\n/,"\n");}1;' | sort -u`
We can identify the hosts accessible from the web: `for i in $(cat subdomainlist);do host $i | grep "has address" | grep inlanefreight.com | cut -d" " -f1,4;done`

Once we have a list of public IP's we can run them through shodan. [Shodan](https://www.shodan.io/) can be used to find devices and systems permanently connected to the Internet like Internet of Things (IoT). It searches the Internet for open TCP/IP ports and filters the systems according to specific terms and criteria. 

To look at the IP's services available in shodan: `for i in $(cat ip-addresses.txt);do shodan host $i;done`

To obtain additional information about domains we can use a tool called dig. Dig is a DNS lookup tool that interrogates DNS servers about a certain domain.
It performs DNS lookup and displays the answers. The answers can be from the following types:

- **A records**: We recognize the IP addresses that point to a specific (sub)domain through the A record. Here we only see one that we already know.

- **MX records**: The mail server records show us which mail server is responsible for managing the emails for the company. Since this is handled by google in our case, we should note this and skip it for now.

- **NS records**: These kinds of records show which name servers are used to resolve the FQDN to IP addresses. Most hosting providers use their own name servers, making it easier to identify the hosting provider.

- **TXT records**: this type of record often contains verification keys for different third-party providers and other security aspects of DNS, such as SPF, DMARC, and DKIM, which are responsible for verifying and confirming the origin of the emails sent. Here we can already see some valuable information if we look closer at the results.

## Cloud Resources

Companies tipically use centrallized services such as Amazon (AWS), Google (GCP), and Microsoft (Azure) to implement their infrastructure. The fact that this services are owned by top IT companies do not mean that companies are saved from vulnerabilities in their services. The configurations made by the administrators may nevertheless make the company's cloud resources vulnerable. This often starts with the S3 buckets (AWS), blobs (Azure), cloud storage (GCP), which can be accessed without authentication if configured incorrectly.  

One of the easiest and most used is Google search combined with Google Dorks. For example, we can use the Google Dorks `inurl:` and `intext:` to narrow our search to specific terms. For example: intext:inlanefreight inurl:amazonaws.com .

To get more information about the company infrastructure we can use the website [domain.glass](https://domain.glass/). This website can tell us more information about who register the domain and the DNS records. 

Another usefull tool called [GrayHatWarfare](https://buckets.grayhatwarfare.com/) can help us find AWS, Azure, and GCP cloud storage, and even sort and filter by file format. Companies use abbreviations of the company name to use in the IT infrastucutre. The abbreviations are a good abbreviations to discovering new cloud storage from the company. 





