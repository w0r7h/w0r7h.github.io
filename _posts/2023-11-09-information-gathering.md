---
layout: post
title: Information Gathering
date: 2023-11-09 18:38 +0000
---

## Information Gathering

During this process, our objective is to identify as much information as we can from the following areas:

| Area                   | Description            |
|------------------------|-----------------|
| Domains and Subdomains | Often, we are given a single domain or perhaps a list of domains and subdomains that belong to an organization. Many organizations do not have an accurate asset inventory and may have forgotten both domains and subdomains exposed externally. This is an essential part of the reconnaissance phase. We may come across various subdomains that map back to in-scope IP addresses, increasing the overall attack surface of our engagement (or bug bounty program). Hidden and forgotten subdomains may have old/vulnerable versions of applications or dev versions with additional functionality (a Python debugging console, for example). Bug bounty programs will often set the scope as something such as *.inlanefreight.com, meaning that all subdomains of inlanefreight.com, in this example, are in-scope (i.e., acme.inlanefreight.com, admin.inlanefreight.com, and so forth and so on). We may also discover subdomains of subdomains. For example, let's assume we discover something along the lines of admin.inlanefreight.com. We could then run further subdomain enumeration against this subdomain and perhaps find dev.admin.inlanefreight.com as a very enticing target. There are many ways to find subdomains (both passively and actively) which we will cover later in this module. |
| IP ranges              | Unless we are constrained to a very specific scope, we want to find out as much about our target as possible. Finding additional IP ranges owned by our target may lead to discovering other domains and subdomains and open up our possible attack surface even wider.                                                                                    |
| Infrastructure         | We want to learn as much about our target as possible. We need to know what technology stacks our target is using. Are their applications all ASP.NET? Do they use Django, PHP, Flask, etc.? What type(s) of APIs/web services are in use? Are they using Content Management Systems (CMS) such as WordPress, Joomla, Drupal, or DotNetNuke, which have their own types of vulnerabilities and misconfigurations that we may encounter? We also care about the web servers in use, such as IIS, Nginx, Apache, and the version numbers. If our target is running outdated frameworks or web servers, we want to dig deeper into the associated web applications. We are also interested in the types of back-end databases in use (MSSQL, MySQL, PostgreSQL, SQLite, Oracle, etc.) as this will give us an indication of the types of attacks we may be able to perform.                                                                                                                            |
| Virtual Hosts          | Lastly, we want to enumerate virtual hosts (vhosts), which are similar to subdomains but indicate that an organization is hosting multiple applications on the same web server. We will cover vhost enumeration later in the module as well.      |


We can break the information gathering process into two main categories:

| Category                      | Description         |
|-------------------------------|------------------------------------------|
| Passive information gathering | We do not interact directly with the target at this stage. Instead, we collect publicly available information using search engines, whois, certificate information, etc. The goal is to obtain as much information as possible to use as inputs to the active information gathering phase.                                                                                                                                              |
| Active information gathering  | We directly interact with the target at this stage. Before performing active information gathering, we need to ensure we have the required authorization to test. Otherwise, we will likely be engaging in illegal activities. Some of the techniques used in the active information gathering stage include port scanning, DNS enumeration, directory brute-forcing, virtual host enumeration, and web application crawling/spidering. |


## WHOIS

The WHOIS domain lookups allow us to retrieve information about the domain name of an already registered domain.
The corporation behind domain names, ICANN, requires that accredited registrars enter the holder's contact information, the domain's creation, and expiration dates, and other information in the Whois database immediately after registering a domain.

Web tool for searching domains using WHOIS protocol:

https://whois.domaintools.com/

Linux has a command-line tool that does the same called `whois $DOMAIN`.

Though none of the information on its own is enough for us to mount an attack, it is essential data that we want to note down for later.

## DNS

To add to the information already retrieved by the WHOIS protocol, we can use DNS.
The DNS is the Internet's phone book. DNS converts domain names to IP addresses, allowing browsers to access resources on the Internet.
The advantages of using DNS are the following:
- It allows names to be used instead of numbers to identify hosts.
- It is a lot easier to remember a name than it is to recall a number.
- By merely retargeting a name to the new numeric address, a server can change numeric addresses without having to notify everyone on the Internet.
- A single name might refer to several hosts splitting the workload between different servers.

There is a hierarchy of names in the DNS structure. 
Using the example, www.facebook.com, we have the root which is unnamed and starts before the "com".
Then we have TLDs or Top-Level Domains which is the first name in a domain, in our case is "com". Sometimes they have meaning, for example "pt" is a domain of website belonging probably to a portuguese company.
After that, we have SLDs or Second-Level domains, which in our example is "facebook". 
In our example the "www" is a subdomain of the domain "facebook.com".

Resource Records are the results of DNS queries and have the following structure:

| Resource Record          | A domain name, usually a fully qualified domain name, is the first  part of a Resource Record. If you don't use a fully qualified domain  name, the zone's name where the record is located will be appended to  the end of the name.                                   |
|--------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| TTL                      | In seconds, the Time-To-Live (TTL) defaults to the minimum value specified in the SOA record.                                                                                                                                                                           |
| Record Class             | Internet, Hesiod, or Chaos                                                                                                                                                                                                                                              |
| Start Of Authority (SOA) | It should be first in a zone file because it indicates the start of a zone. Each zone can only have one SOA record, and additionally, it contains the zone's values, such as a serial number and multiple expiration timeouts.                                          |
| Name Servers (NS)        | The distributed database is bound together by NS Records. They are in charge of a zone's authoritative name server and the authority for a child zone to a name server.                                                                                                 |
| IPv4 Addresses (A)       | The A record is only a mapping between a hostname and an IP address. 'Forward' zones are those with A records.                                                                                                                                                          |
| Pointer (PTR)            | The PTR record is a mapping between an IP address and a hostname. 'Reverse' zones are those that have PTR records.                                                                                                                                                      |
| Canonical Name (CNAME)   | An alias hostname is mapped to an A record hostname using the CNAME record.                                                                                                                                                                                             |
| Mail Exchange (MX)       | The MX record identifies a host that will accept emails  for a specific host. A priority value has been assigned to the  specified host. Multiple MX records can exist on the same host, and a  prioritized list is made consisting of the records for a specific host. |



### Nslookup & DIG

Let us assume that a customer requested us to perform an external penetration test. 
Therefore, we first need to familiarize ourselves with their infrastructure and identify which hosts are publicly accessible. 
We can find this out using different types of DNS requests. With Nslookup, we can search for domain name servers on the Internet and ask them for information about hosts and domains, `nslookup $TARGET`.

Unlike nslookup, DIG shows us some more information that can be of importance, `dig facebook.com @1.1.1.1`.
The dig command in this case is querying the nameserver 1.1.1.1 for the domain or A record facebook.com.

Querying: A records for a subdomain:
`nslookup -query=A $TARGET`
`dig a www.facebook.com @1.1.1.1`

Querying: PTR Records for an IP Address
`nslookup -query=PTR 31.13.92.36`
`dig -x 31.13.92.36 @1.1.1.1`

Querying: ANY Existing Records:
`nslookup -query=ANY $TARGET`
`dig any google.com @8.8.8.8`

Note: The more recent RFC8482 specified that ANY DNS requests be abolished. Therefore, we may not receive a response to our ANY request from the DNS server or get a reference to the said RFC8482.

Querying: TXT Records:
`nslookup -query=TXT $TARGET`
`dig txt facebook.com @1.1.1.1`

Querying: MX Records:
`nslookup -query=MX $TARGET`
`dig mx facebook.com @1.1.1.1`


## Passive Subdomain Enumeration

Subdomain enumeration refers to mapping all available subdomains within a domain name. It increases our attack surface and may uncover hidden management backend panels or intranet web applications that network administrators expected to keep hidden using the "security by obscurity" strategy. At this point, we will only perform passive subdomain enumeration using third-party services or publicly available information. Still, we will expand the information we gather in future active subdomain enumeration activities.

### Certificates

One tool that we can use to extract information about subdomains are SSL/TLS certificates.
There are two main resources to extract information from certificates:
- https://censys.io/
- https://crt.sh/


In order to extract the information in order to collect every piece of information we have about the client we can run

```shell
export TARGET="facebook.com"
curl -s "https://crt.sh/?q=${TARGET}&output=json" | jq -r '.[] | "\(.name_value)\n\(.common_name)"' | sort -u > "${TARGET}_crt.sh.txt"
head -n20 facebook.com_crt.sh.txt
```

We can do the same by using openssl directly against the target:

```shell
export TARGET="facebook.com"
export PORT="443"
openssl s_client -ign_eof 2>/dev/null <<<$'HEAD / HTTP/1.0\r\n\r' -connect "${TARGET}:${PORT}" | openssl x509 -noout -text -in - | grep 'DNS' | sed -e 's|DNS:|\n|g' -e 's|^\*.*||g' | tr -d ',' | sort -u
```

To automate all the process of finding subdomains, IP addresses, URLs, emails and names we can use a tool called [TheHarvester](https://github.com/laramies/theHarvester). This tool uses modules as sources to get information from a target domain.




