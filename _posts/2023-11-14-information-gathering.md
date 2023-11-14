---
layout: post
title: Information Gathering
categories:
- Information
- Hackthebox
tags:
- whois
- dns
- nslookup
- dig
- certificates
- theharvester
- netcraft
- wayback machine
- whatweb
- wappalyzer
- wafw00f
- aquatone
- gobuster
- vhosts
- ffuf
- crawling
- ZAP
- subdomain
- domain
date: 2023-11-14 16:15 +0000
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

### TheHarvester

To automate all the process of finding subdomains, IP addresses, URLs, emails and names we can use a tool called [TheHarvester](https://github.com/laramies/theHarvester). This tool uses modules as sources to get information from a target domain, the most used modules are:

| Baidu        | Baidu search engine.                                                             |
|--------------|----------------------------------------------------------------------------------|
| Bufferoverun | Uses data from Rapid7's Project Sonar - www.rapid7.com/research/project-sonar/   |
| Crtsh        | Comodo Certificate search.                                                       |
| Hackertarget | Online vulnerability scanners and network intelligence to help organizations.    |
| Otx          | AlienVault Open Threat Exchange - https://otx.alienvault.com                     |
| Rapiddns     | DNS query tool, which makes querying subdomains or sites using the same IP easy. |
| Sublist3r    | Fast subdomains enumeration tool for penetration testers                         |
| Threatcrowd  | Open source threat intelligence.                                                 |
| Threatminer  | Data mining for threat intelligence.                                             |
| Trello       | Search Trello boards (Uses Google search)                                        |
| Urlscan      | A sandbox for the web that is a URL and website scanner.                         |
| Vhost        | Bing virtual hosts search.                                                       |
| Virustotal   | Domain search.                                                                   |
| Zoomeye      | A Chinese version of Shodan.                                                     |

We add them in a list:

```
$ cat sources.txt

baidu
bufferoverun
crtsh
hackertarget
otx
projecdiscovery
rapiddns
sublist3r
threatcrowd
trello
urlscan
vhost
virustotal
zoomeye
```

An then run harvester against the list: `cat sources.txt | while read source; do theHarvester -d "${TARGET}" -b $source -f "${source}_${TARGET}";done`
We can extract all the subdomains: `cat *.json | jq -r '.hosts[]' 2>/dev/null | cut -d':' -f 1 | sort -u > "${TARGET}_theHarvester.txt"`
And merge all the information: 

```shell
cat ${TARGET}_*.txt | sort -u > ${TARGET}_subdomains_passive.txt
cat ${TARGET}_subdomains_passive.txt | wc -l
```

## Passive Infrastructure Identification

### Netcraft

To obtain information about the server without interacting with them we can use [netcraft](https://www.netcraft.com/).
We can the service like: https://sitereport.netcraft.com/?url=https%3A%2F%2Ffacebook.com to obtain information about the domain facebook.com.
Some interesting details we can observe from the report are:

| Background      | General information about the domain, including the date it was first seen by Netcraft crawlers. |
|-----------------|--------------------------------------------------------------------------------------------------|
| Network         | Information about the netblock owner, hosting company, nameservers, etc.                         |
| Hosting history | Latest IPs used, webserver, and target OS.                                                       |

**We need to pay special attention to the latest IPs used. Sometimes we can spot the actual IP address from the webserver before it was placed behind a load balancer, web application firewall, or IDS, allowing us to connect directly to it if the configuration allows it. This kind of technology could interfere with or alter our future testing activities.**

### Wayback Machine

We can access several versions of these websites using the Wayback Machine to find old versions that may have interesting comments in the source code or files that should not be there. This tool can be used to find older versions of a website at a point in time. Let's take a website running WordPress, for example. We may not find anything interesting while assessing it using manual methods and automated tools, so we search for it using Wayback Machine and find a version that utilizes a specific (now vulnerable) plugin. Heading back to the current version of the site, we find that the plugin was not removed properly and can still be accessed via the wp-content directory. We can then utilize it to gain remote code execution on the host and a nice bounty.

We can also use the tool [waybackurls](https://github.com/tomnomnom/waybackurls) to inspect URLs saved by Wayback Machine and look for specific keywords. We can use the tool as follows: `waybackurls -dates https://facebook.com > waybackurls.txt`.

## Active Infrastructure Identification

When dealing with web applications, there are always web servers serving the application. Some of the most popular are Apache, Nginx, and Microsoft IIS, among others.
In some cases we can discover the target OS running the application by the version of the web server. In windows, the Microsoft IIS version is directly mapped to a windows server version, This is because, they are installed by default.  Some default installations are:

1. IIS 6.0: Windows Server 2003
2. IIS 7.0-8.5: Windows Server 2008 / Windows Server 2008R2
3. IIS 10.0 (v1607-v1709): Windows Server 2016
4. IIS 10.0 (v1809-): Windows Server 2019  

When dealing with linux, we can't infer what is the OS version by the apache or nginx version that it is running.
The first thing we can do to identify the web server version is to look at the response headers.

There are also other characteristics to take into account while fingerprinting web servers in the response headers. These are:
- X-Powered-By header: This header can tell us what the web app is using. We can see values like PHP, ASP.NET, JSP, etc.
- Cookies: Cookies are another attractive value to look at as each technology by default has its cookies. Some of the default cookie values are:
  - .NET: ASPSESSIONID<RANDOM>=<COOKIE_VALUE>
  - PHP: PHPSESSID=<COOKIE_VALUE>
  - JAVA: JSESSION=<COOKIE_VALUE>

### Whatweb

[whatweb](https://www.morningstarsecurity.com/research/whatweb) recognizes web technologies, including content management systems (CMS), blogging platforms, statistic/analytics packages, JavaScript libraries, web servers, and embedded devices.

`$ whatweb -a3 https://www.facebook.com -v`

### Wappalyzer

We also would want to install Wappalyzer as a browser extension. It has similar functionality to Whatweb, but the results are displayed while navigating the target URL.

### Wafw00f

[Wafw00f](https://github.com/EnableSecurity/wafw00f) is a web application firewall (WAF) fingerprinting tool that sends requests and analyses responses to determine if a security solution is in place.

`wafw00f -v https://www.tesla.com`

### Aquatone

[Aquatone](https://github.com/michenriksen/aquatone) is a tool for automatic and visual inspection of websites across many hosts and is convenient for quickly gaining an overview of HTTP-based attack surfaces by scanning a list of configurable ports, visiting the website with a headless Chrome browser, and taking a screenshot.

`cat facebook_aquatone.txt | aquatone -out ./aquatone -screenshot-timeout 1000` 

## Active Subdomain Enumeration

When dealing with a client that has a DNS service with nameservers is always good to look for zone transfers. Zone transfers are a way of copying new entries from the primary nameserver(Master) to the other nameservers(Slaves) in the infrastructure. Typically the master nameserver has a configuration that allows only the slaves to get the new records however if it is misconfigured it may leak the records including mail servers, subdomains and txt records. To learn more about misconfigured zone transfers see the [link](https://digi.ninja/projects/zonetransferme.php).

We can use two tools: [hacker target](https://hackertarget.com/zone-transfer/) and dig(which is a tool from linux).

We can identify the nameservers that hold a domain: `nslookup -type=NS <domain>`
Perform the Zone transfer using `-type=any` and `-query=AXFR` parameters: `nslookup -type=any -query=AXFR <domain> <nameserver>`

### Gobuster

If we find a pattern in a subdomain we can try to find more subdomains with gobuster by creating a list of those subdomains called `patterns.txt`:

```patterns.txt
lert-api-shv-{GOBUSTER}-sin6
atlas-pp-shv-{GOBUSTER}-sin6
```

The next step will be to launch gobuster using the dns module, specifying the following options:

1. dns: Launch the DNS module
2. -q: Don't print the banner and other noise.
3. -r: Use custom DNS server
4. -d: A target domain name
5. -p: Path to the patterns file
6. -w: Path to the wordlist
7. -o: Output file

```shell
$ export TARGET="facebook.com"
$ export NS="d.ns.facebook.com"
$ export WORDLIST="numbers.txt"
$ gobuster dns -q -r "${NS}" -d "${TARGET}" -w "${WORDLIST}" -p ./patterns.txt -o "gobuster_${TARGET}.txt"
```


## Vhosts

A virtual host (vHost) is a feature that allows several websites to be hosted on a single server.
There are two ways to configure virtual hosts:

1. IP-based virtual hosting
2. Name-based virtual hosting

### IP-based Virtual Hosting

For this type, a host can have multiple network interfaces. Multiple IP addresses, or interface aliases, can be configured on each network interface of a host. The servers or virtual servers running on the host can bind to one or more IP addresses. This means that different servers can be addressed under different IP addresses on this host. From the client's point of view, the servers are independent of each other.

### Name-based Virtual Hosting

The distinction for which domain the service was requested is made at the application level. For example, several domain names, such as admin.inlanefreight.htb and backup.inlanefreight.htb, can refer to the same IP. Internally on the server, these are separated and distinguished using different folders. Using this example, on a Linux server, the vHost admin.inlanefreight.htb could point to the folder /var/www/admin. For backup.inlanefreight.htb the folder name would then be adapted and could look something like /var/www/backup.

To access a different vhost using the same IP we can change the header `Host`.
Like: `curl -s http://192.168.10.10 -H "Host: randomtarget.com"`
To find more vhost we just switch the Host header for another value like `dev.randomtarget.com` or `admin.randomtarget.com`, in this case.


### Automating Virtual Hosts Discovery

We can automate this process using primarly two tools, gobuster and ffuf. 
With **gobuster** we can use the mode `vhost`: 

```shell
gobuster vhost -u http://codify.htb -w ~/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
```
The wordlist `subdomains-top1million-5000.txt` is nice list of vhosts from the SecList that we can use to find additional vhosts.

With **ffuf** we can fuzz the Host header with the same wordlist we used before: 

```shell
ffuf -w ~/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -u http://codify.htb -H "HOST: FUZZ.codify.htb"
```

Here we can look for the size of the vhosts and find a pattern then we use the flag `-fs <size>`.

## Crawling

Crawling a website is the systematic or automatic process of exploring a website to list all of the resources encountered along the way. It shows us the structure of the website we are auditing and an overview of the attack surface we will be testing in the future. We use the crawling process to find as many pages and subdirectories belonging to a website as possible.

### ZAP

Zed Attack Proxy or ZAP allow us to perform manual and automated security testing on web applications. 

#### Spider

After openning thw website with a browser initialized with ZAP we can use the spider functionality to look for all the resources used by the website.

### Fuzzer

Fuzzer is another type of attack that we can use to try to find more resources using a list of payloads

For more information about the ZAP tool, see the following links
- [https://www.zaproxy.org/docs/desktop/start/](https://www.zaproxy.org/docs/desktop/start/)

### Ffuf

ZAP spidering module only enumerates the resources it finds in links and forms, but it can miss important information such as hidden folders or backup files. We can use ffuf to discover files and folders that we cannot spot by simply browsing the website. All we need to do is launch ffuf with a list of folders names and instruct it to look recursively through them.

`ffuf -recursion -recursion-depth 1 -u http://192.168.10.10/FUZZ -w /opt/useful/SecLists/Discovery/Web-Content/raft-small-directories-lowercase.txt`

We can use the informatiom found in the website to find additional information with ffuf.
To do this we can use a tool called [CeWL](https://github.com/digininja/CeWL), first we extract words with a minimum length of 5 characters -m5, convert them to lowercase --lowercase and save them into a file called wordlist.txt -w <FILE>: `cewl -m5 --lowercase -w wordlist.txt http://192.168.10.10`

The next step we combine everything:

`ffuf -w ./folders.txt:FOLDERS,./wordlist.txt:WORDLIST,./extensions.txt:EXTENSIONS -u http://192.168.10.10/FOLDERS/WORDLISTEXTENSIONS`

where folders.txt are the folders we have found using the first command of ffuf, wordlist.txt the extracted words from cewl and extensions a list of extensions that we can found in SecList.

Source: HTB Academy