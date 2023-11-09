---
layout: post
title: Footprinting Services
categories:
- Information
- Hackthebox
tags:
- IMAP and POP3
- SNMP
- Mysql
- MSSQL
- Oracle TNS
- IPMI
- SSH
- Rsync
- R-Services
- WinRM
- WMI
- DNS
- FTP
- NFS
- SMB
date: 2023-11-06 14:32 +0000
---

## Enumeration Principles

`Our goal is not to get at the systems but to find all the ways to get there.`

| Nº | Principle                                                              |
|----|------------------------------------------------------------------------|
| 1  | There is more than meets the eye. Consider all points of view.         |
| 2  | Distinguish between what we see and what we do not see.                |
| 3  | There are always ways to gain more information. Understand the target. |


### Enumeration Methodology

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

### Domain Information

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

### Cloud Resources

Companies tipically use centrallized services such as Amazon (AWS), Google (GCP), and Microsoft (Azure) to implement their infrastructure. The fact that this services are owned by top IT companies do not mean that companies are saved from vulnerabilities in their services. The configurations made by the administrators may nevertheless make the company's cloud resources vulnerable. This often starts with the S3 buckets (AWS), blobs (Azure), cloud storage (GCP), which can be accessed without authentication if configured incorrectly.  

One of the easiest and most used is Google search combined with Google Dorks. For example, we can use the Google Dorks `inurl:` and `intext:` to narrow our search to specific terms. For example: intext:inlanefreight inurl:amazonaws.com .

To get more information about the company infrastructure we can use the website [domain.glass](https://domain.glass/). This website can tell us more information about who register the domain and the DNS records. 

Another usefull tool called [GrayHatWarfare](https://buckets.grayhatwarfare.com/) can help us find AWS, Azure, and GCP cloud storage, and even sort and filter by file format. Companies use abbreviations of the company name to use in the IT infrastucutre. The abbreviations are a good abbreviations to discovering new cloud storage from the company. 

## DNS

DNS is a system for resolving computer names into IP addresses, and it does not have a central database. The information is distributed over many thousands of name servers. There several types of DNS servers:

|          Server Type         |                                                                                                                                                                                                                         Description                                                                                                                                                                                                                         |
|:----------------------------:|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------:|
| DNS Root Server              | The root servers of the DNS are responsible for the top-level domains (TLD).  As the last instance, they are only requested if the name server does  not respond. Thus, a root server is a central interface between users  and content on the Internet, as it links domain and IP address. The Internet Corporation for Assigned Names and Numbers (ICANN) coordinates the work of the root name servers. There are 13 such root servers around the globe. |
| Authoritative Nameserver     | Authoritative name servers hold authority for a particular zone.  They only answer queries from their area of responsibility, and their  information is binding. If an authoritative name server cannot answer a  client's query, the root name server takes over at that point.                                                                                                                                                                            |
| Non-authoritative Nameserver | Non-authoritative name servers are not responsible for a particular  DNS zone. Instead, they collect information on specific DNS zones  themselves, which is done using recursive or iterative DNS querying.                                                                                                                                                                                                                                                |
| Caching DNS Server           | Caching DNS servers cache information from other name servers for a  specified period. The authoritative name server determines the duration  of this storage.                                                                                                                                                                                                                                                                                              |
| Forwarding Server            | Forwarding servers perform only one function: they forward DNS queries to another DNS server.                                                                                                                                                                                                                                                                                                                                                               |
| Resolver                     | Resolvers are not authoritative DNS servers but perform name resolution locally in the computer or router.                                                                                                                                                                                                                                                                                                                                                  |

DNS is mainly unencrypted, which means that everyone in the network can see what queries a certain IP is trying to resolve.
Associating an IP address to a name is not the only function the DNS has. It also stores and outputs additional information about the services associated with a domain. This information come from the DNS records and they have several types. Each type has a different task.

| DNS Record |                                                                                                                      Description                                                                                                                     |
|:----------:|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------:|
| A          | Returns an IPv4 address of the requested domain as a result.                                                                                                                                                                                         |
| AAAA       | Returns an IPv6 address of the requested domain.                                                                                                                                                                                                     |
| MX         | Returns the responsible mail servers as a result.                                                                                                                                                                                                    |
| NS         | Returns the DNS servers (nameservers) of the domain.                                                                                                                                                                                                 |
| TXT        | This record can contain various information. The all-rounder can be  used, e.g., to validate the Google Search Console or validate SSL  certificates. In addition, SPF and DMARC entries are set to validate  mail traffic and protect it from spam. |
| CNAME      | This record serves as an alias. If the domain www.hackthebox.eu  should point to the same IP, and we create an A record for one and a  CNAME record for the other.                                                                                   |
| PTR        | The PTR record works the other way around (reverse lookup). It converts IP addresses into valid domain names.                                                                                                                                        |
| SOA        | Provides information about the corresponding DNS zone and email address of the administrative contact.                                                                                                                                               |

The SOA record for example is located in a domain's zone file and specifies who is responsible for the operation of the domain and how DNS information for the domain is managed.

```shell
$ dig soa www.inlanefreight.com

; <<>> DiG 9.16.27-Debian <<>> soa www.inlanefreight.com
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 15876
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 512
;; QUESTION SECTION:
;www.inlanefreight.com.         IN      SOA

;; AUTHORITY SECTION:
inlanefreight.com.      900     IN      SOA     ns-161.awsdns-20.com. awsdns-hostmaster.amazon.com. 1 7200 900 1209600 86400

;; Query time: 16 msec
;; SERVER: 8.8.8.8#53(8.8.8.8)
;; WHEN: Thu Jan 05 12:56:10 GMT 2023
;; MSG SIZE  rcvd: 128

```

The dot (.) is replaced by an at sign (@) in the email address. In this example, the email address of the administrator is awsdns-hostmaster@amazon.com.

### Default Configuration

All DNS servers work with three different types of configuration files:

- local DNS configuration files
- zone files
- reverse name resolution files

### Local DNS configuration files

The local configuration files are usually:

- named.conf.local
- named.conf.options
- named.conf.log

The configuration file `named.conf` is divided into several options that control the behavior of the name server. A distinction is made between global options and zone options.

### Zone Files

A zone file is a text file that describes a DNS zone with the BIND file format. In other words it is a point of delegation in the DNS tree.
There must be precisely one SOA record and at least one NS record. 

```shell
root@bind9:~# cat /etc/bind/db.domain.com

;
; BIND reverse data file for local loopback interface
;
$ORIGIN domain.com
$TTL 86400
@     IN     SOA    dns1.domain.com.     hostmaster.domain.com. (
                    2001062501 ; serial
                    21600      ; refresh after 6 hours
                    3600       ; retry after 1 hour
                    604800     ; expire after 1 week
                    86400 )    ; minimum TTL of 1 day

      IN     NS     ns1.domain.com.
      IN     NS     ns2.domain.com.

      IN     MX     10     mx.domain.com.
      IN     MX     20     mx2.domain.com.

             IN     A       10.129.14.5

server1      IN     A       10.129.14.5
server2      IN     A       10.129.14.7
ns1          IN     A       10.129.14.2
ns2          IN     A       10.129.14.3

ftp          IN     CNAME   server1
mx           IN     CNAME   server1
mx2          IN     CNAME   server2
www          IN     CNAME   server2
```

###  Reverse Name Resolution Files

For the IP address to be resolved from the Fully Qualified Domain Name (FQDN), the DNS server must have a reverse lookup file. In this file, the computer name (FQDN) is assigned to the last octet of an IP address, which corresponds to the respective host, using a PTR record. The PTR records are responsible for the reverse translation of IP addresses into names, as we have already seen in the above table.


```shell

root@bind9:~# cat /etc/bind/db.10.129.14

;
; BIND reverse data file for local loopback interface
;
$ORIGIN 14.129.10.in-addr.arpa
$TTL 86400
@     IN     SOA    dns1.domain.com.     hostmaster.domain.com. (
                    2001062501 ; serial
                    21600      ; refresh after 6 hours
                    3600       ; retry after 1 hour
                    604800     ; expire after 1 week
                    86400 )    ; minimum TTL of 1 day

      IN     NS     ns1.domain.com.
      IN     NS     ns2.domain.com.

5    IN     PTR    server1.domain.com.
7    IN     MX     mx.domain.com.
...SNIP...

```

### Dangerous Settings

|      Option     |                                   Description                                  |
|:---------------:|:------------------------------------------------------------------------------:|
| allow-query     | Defines which hosts are allowed to send requests to the DNS server.            |
| allow-recursion | Defines which hosts are allowed to send recursive requests to the DNS server.  |
| allow-transfer  | Defines which hosts are allowed to receive zone transfers from the DNS server. |
| zone-statistics | Collects statistical data of zones.                                            |

### Footprinting DNS

- NS query: `dig ns inlanefreight.htb @10.129.14.128`
- Version query: `dig CH TXT version.bind 10.129.120.85`
- ANY query: `dig any inlanefreight.htb @10.129.14.128`

### Zone Transfers

A DNS failure usually has severe consequences for a company, the zone file is almost invariably kept identical on several name servers. When changes are made, it must be ensured that all servers have the same data. Synchronization between the servers involved is realized by zone transfer. Using a secret key rndc-key, which we have seen initially in the default configuration, the servers make sure that they communicate with their own master or slave.

The original data of a zone is located on a DNS server, which is called the primary name server for this zone. However, to increase the reliability, realize a simple load distribution, or protect the primary from attacks, one or more additional servers are installed in practice in almost all cases, which are called secondary name servers for this zone. DNS entries are generally only created, modified, or deleted on the primary.

A DNS server that serves as a direct source for synchronizing a zone file is called a master. A DNS server that obtains zone data from a master is called a slave. A primary is always a master, while a secondary can be both a slave and a master.

### Subdomain Brute Force

To find subdomains it is common to use bruteforce using hostnames. To do this, we need a list of possible hostnames, which we use to send the requests in order. Such lists are provided, for example, by [SecLists](https://github.com/danielmiessler/SecLists/blob/master/Discovery/DNS/subdomains-top1million-5000.txt).

Tools such as [DNSenum](https://github.com/fwaeytens/dnsenum) can help to gather information about subdomains.

```shell
dnsenum --dnsserver 10.129.14.128 --enum -p 0 -s 0 -o subdomains.txt -f /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-110000.txt inlanefreight.htb
```

### HTB Challenge

```
dnsenum --dnsserver 10.129.3.15 --enum -p 0 -s 0 -o subdomains.txt -f ~/SecLists/Discovery/DNS/subdomains-top1million-110000.txt inlanefreight.htb

Interact with the target DNS using its IP address and enumerate the FQDN of it for the "inlanefreight.htb" domain: ns.inlanefreight.htb 

dig axfr inlanefreight.htb @10.129.3.15 #We do a zone transfer

 <<>> DiG 9.18.16-1~deb12u1~bpo11+1-Debian <<>> axfr inlanefreight.htb @10.129.3.15
;; global options: +cmd
inlanefreight.htb.	604800	IN	SOA	inlanefreight.htb. root.inlanefreight.htb. 2 604800 86400 2419200 604800
inlanefreight.htb.	604800	IN	TXT	"MS=ms97310371"
inlanefreight.htb.	604800	IN	TXT	"atlassian-domain-verification=t1rKCy68JFszSdCKVpw64A1QksWdXuYFUeSXKU"
inlanefreight.htb.	604800	IN	TXT	"v=spf1 include:mailgun.org include:_spf.google.com include:spf.protection.outlook.com include:_spf.atlassian.net ip4:10.129.124.8 ip4:10.129.127.2 ip4:10.129.42.106 ~all"
inlanefreight.htb.	604800	IN	NS	ns.inlanefreight.htb.
app.inlanefreight.htb.	604800	IN	A	10.129.18.15
dev.inlanefreight.htb.	604800	IN	A	10.12.0.1
internal.inlanefreight.htb. 604800 IN	A	10.129.1.6
mail1.inlanefreight.htb. 604800	IN	A	10.129.18.201
ns.inlanefreight.htb.	604800	IN	A	127.0.0.1
inlanefreight.htb.	604800	IN	SOA	inlanefreight.htb. root.inlanefreight.htb. 2 604800 86400 2419200 604800
;; Query time: 93 msec
;; SERVER: 10.129.3.15#53(10.129.3.15) (TCP)
;; WHEN: Thu Sep 21 17:55:45 WEST 2023
;; XFR size: 11 records (messages 1, bytes 560)


dig axfr internal.inlanefreight.htb @10.129.3.15 #Then try every other domain for zone transfer and internal.inlanefreight.htb did work

; <<>> DiG 9.18.16-1~deb12u1~bpo11+1-Debian <<>> axfr internal.inlanefreight.htb @10.129.3.15
;; global options: +cmd
internal.inlanefreight.htb. 604800 IN	SOA	inlanefreight.htb. root.inlanefreight.htb. 2 604800 86400 2419200 604800
internal.inlanefreight.htb. 604800 IN	TXT	"MS=ms97310371"
internal.inlanefreight.htb. 604800 IN	TXT	"HTB{DN5_z0N3_7r4N5F3r_iskdufhcnlu34}"
internal.inlanefreight.htb. 604800 IN	TXT	"atlassian-domain-verification=t1rKCy68JFszSdCKVpw64A1QksWdXuYFUeSXKU"
internal.inlanefreight.htb. 604800 IN	TXT	"v=spf1 include:mailgun.org include:_spf.google.com include:spf.protection.outlook.com include:_spf.atlassian.net ip4:10.129.124.8 ip4:10.129.127.2 ip4:10.129.42.106 ~all"
internal.inlanefreight.htb. 604800 IN	NS	ns.inlanefreight.htb.
dc1.internal.inlanefreight.htb.	604800 IN A	10.129.34.16
dc2.internal.inlanefreight.htb.	604800 IN A	10.129.34.11
mail1.internal.inlanefreight.htb. 604800 IN A	10.129.18.200
ns.internal.inlanefreight.htb. 604800 IN A	127.0.0.1
vpn.internal.inlanefreight.htb.	604800 IN A	10.129.1.6
ws1.internal.inlanefreight.htb.	604800 IN A	10.129.1.34
ws2.internal.inlanefreight.htb.	604800 IN A	10.129.1.35
wsus.internal.inlanefreight.htb. 604800	IN A	10.129.18.2
internal.inlanefreight.htb. 604800 IN	SOA	inlanefreight.htb. root.inlanefreight.htb. 2 604800 86400 2419200 604800
;; Query time: 93 msec
;; SERVER: 10.129.3.15#53(10.129.3.15) (TCP)
;; WHEN: Thu Sep 21 17:58:33 WEST 2023
;; XFR size: 15 records (messages 1, bytes 677)


Identify if its possible to perform a zone transfer and submit the TXT record as the answer. (Format: HTB{...)) : HTB{DN5_z0N3_7r4N5F3r_iskdufhcnlu34}


What is the IPv4 address of the hostname DC1? 10.129.34.16

$ cat domains_found.txt

app.inlanefreight.htb
dev.inlanefreight.htb
mail1.inlanefreight.htb
ns.inlanefreight.htb


$ for dom in $(cat ~/domains_found.txt); do dnsenum --dnsserver 10.129.3.15 --enum -p 0 -s 0 -o subdomains.txt -f ~/SecLists/Discovery/DNS/fierce-hostlist.txt $dom;done

-----   dev.inlanefreight.htb   -----


Host's addresses:
__________________



Name Servers:
______________

ns.inlanefreight.htb.                    604800   IN    A         127.0.0.1


Mail (MX) Servers:
___________________



Trying Zone Transfers and getting Bind Versions:
_________________________________________________

unresolvable name: ns.inlanefreight.htb at /usr/bin/dnsenum line 900 thread 2.

Trying Zone Transfer for dev.inlanefreight.htb on ns.inlanefreight.htb ... 
AXFR record query failed: no nameservers


Brute forcing with /home/w0rth/SecLists/Discovery/DNS/fierce-hostlist.txt:
___________________________________________________________________________

dev1.dev.inlanefreight.htb.              604800   IN    A         10.12.3.6
ns.dev.inlanefreight.htb.                604800   IN    A         127.0.0.1
win2k.dev.inlanefreight.htb.             604800   IN    A        10.12.3.203


win2k.dev.inlanefreight.htb
```


## FTP

The File Transfer Protocol (FTP) is one of the oldest protocols on the Internet. The FTP runs within the application layer of the TCP/IP protocol stack. Thus, it is on the same layer as HTTP or POP. These protocols also work with the support of browsers or email clients to perform their services. There are also special FTP programs for the File Transfer Protocol.

Usually, we need credentials to use FTP on a server. We also need to know that FTP is a clear-text protocol that can sometimes be sniffed if conditions on the network are right. However, there is also the possibility that a server offers anonymous FTP. The server operator then allows any user to upload or download files via FTP without using a password. Since there are security risks associated with such a public FTP server, the options for users are usually limited.

Config file: "/etc/vsftpd.conf"
Users file: "/etc/ftpusers"

### Dangerous Settings

|            Setting           |                                     Description                                    |
|:----------------------------:|:----------------------------------------------------------------------------------:|
| anonymous_enable=YES         | Allowing anonymous login?                                                          |
| anon_upload_enable=YES       | Allowing anonymous to upload files?                                                |
| anon_mkdir_write_enable=YES  | Allowing anonymous to create new directories?                                      |
| no_anon_password=YES         | Do not ask anonymous for password?                                                 |
| anon_root=/home/username/ftp | Directory for anonymous.                                                           |
| write_enable=YES             | Allow the usage of FTP commands: STOR, DELE, RNFR, RNTO, MKD, RMD, APPE, and SITE? |


### Footprinting FTP service

One of the most common tools to gather information about a FTP service is NMAP. NMAP has built in scripts(NSE) that are executed against the ports scanned if the flag -sC is passed. NMAP stores the scripts in `/usr/share/nmap/scripts/` and it has scripts for FTP servers. NMAP knows that a port is serving an FTP server when the banner after connecting the first time presents the FTP server details.

Other tools to look at the banner and connect ot the FTP server are netcat and telnet. However if the FTP server runs withs  SSL/TLS encryption we can use a tool called openssl, to communicate with the FTP server. The good thing abou the openssl is that we can look at the SSL certificate and gain more information abou the company certificate.  


### HTB Challenge
```
nmap -p- <IP>
nmap -p 21 -sC -sV <IP>
Version: InFreight FTP v1.1

ftp <IP>
Name: anonymous
password: <Press Enter>

ls 
get flag.txt

```

## NFS

Network File System (NFS) is a network file system developed by Sun Microsystems and has the same purpose as SMB. Its purpose is to access file systems over a network as if they were local. However, it uses an entirely different protocol. NFS is used between Linux and Unix systems. This means that NFS clients cannot communicate directly with SMB servers. NFS is an Internet standard that governs the procedures in a distributed file system. While NFS protocol version 3.0 (NFSv3), which has been in use for many years, authenticates the client computer, this changes with NFSv4. Here, as with the Windows SMB protocol, the user must authenticate.

| Version |                                                                                                                                 Features                                                                                                                                |
|:-------:|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------:|
| NFSv2   | It is older but is supported by many systems and was initially operated entirely over UDP.                                                                                                                                                                              |
| NFSv3   | It has more features, including variable file size and better error reporting, but is not fully compatible with NFSv2 clients.                                                                                                                                          |
| NFSv4   | It includes Kerberos, works through firewalls and on the Internet,  no longer requires portmappers, supports ACLs, applies state-based  operations, and provides performance improvements and high security. It  is also the first version to have a stateful protocol. |


NFS is based on the Open Network Computing Remote Procedure Call (ONC-RPC/SUN-RPC) protocol exposed on TCP and UDP ports 111, which uses External Data Representation (XDR) for the system-independent exchange of data. The NFS protocol has no mechanism for authentication or authorization. Instead, authentication is completely shifted to the RPC protocol's options. The authorization is taken from the available information of the file system where the server is responsible for translating the user information supplied by the client to that of the file system and converting the corresponding authorization information as correctly as possible into the syntax required by UNIX.

The most common authentication is via UNIX UID/GID and group memberships, which is why this syntax is most likely to be applied to the NFS protocol. One problem is that the client and server do not necessarily have to have the same mappings of UID/GID to users and groups, and the server does not need to do anything further. No further checks can be made on the part of the server. This is why NFS should only be used with this authentication method in trusted networks.

### Default Configuration

The /etc/exports file contains a table of physical filesystems on an NFS server accessible by the clients.

```
$ cat /etc/exports 

# /etc/exports: the access control list for filesystems which may be exported
#               to NFS clients.  See exports(5).
#
# Example for NFSv2 and NFSv3:
# /srv/homes       hostname1(rw,sync,no_subtree_check) hostname2(ro,sync,no_subtree_check)
#
# Example for NFSv4:
# /srv/nfs4        gss/krb5i(rw,sync,fsid=0,crossmnt,no_subtree_check)
# /srv/nfs4/homes  gss/krb5i(rw,sync,no_subtree_check)
```


|      Option      |                                                                Description                                                                |
|:----------------:|:-----------------------------------------------------------------------------------------------------------------------------------------:|
| rw               | Read and write permissions.                                                                                                               |
| ro               | Read only permissions.                                                                                                                    |
| sync             | Synchronous data transfer. (A bit slower)                                                                                                 |
| async            | Asynchronous data transfer. (A bit faster)                                                                                                |
| secure           | Ports above 1024 will not be used.                                                                                                        |
| insecure         | Ports above 1024 will be used.                                                                                                            |
| no_subtree_check | This option disables the checking of subdirectory trees.                                                                                  |
| root_squash      | Assigns all permissions to files of root UID/GID 0 to the UID/GID of anonymous, which prevents root from accessing files on an NFS mount. |

### ExportFS

```shell
$ echo '/mnt/nfs  10.129.14.0/24(sync,no_subtree_check)' >> /etc/exports
$ systemctl restart nfs-kernel-server 
$ exportfs

/mnt/nfs      	10.129.14.0/24
```
Here we share the folder `/mnt/nfs` to the subnet 10.129.14.0.
The exportfs command maintains the current table of exports for the NFS server. 

### Dangerous Settings

|     Option     |                                                      Description                                                     |
|:--------------:|:--------------------------------------------------------------------------------------------------------------------:|
| rw             | Read and write permissions.                                                                                          |
| insecure       | Ports above 1024 will be used.                                                                                       |
| nohide         | If another file system was mounted below an exported directory, this directory is exported by its own exports entry. |
| no_root_squash | All files created by root are kept with the UID/GID 0.                                                               |

### Footprinting NFS

When footprinting NFS, the TCP ports 111 and 2049 are essential. We can also get information about the NFS service and the host via RPC, as shown below in the example.

```
$ sudo nmap 10.129.14.128 -p111,2049 -sV -sC

Starting Nmap 7.80 ( https://nmap.org ) at 2021-09-19 17:12 CEST
Nmap scan report for 10.129.14.128
Host is up (0.00018s latency).

PORT    STATE SERVICE VERSION
111/tcp open  rpcbind 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3           2049/udp   nfs
|   100003  3           2049/udp6  nfs
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100005  1,2,3      41982/udp6  mountd
|   100005  1,2,3      45837/tcp   mountd
|   100005  1,2,3      47217/tcp6  mountd
|   100005  1,2,3      58830/udp   mountd
|   100021  1,3,4      39542/udp   nlockmgr
|   100021  1,3,4      44629/tcp   nlockmgr
|   100021  1,3,4      45273/tcp6  nlockmgr
|   100021  1,3,4      47524/udp6  nlockmgr
|   100227  3           2049/tcp   nfs_acl
|   100227  3           2049/tcp6  nfs_acl
|   100227  3           2049/udp   nfs_acl
|_  100227  3           2049/udp6  nfs_acl
2049/tcp open  nfs_acl 3 (RPC #100227)

```

The `rpcinfo` NSE script lists all the RPC services running and the port they use.
For NFS, NMAP has a couple NSE scripts too, which we can use to gather more information about the service.
`sudo nmap --script nfs* 10.129.14.128 -sV -p111,2049`

- Show Available NFS Shares: `showmount -e 10.129.14.128`
- Mounting NFS Share: `mkdir target-NFS && sudo mount -t nfs 10.129.14.128:/ ./target-NFS/ -o nolock`

If the root_squash config is set, we cannot edit the files even as root.
- Unmount NFS share: `sudo umount ./target-NFS`

### HTB Challenge

```shell
nmap -p 111,2049 -sV -sC 10.129.74.117

PORT     STATE SERVICE VERSION
111/tcp  open  rpcbind 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3           2049/udp   nfs
|   100003  3           2049/udp6  nfs
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100005  1,2,3      37185/udp   mountd
|   100005  1,2,3      40589/tcp6  mountd
|   100005  1,2,3      50985/tcp   mountd
|   100005  1,2,3      60330/udp6  mountd
|   100021  1,3,4      33999/tcp6  nlockmgr
|   100021  1,3,4      37383/tcp   nlockmgr
|   100021  1,3,4      40396/udp   nlockmgr
|   100021  1,3,4      48334/udp6  nlockmgr
|   100227  3           2049/tcp   nfs_acl
|   100227  3           2049/tcp6  nfs_acl
|   100227  3           2049/udp   nfs_acl
|_  100227  3           2049/udp6  nfs_acl
2049/tcp open  nfs_acl 3 (RPC #100227)


nmap -p 111,2049 --script nfs* 10.129.74.117

PORT     STATE SERVICE
111/tcp  open  rpcbind
| nfs-showmount: 
|   /var/nfs 10.0.0.0/8
|_  /mnt/nfsshare 10.0.0.0/8
2049/tcp open  nfs

sudo mount -t nfs 10.129.74.117:/ ./nfs_tst/ -o nolock
# If we get the following error: mount: /home/w0rth/nfs_tst: bad option; for several filesystems (e.g. nfs, cifs) you might need a /sbin/mount.<type> helper program.
# Install: sudo apt install nfs-common

find ./nfs_tst/ -name flag*

./var/nfs/flag.txt
./mnt/nfsshare/flag.txt

```

## SMB

Server Message Block (SMB) is a client-server protocol that regulates access to files and entire directories and other network resources such as printers, routers, or interfaces released for the network. Information exchange between different system processes can also be handled based on the SMB protocol. SMB first became available to a broader public, for example, as part of the OS/2 network operating system LAN Manager and LAN Server. Since then, the main application area of the protocol has been the Windows operating system series in particular, whose network services support SMB in a downward-compatible manner - which means that devices with newer editions can easily communicate with devices that have an older Microsoft operating system installed. With the free software project Samba, there is also a solution that enables the use of SMB in Linux and Unix distributions and thus cross-platform communication via SMB.

An SMB server can provide arbitrary parts of its local file system as shares. Therefore the hierarchy visible to a client is partially independent of the structure on the server. Access rights are defined by Access Control Lists (ACL). They can be controlled in a fine-grained manner based on attributes such as execute, read, and full access for individual users or user groups. The ACLs are defined based on the shares and therefore do not correspond to the rights assigned locally on the server.

As mentioned earlier, there is an alternative variant to the SMB server, called Samba, developed for Unix-based operating system. Samba implements the Common Internet File System (CIFS) network protocol. CIFS is a "dialect" of SMB. In other words, CIFS is a very specific implementation of the SMB protocol, which in turn was created by Microsoft. This allows Samba to communicate with newer Windows systems. Therefore, it usually is referred to as SMB / CIFS. However, CIFS is the extension of the SMB protocol. So when we pass SMB commands over Samba to an older NetBIOS service, it usually connects to the Samba server over TCP ports 137, 138, 139, but CIFS uses TCP port 445 only. There are several versions of SMB, including outdated versions that are still used in specific infrastructures.

We know that Samba is suitable for both Linux and Windows systems. In a network, each host participates in the same workgroup. A workgroup is a group name that identifies an arbitrary collection of computers and their resources on an SMB network. There can be multiple workgroups on the network at any given time. IBM developed an application programming interface (API) for networking computers called the Network Basic Input/Output System (NetBIOS). The NetBIOS API provided a blueprint for an application to connect and share data with other computers. In a NetBIOS environment, when a machine goes online, it needs a name, which is done through the so-called name registration procedure. Either each host reserves its hostname on the network, or the NetBIOS Name Server (NBNS) is used for this purpose. It also has been enhanced to Windows Internet Name Service (WINS).

Configuration file: `/etc/samba/smb.conf`

|            Setting           |                              Description                              |
|:----------------------------:|:---------------------------------------------------------------------:|
| [sharename]                  | The name of the network share.                                        |
| workgroup = WORKGROUP/DOMAIN | Workgroup that will appear when clients query.                        |
| path = /path/here/           | The directory to which user is to be given access.                    |
| server string = STRING       | The string that will show up when a connection is initiated.          |
| unix password sync = yes     | Synchronize the UNIX password with the SMB password?                  |
| usershare allow guests = yes | Allow non-authenticated users to access defined shared?               |
| map to guest = bad user      | What to do when a user login request doesn't match a valid UNIX user? |
| browseable = yes             | Should this share be shown in the list of available shares?           |
| guest ok = yes               | Allow connecting to the service without using a password?             |
| read only = yes              | Allow users to read files only?                                       |
| create mask = 0700           | What permissions need to be set for newly created files?              |

### Dangerous Settings


|          Setting          |                             Description                             |
|:-------------------------:|:-------------------------------------------------------------------:|
| browseable = yes          | Allow listing available shares in the current share?                |
| read only = no            | Forbid the creation and modification of files?                      |
| writable = yes            | Allow users to create and modify files?                             |
| guest ok = yes            | Allow connecting to the service without using a password?           |
| enable privileges = yes   | Honor privileges assigned to specific SID?                          |
| create mask = 0777        | What permissions must be assigned to the newly created files?       |
| directory mask = 0777     | What permissions must be assigned to the newly created directories? |
| logon script = script.sh  | What script needs to be executed on the user's login?               |
| magic script = script.sh  | Which script should be executed when the script gets closed?        |
| magic output = script.out | Where the output of the magic script needs to be stored?             |


Connecting to a samba server to look at shares as an anonymous user: `smbclient -N -L //10.129.14.128` 

-N means null session whuch is the same the anonymous session in an FTP service. It does not need password to connect. -L means listing the shares.

To connect to a share: `smbclient //10.129.14.128/<share_name>`

If we want to download a file to our system we can use the `get` command. If we want to execute commands we can use `!<cmd>`, for example: `!ls`.

From the administrative point of view, we can check these connections using smbstatus. Apart from the Samba version, we can also see who, from which host, and which share the client is connected. This is especially important once we have entered a subnet (perhaps even an isolated one) that the others can still access.

For example, with domain-level security, the samba server acts as a member of a Windows domain. Each domain has at least one domain controller, usually a Windows NT server providing password authentication. This domain controller provides the workgroup with a definitive password server. The domain controllers keep track of users and passwords in their own Security Authentication Module (SAM) and authenticate each user when they log in for the first time and wish to access another machine's share.

### Footprinting SMB service

We can use NMAP to gather information about the SMB server using the NSE scripts. However they take to long and the information is very limited. Due to that we need to analyse the SMB server manually using other tools.

One of the handy tools for this is rpcclient. This is a tool to perform MS-RPC functions. The Remote Procedure Call (RPC) is a concept and, therefore, also a central tool to realize operational and work-sharing structures in networks and client-server architectures. The communication process via RPC includes passing parameters and the return of a function value.

`rpcclient -U "" 10.129.14.128`

The rpcclient offers us many different requests with which we can execute specific functions on the SMB server to get information.

|      Query      |                             Description                            |
|:---------------:|:------------------------------------------------------------------:|
| srvinfo         | Server information.                                                |
| enumdomains     | Enumerate all domains that are deployed in the network.            |
| querydominfo    | Provides domain, server, and user information of deployed domains. |
| netshareenumall | Enumerates all available shares.                                   |
| netsharegetinfo | Provides information about a specific share.                       |
| enumdomusers    | Enumerates all domain users.                                       |
| queryuser       | Provides information about a specific user.                        |
| querygroup      | Provides information about a specific group.                       |

Sometimes we dont have access to all the commands such as enumdomusers. In this situation we can bruteforce the RID and try to find users with queryuser which is a very common command to be available. To do this we can use the following bash command: `$ for i in $(seq 500 1100);do rpcclient -N -U "" 10.129.14.128 -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo "";done`.

### Other Tools

However instead of using the rpcclient, we can an alternative python script from the [Impacket](https://github.com/SecureAuthCorp/impacket) called [samrdump.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/samrdump.py). Command: `samrdump.py <IP>`

All the information can be obtain using other tools such as [SMBMap](https://github.com/ShawnDEvans/smbmap) and [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec).

- SMBMap: `smbmap -H 10.129.14.128`
- CrackMapExec: `crackmapexec smb 10.129.14.128 --shares -u '' -p ''`

Another tool that automates most of the work is [enum4linux-ng](https://github.com/cddmp/enum4linux-ng). This tool can provide a lot of information, however it is not recommeneded to rely only on 1 automated tool to gather all the information.

```shell
$ git clone https://github.com/cddmp/enum4linux-ng.git
$ cd enum4linux-ng
$ pip3 install -r requirements.txt
$ ./enum4linux-ng.py 10.129.14.128 -A

```


### HTB Challenge

```shell
nmap -p 137,138,139,445 -sV -sC 10.129.161.245
Version: Samba smbd 4.6.2

$ samrdump.py 10.129.161.245
Impacket v0.12.0.dev1+20230817.32422.a769683 - Copyright 2023 Fortra

[*] Retrieving endpoint list from 10.129.161.245
Found domain(s):
 . DEVSMB
 . Builtin
[*] Looking up users in domain DEVSMB
[*] No entries received.

$ smbmap -H 10.129.161.245
[+] IP: 10.129.161.245:445	Name: 10.129.161.245                                    
        Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	print$                                            	NO ACCESS	Printer Drivers
	sambashare                                        	READ ONLY	InFreight SMB v3.1
	IPC$                                              	NO ACCESS	IPC Service (InlaneFreight SMB server (Samba, Ubuntu))


$ smbclient //10.129.161.245/sambashare

!cat contents/flag.txt 
HTB{o873nz4xdo873n4zo873zn4fksuhldsf}

$ enum4linux 10.129.161.245 -A
Domain: DEVOPS
Additional information about the sambashare share: InFreight SMB v3.1

To find the path for the sambashare share the tool rpcclient was used.
$ rpcclient -U "" 10.129.161.245
$> netsharegetinfo sambashare

netname: sambashare
	remark:	InFreight SMB v3.1
	path:	C:\home\sambauser\
	password:	
	type:	0x0
	perms:	0
	max_uses:	-1
	num_uses:	1
revision: 1
type: 0x8004: SEC_DESC_DACL_PRESENT SEC_DESC_SELF_RELATIVE 
DACL
	ACL	Num ACEs:	1	revision:	2
	---
	ACE
		type: ACCESS ALLOWED (0) flags: 0x00 
		Specific bits: 0x1ff
		Permissions: 0x1f01ff: SYNCHRONIZE_ACCESS WRITE_OWNER_ACCESS WRITE_DAC_ACCESS READ_CONTROL_ACCESS DELETE_ACCESS 
		SID: S-1-1-0


Trying C:\home\sambauser\ was not sucessful, however /home/sambauser was the right answer. 
This is because the machine was a Linux machine instead of windows and the paths are represented differently.

```


## IMAP and POP3

By default, ports **110**, **143**, **993**, and **995** are used for IMAP and POP3. 

### IMAP

| Command                       | Description                                                                                               |
|-------------------------------|-----------------------------------------------------------------------------------------------------------|
| 1 LOGIN username password     | User's login.                                                                                             |
| 1 LIST "" *                   | Lists all directories.                                                                                    |
| 1 CREATE "INBOX"              | Creates a mailbox with a specified name.                                                                  |
| 1 DELETE "INBOX"              | Deletes a mailbox.                                                                                        |
| 1 RENAME "ToRead" "Important" | Renames a mailbox.                                                                                        |
| 1 LSUB "" *                   | Returns a subset of names from the set of names that the User has declared as being active or subscribed. |
| 1 SELECT INBOX                | Selects a mailbox so that messages in the mailbox can be accessed.                                        |
| 1 UNSELECT INBOX              | Exits the selected mailbox.                                                                               |
| 1 FETCH <ID> all              | Retrieves data associated with a message in the mailbox.                                                  |
| 1 FETCH 1 (body[])            | Retrieves message full body                                                                               |
| 1 CLOSE                       | Removes all messages with the Deleted flag set.                                                           |
| 1 LOGOUT                      | Closes the connection with the IMAP server.                                                               |

### POP3

| Command                       | Description                                                                                               |
|-------------------------------|-----------------------------------------------------------------------------------------------------------|
| 1 LOGIN username password     | User's login.                                                                                             |
| 1 LIST "" *                   | Lists all directories.                                                                                    |
| 1 CREATE "INBOX"              | Creates a mailbox with a specified name.                                                                  |
| 1 DELETE "INBOX"              | Deletes a mailbox.                                                                                        |
| 1 RENAME "ToRead" "Important" | Renames a mailbox.                                                                                        |
| 1 LSUB "" *                   | Returns a subset of names from the set of names that the User has declared as being active or subscribed. |
| 1 SELECT INBOX                | Selects a mailbox so that messages in the mailbox can be accessed.                                        |
| 1 UNSELECT INBOX              | Exits the selected mailbox.                                                                               |
| 1 FETCH <ID> all              | Retrieves data associated with a message in the mailbox.                                                  |
| 1 CLOSE                       | Removes all messages with the Deleted flag set.                                                           |
| 1 LOGOUT                      | Closes the connection with the IMAP server.                                                               |


### Dangerous Settings

| Setting                 | Description                                                                               |
|-------------------------|-------------------------------------------------------------------------------------------|
| auth_debug              | Enables all authentication debug logging.                                                 |
| auth_debug_passwords    | This setting adjusts log verbosity, the submitted passwords, and the scheme gets logged.  |
| auth_verbose            | Logs unsuccessful authentication attempts and their reasons.                              |
| auth_verbose_passwords  | Passwords used for authentication are logged and can also be truncated.                   |
| auth_anonymous_username | This specifies the username to be used when logging in with the ANONYMOUS SASL mechanism. |


### Footprinting the Service

`$ sudo nmap 10.129.14.128 -sV -p110,143,993,995 -sC`

`$ curl -k 'imaps://10.129.14.128' --user user:p4ssw0rd -v`

`$ openssl s_client -connect 10.129.14.128:pop3s`

`$ openssl s_client -connect 10.129.14.128:imaps`


## SNMP

By default, ports **161** and **162** are used for SNMP.

### SNMPv1

-  SNMPv1 has no built-in authentication mechanism, meaning anyone accessing the network can read and modify network data
-  SNMPv1 does not support encryption, meaning that all data is sent in plain text and can be easily intercepted

### SNMPv2

- SNMPv2 community string that provides security is only transmitted in plain text, meaning it has no built-in encryption.

### SNMPv3

- SNMPv3 provides authentication using username and password
- SNMPv3 provides transmission encryption (via pre-shared key)

### Community Strings

They are like passwords that determine whether the requested information can be viewed or not.

### Dangerous Settings

| Settings                                       | Description                                                                               |
|------------------------------------------------|-------------------------------------------------------------------------------------------|
| rwuser noauth                                  | Provides access to the full OID tree without authentication.                              |
| rwcommunity <community string> <IPv4 address>  | Provides access to the full OID tree regardless of where the requests were sent from.     |
| rwcommunity6 <community string> <IPv6 address> | Same access as with rwcommunity with the difference of using IPv6.                        |
| auth_verbose_passwords                         | Passwords used for authentication are logged and can also be truncated.                   |
| auth_anonymous_username                        | This specifies the username to be used when logging in with the ANONYMOUS SASL mechanism. |

### Footprinting the Service

For footprinting SNMP, we can use tools like **snmpwalk**, **onesixtyone**, and **braa**. **Snmpwalk** is used to query the OIDs with their information. **Onesixtyone** can be used to brute-force the names of the community strings since they can be named arbitrarily by the administrator. Since these community strings can be bound to any source, identifying the existing community strings can take quite some time.

`$ snmpwalk -v2c -c public 10.129.14.128`
Note: In case of needing to install use `$ sudo apt-get install snmp`

If we do not know the community string, we can use **onesixtyone** and **SecLists** wordlists to identify these community strings.

`$ onesixtyone -c /opt/useful/SecLists/Discovery/SNMP/snmp.txt 10.129.14.128`

Once we know a community string, we can use it with **braa** to brute-force the individual OIDs and enumerate the information behind them.

`$ braa <community string>@<IP>:.1.3.6.*   # Syntax`


## Mysql

By default, the port used by MySQL is 3306.

### Dangerous Settings

| Settings         | Description                                                                                                  |
|------------------|--------------------------------------------------------------------------------------------------------------|
| user             | Sets which user the MySQL service will run as.                                                               |
| password         | Sets the password for the MySQL user.                                                                        |
| admin_address    | The IP address on which to listen for TCP/IP connections on the administrative network interface.            |
| debug            | This variable indicates the current debugging settings                                                       |
| sql_warnings     | This variable controls whether single-row INSERT statements produce an information string if warnings occur. |
| secure_file_priv | This variable is used to limit the effect of data import and export operations.                              |

### Footprinting the Service

Commands to use when working with mysql databases.

| Command                                            | Description                                                                                       |
|----------------------------------------------------|---------------------------------------------------------------------------------------------------|
| mysql -u <user> -p<password> -h <IP address>       | Connect to the MySQL server. There should not be a space between the '-p' flag, and the password. |
| show databases;                                    | Show all databases.                                                                               |
| use <database>;                                    | Select one of the existing databases.                                                             |
| show tables;                                       | Show all available tables in the selected database.                                               |
| show columns from <table>;                         | Show all columns in the selected database.                                                        |
| select * from <table>;                             | Show everything in the desired table.                                                             |
| select * from <table> where <column> = "<string>"; | Search for needed string in the desired table.                                                    |


For more information about security guidelines for mysql databases see [link](https://dev.mysql.com/doc/refman/8.0/en/general-security-issues.html).

## MSSQL

MSSQL runs by default on port 1433.

Clients that can be use to access a database running on MSSQL:
- https://docs.microsoft.com/en-us/sql/tools/mssql-cli?view=sql-server-ver15
- https://www.heidisql.com/
- https://www.macsqlclient.com/
- https://github.com/SecureAuthCorp/impacket/blob/master/examples/mssqlclient.py

The most used by pentestes is the impacket one: `$ impacket-mssqlclient`

### Default MSSQL Databases

| Default System Database                            | Description                                                                                                                                                                                            |
|----------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| master                                             | Tracks all system information for an SQL server instance                                                                                                                                               |
| model                                              | Template database that acts as a structure for every new database created. Any setting changed in the model database will be reflected in any new database created after changes to the model database |
| msdb                                               | The SQL Server Agent uses this database to schedule jobs & alerts                                                                                                                                      |
| tempdb                                             | Stores temporary objects                                                                                                                                                                               |
| resource                                           | Read-only database containing system objects included with SQL server                                                                                                                                  |
| select * from <table>;                             | Show everything in the desired table.                                                                                                                                                                  |
| select * from <table> where <column> = "<string>"; | Search for needed string in the desired table.                                                                                                                                                         |


### Default Configuration

-  SQL service will likely run as **NT SERVICE\MSSQLSERVER**
-  By default, encryption is not enforced when attempting to connect
-  Authentication being set to Windows Authentication means that the underlying Windows OS will process the login request and use either the local SAM database or the domain controller (hosting Active Directory) before allowing connectivity to the database management system.

### Dangerous Settings

We may benefit from looking into the following:
- MSSQL clients not using encryption to connect to the MSSQL server
- The use of self-signed certificates when encryption is being used. It is possible to spoof self-signed certificates
- The use of named pipes
- Weak & default sa credentials. Admins may forget to disable this account

### Footprinting the Service

**Nmap** has various default scripts for mssql. The scripted NMAP scan below provides us with helpful information. We can see the hostname, database instance name, software version of MSSQL and named pipes are enabled.

`$ sudo nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 10.129.201.248`

We can also use **metasploit** script **mssql_ping**.

`msf6 auxiliary(scanner/mssql/mssql_ping)`

Once we got credentials we can login in the service using impacket mssql client.

`python3 mssqlclient.py Administrator@10.129.201.248 -windows-auth`


| Command                                     | Description                    |
|---------------------------------------------|--------------------------------|
| SELECT name FROM master.sys.databases       | Show databases in mssql server |
| use <database name>                         | use database                   |
| Select * from <database>.Information_schema.tables go | Show tables from database | 


## Oracle TNS

- Oracle TNS server is a communication protocol that facilitates communication between Oracle databases and applications over networks
- The configs files are tnsnames.ora and listener.ora and are typically located in the ORACLE_HOME/network/admin directory.
- The service is typically running in the port 1521


| Setting            | Description                                                                                                              |
|--------------------|--------------------------------------------------------------------------------------------------------------------------|
| DESCRIPTION        | A descriptor that provides a name for the database and its connection type.                                              |
| ADDRESS            | The network address of the database, which includes the hostname and port number.                                        |
| PROTOCOL           | The network protocol used for communication with the server                                                              |
| PORT               | The port number used for communication with the server                                                                   |
| CONNECT_DATA       | Specifies the attributes of the connection, such as the service name or SID, protocol, and database instance identifier. |
| INSTANCE_NAME      | The name of the database instance the client wants to connect.                                                           |
| SERVICE_NAME       | The name of the service that the client wants to connect to.                                                             |
| SERVER             | The type of server used for the database connection, such as dedicated or shared.                                        |
| USER               | The username used to authenticate with the database server.                                                              |
| PASSWORD           | The password used to authenticate with the database server.                                                              |
| SECURITY           | The type of security for the connection.                                                                                 |
| VALIDATE_CERT      | Whether to validate the certificate using SSL/TLS.                                                                       |
| SSL_VERSION        | The version of SSL/TLS to use for the connection.                                                                        |
| CONNECT_TIMEOUT    | The time limit in seconds for the client to establish a connection to the database.                                      |
| RECEIVE_TIMEOUT    | The time limit in seconds for the client to receive a response from the database.                                        |
| SEND_TIMEOUT       | The time limit in seconds for the client to send a request to the database.                                              |
| SQLNET.EXPIRE_TIME | The time limit in seconds for the client to detect a connection has failed.                                              |
| TRACE_LEVEL        | The level of tracing for the database connection.                                                                        |
| TRACE_DIRECTORY    | The directory where the trace files are stored.                                                                          |
| TRACE_FILE_NAME    | The name of the trace file.                                                                                              |
| LOG_FILE           | The file where the log information is stored.                                                                            |


### Enumeration 

- In Oracle RDBMS, a **System Identifier (SID)** is a unique name that identifies a particular database instance.
- To connect to a specific database we need to know the **SID**.
- We can bruteforce it with an **nmap** script: `sudo nmap -p1521 -sV 10.129.204.235 --open --script oracle-sid-brute`
- We can use the **odat.py** tool to perform a variety of scans to enumerate and gather information about the Oracle database services and its components. Those scans can retrieve database names, versions, running processes, user accounts, vulnerabilities, misconfigurations, etc. The command is : ` python3 odat.py all -s 10.129.204.235`
- Once we got credentials we can use sqlplus to connect to the database instance: `sqlplus <user>/<pass>@10.129.204.235/<SID>`
- List all available database `select table_name from all_tables;`
- Show the privileges of the current user: `select * from user_role_privs;`
- We can try to get more permissions by login as **sysdba** : `sqlplus <user>/<pass>@10.129.204.235/<SID> as sysdba`
- To extract the hashes from the users we can execute the following command: `select name, password from sys.user$;`
- We can try to upload a web shell, if the server has a web server running.
- For linux is typically `/var/www/linux` and for windows is `C:\inetpub\wwwroot`
- We can upload it using odat: `./odat.py utlfile -s 10.129.204.235 -d <SID> -U <USER> -P <PASS> --sysdba --putFile C:\\inetpub\\wwwroot testing.txt ./testing.txt`

Note: if we cant run sqlplus do : `sudo sh -c "echo /usr/lib/oracle/12.2/client64/lib > /etc/ld.so.conf.d/oracle-instantclient.conf";sudo ldconfig`

## IPMI

[Intelligent Platform Management Interface (IPMI)](https://www.thomas-krenn.com/en/wiki/IPMI_Basics) is a set of standardized specifications for hardware-based host management systems used for system management and monitoring. It acts as an autonomous subsystem and works independently of the host's BIOS, CPU, firmware, and underlying operating system. 

### Footprinting the Service

- IPMI communicates over port 623 UDP
- Systems that use the IPMI protocol are called Baseboard Management Controllers (BMCs). Most servers either come with a BMC or support adding a BMC. The most common BMCs we often see during internal penetration tests are HP iLO, Dell DRAC, and Supermicro IPMI. If we can access one BMC during a pentest we can monitor, shutdown, reboot and change the host operating system. Most of those BMCs have a web-based management console, some sort of command-line remote access protocol such as Telnet or SSH and the port 639 UDP.

- To get the version of the ipmi we can run the following nmap script: `sudo nmap -sU --script ipmi-version  -p 623 10.129.23.113`
- Or we can use a module from metasploit: `use auxiliary/scanner/ipmi/ipmi_version`

- During internal penetration tests, we often find BMCs where the administrators have not changed the default password. Some unique default passwords to keep in our cheatsheets include:

| Product         | Username      | Password                                                                  |
|-----------------|---------------|---------------------------------------------------------------------------|
| Dell iDRAC      | root          | calvin                                                                    |
| HP iLO          | Administrator | randomized 8-character string consisting of numbers and uppercase letters |
| Supermicro IPMI | ADMIN         | ADMIN                                                                     |

However if we can't gain access with the default credentials, we take advantage of a known flaw in the RAKP protocol in IPMI 2.0. During the authentication process the user password hash is sent to the client before the authentication has place. Using this flaw we can have all the users hashes and crack them offline using hashcat mode 7300, since they use SHA1 or MD5. For HP iLO we can use a mask in hashcat since we know the format of the password. The command to crack it is : `hashcat -m 7300 ipmi.txt -a 3 ?1?1?1?1?1?1?1?1 -1 ?d?u`, which tries all combinations of upper case letters and numbers for an eight-character password.

We can retrieve all the hashes using a metasploit module: `use auxiliary/scanner/ipmi/ipmi_dumphashes`

## SSH

SSH is typically running in the port 22 and has two versions, SSH-1 and SSH-2. SSH-1 is vulnerable to MITM attacks and is less overall is less secure.
Ways of connecting to a SSH service:

1. Password authentication
2. Public-key authentication
3. Host-based authentication
4. Keyboard authentication
5. Challenge-response authentication
6. GSSAPI authentication

### Default Configuration

The config file is called sshd_config and has the following default config:

```shell
Include /etc/ssh/sshd_config.d/*.conf
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding yes
PrintMotd no
AcceptEnv LANG LC_*
Subsystem       sftp    /usr/lib/openssh/sftp-server
```

### Dangerous Settings

| Setting                    | Description                                 |
|----------------------------|---------------------------------------------|
| PasswordAuthentication yes | Allows password-based authentication.       |
| PermitEmptyPasswords yes   | Allows the use of empty passwords.          |
| PermitRootLogin yes        | Allows to log in as the root user.          |
| Protocol 1                 | Uses an outdated version of encryption.     |
| X11Forwarding yes          | Allows X11 forwarding for GUI applications. |
| AllowTcpForwarding yes     | Allows forwarding of TCP ports.             |
| PermitTunnel               | Allows tunneling.                           |
| DebianBanner yes           | Displays a specific banner when logging in. |


### Footprinting the Service

One of the tools we can use to fingerprint the SSH server is [ssh-audit](https://github.com/jtesta/ssh-audit): `./ssh-audit.py 10.129.14.132`.
By using `ssh -v` we can know the authentication methods used by the host ssh service.

## Rsync

Rsync is usually used to copy files between remote hosts. It usually uses port 873 sometimes ssh. 
This [guide](https://book.hacktricks.xyz/network-services-pentesting/873-pentesting-rsync) covers some of the ways Rsync can be abused, most notably by listing the contents of a shared folder on a target server and retrieving files. This can sometimes be done without authentication. Other times we will need credentials.

We can access rsync port to see if we have accessible shares: `nc -nv <hosts_ip> 873`
Enumerate a rsync share: `rsync -av --list-only rsync://<host_ip>/<share_name>`
If Rsync is configured to use SSH to transfer files, we could modify our commands to include the -e ssh flag, or -e "ssh -p2222" if a non-standard port is in use for SSH, see the [link](https://phoenixnap.com/kb/how-to-rsync-over-ssh).

## R-Services

R-services are a bundle of services that were the standard utilities for Unix systems until they got replaced by SSH because they are unencrypted like telnet. They typically run in the port 512, 513 and 514. The services that are part of this bundle are:

- rcp (remote copy)
- rexec (remote execution)
- rlogin (remote login)
- rsh (remote shell)
- rstat
- ruptime
- rwho (remote who)

Each command has a different functionality but the most abused are in the following table:

| Command | Service Daemon | Port | Transport Protocol | Description                                                                                                                                                                                                                                                        |
|---------|----------------|------|--------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| rcp     | rshd           | 514  | TCP                | Copy a file or directory bidirectionally from the local system to the remote system (or vice versa) or from one remote system to another. It works like the cp command on Linux but provides no warning to the user for overwriting existing files on a system.    |
| rsh     | rshd           | 514  | TCP                | Opens a shell on a remote machine without a login procedure. Relies upon the trusted entries in the /etc/hosts.equiv and .rhosts files for validation.                                                                                                             |
| rexec   | rexecd         | 512  | TCP                | Enables a user to run shell commands on a remote machine. Requires authentication through the use of a username and password through an unencrypted network socket. Authentication is overridden by the trusted entries in the /etc/hosts.equiv and .rhosts files. |
| rlogin  | rlogind        | 513  | TCP                | Enables a user to log in to a remote host over the network. It works similarly to telnet but can only connect to Unix-like hosts. Authentication is overridden by the trusted entries in the /etc/hosts.equiv and .rhosts files.                                   |


The /etc/hosts.equiv file contains a list of trusted hosts and is used to grant access to other systems on the network. When users on one of these hosts attempt to access the system, they are automatically granted access without further authentication. 
By default, these services utilize Pluggable Authentication Modules (PAM) for user authentication onto a remote system; however, they also bypass this authentication through the use of the /etc/hosts.equiv and .rhosts files on the system. The hosts.equiv and .rhosts files contain a list of hosts (IPs or Hostnames) and users that are trusted by the local host when a connection attempt is made using r-commands.

**Note**: The hosts.equiv file is recognized as the global configuration regarding all users on a system, whereas .rhosts provides a per-user configuration.

If either of the files are misconfigured and allow our host IP to connect to the services we can gain instant shell by using **rlogin** without needing to authenticate. To login the target machine running this services: `rlogin 10.0.17.2 -l htb-student`. Here we are trying to login as htb-student.

Once successfully logged in, we can also abuse the **rwho** command to list all interactive sessions on the local network by sending requests to the UDP port 513: `rwho`

To provide additional information in conjunction with rwho, we can issue the **rusers** command. This will give us a more detailed account of all logged-in users over the network: `rusers -al 10.0.17.5`

## RDP

The Remote Desktop Protocol (RDP) is a protocol developed by Microsoft for remote access to a computer running the Windows operating system.
RDP typically uses TCP port 3389 for transport portocol and UDP port 3389 for remote adminsitration.

For an RDP session to be established, both the network firewall and the firewall on the server must allow connections from the outside. If Network Address Translation (NAT) is used on the route between client and server, as is often the case with Internet connections, the remote computer needs the public IP address to reach the server. In addition, port forwarding must be set up on the NAT router in the direction of the server.

RDP uses Transport Layer Security (TLS/SSL) since Windows Vista, meaning all data is encrypted. However the certificates used are self-signed.

### Footprinting the Service

`nmap -sV -sC 10.129.201.248 -p3389 --script rdp*`

In addition, we can use --packet-trace to track the individual packages and inspect their contents manually. We can see that the RDP cookies (mstshash=nmap) used by Nmap to interact with the RDP server can be identified by threat hunters and various security services such as Endpoint Detection and Response (EDR), and can lock us out as penetration testers on hardened networks.

`nmap -sV -sC 10.129.201.248 -p3389 --packet-trace --disable-arp-ping -n`

A Perl script named [rdp-sec-check.pl](https://github.com/CiscoCXSecurity/rdp-sec-check) has also been developed by Cisco CX Security Labs that can unauthentically identify the security settings of RDP servers based on the handshakes.

```shell
git clone https://github.com/CiscoCXSecurity/rdp-sec-check.git && cd rdp-sec-check
./rdp-sec-check.pl 10.129.201.248
```

Authentication and connection to such RDP servers can be made in several ways. For example, we can connect to RDP servers on Linux using **xfreerdp**, **rdesktop**, or **Remmina** and interact with the GUI of the server accordingly.

`$ xfreerdp /u:cry0l1t3 /p:"P455w0rd!" /v:10.129.201.248`

## WinRM

Winrm is a Windows integrated remote management protocol that uses SOAP to establish conenctions between remtoe hosts and their applications. WinRM relies on TCP port 5985 and 5986 for communciation where port 5986 uses HTTPS. Winrm allows the execution of commands in the host using the component Windows Remote Shell(WinRS).

### Footprinting the Service

`nmap -sV -sC 10.129.201.248 -p5985,5986 --disable-arp-ping -n`

We can findout if we can reach WinRM by using a powershell in windows with a cmdlet called [Test-WsMan](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/test-wsman?view=powershell-7.2) or in linux by using [evil-winrm](https://github.com/Hackplayers/evil-winrm), another pentest tool to interact with the winrm.

`evil-winrm -i 10.129.201.248 -u Cry0l1t3 -p P455w0rD!`

## WMI

WMI allows read and write access to almost all settings on Windows systems. WMI is typically accessed via PowerShell, VBScript, or the Windows Management Instrumentation Console (WMIC). WMI is not a single program but consists of several programs and various databases, also known as repositories. It is typically running on TCP port 135.

### Footprinting the Service

We can connect to the wmi using a tool called wmiexec.py from the impacket toolkit. 

`/usr/share/doc/python3-impacket/examples/wmiexec.py Cry0l1t3:"P455w0rD!"@10.129.201.248 "hostname"`


Note: The majority of this content is from [Hackthebox Academy](https://academy.hackthebox.com/) so if you are interested and want to learn more use their platform because is one of the best platforms to learn about pentesting. Don't forget to use a school email when buying a subscription ;)