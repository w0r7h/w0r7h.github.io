---
layout: post
title: footprinting_dns
categories:
- Information
tags:
- Enumeration
- Footprinting
- dns
date: 2023-09-20 17:20 +0100
---

## Footprinting - DNS

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

## Default Configuration

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

## Dangerous Settings

|      Option     |                                   Description                                  |
|:---------------:|:------------------------------------------------------------------------------:|
| allow-query     | Defines which hosts are allowed to send requests to the DNS server.            |
| allow-recursion | Defines which hosts are allowed to send recursive requests to the DNS server.  |
| allow-transfer  | Defines which hosts are allowed to receive zone transfers from the DNS server. |
| zone-statistics | Collects statistical data of zones.                                            |

## Footprinting DNS

- NS query: `dig ns inlanefreight.htb @10.129.14.128`
- Version query: `dig CH TXT version.bind 10.129.120.85`
- ANY query: `dig any inlanefreight.htb @10.129.14.128`

## Zone Transfers

A DNS failure usually has severe consequences for a company, the zone file is almost invariably kept identical on several name servers. When changes are made, it must be ensured that all servers have the same data. Synchronization between the servers involved is realized by zone transfer. Using a secret key rndc-key, which we have seen initially in the default configuration, the servers make sure that they communicate with their own master or slave.

The original data of a zone is located on a DNS server, which is called the primary name server for this zone. However, to increase the reliability, realize a simple load distribution, or protect the primary from attacks, one or more additional servers are installed in practice in almost all cases, which are called secondary name servers for this zone. DNS entries are generally only created, modified, or deleted on the primary.

A DNS server that serves as a direct source for synchronizing a zone file is called a master. A DNS server that obtains zone data from a master is called a slave. A primary is always a master, while a secondary can be both a slave and a master.

## Subdomain Brute Force

To find subdomains it is common to use bruteforce using hostnames. To do this, we need a list of possible hostnames, which we use to send the requests in order. Such lists are provided, for example, by [SecLists](https://github.com/danielmiessler/SecLists/blob/master/Discovery/DNS/subdomains-top1million-5000.txt).

Tools such as [DNSenum](https://github.com/fwaeytens/dnsenum) can help to gather information about subdomains.

```shell
dnsenum --dnsserver 10.129.14.128 --enum -p 0 -s 0 -o subdomains.txt -f /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-110000.txt inlanefreight.htb
```

## Challenge

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