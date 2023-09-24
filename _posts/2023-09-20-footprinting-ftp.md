---
layout: post
title: Footprinting - FTP
categories:
- Information
tags:
- Enumeration
- Footprinting
- ftp
date: 2023-09-20 14:36 +0100
---


## Footprinting - FTP

The File Transfer Protocol (FTP) is one of the oldest protocols on the Internet. The FTP runs within the application layer of the TCP/IP protocol stack. Thus, it is on the same layer as HTTP or POP. These protocols also work with the support of browsers or email clients to perform their services. There are also special FTP programs for the File Transfer Protocol.

Usually, we need credentials to use FTP on a server. We also need to know that FTP is a clear-text protocol that can sometimes be sniffed if conditions on the network are right. However, there is also the possibility that a server offers anonymous FTP. The server operator then allows any user to upload or download files via FTP without using a password. Since there are security risks associated with such a public FTP server, the options for users are usually limited.

Config file: "/etc/vsftpd.conf"
Users file: "/etc/ftpusers"

## Dangerous Settings

|            Setting           |                                     Description                                    |
|:----------------------------:|:----------------------------------------------------------------------------------:|
| anonymous_enable=YES         | Allowing anonymous login?                                                          |
| anon_upload_enable=YES       | Allowing anonymous to upload files?                                                |
| anon_mkdir_write_enable=YES  | Allowing anonymous to create new directories?                                      |
| no_anon_password=YES         | Do not ask anonymous for password?                                                 |
| anon_root=/home/username/ftp | Directory for anonymous.                                                           |
| write_enable=YES             | Allow the usage of FTP commands: STOR, DELE, RNFR, RNTO, MKD, RMD, APPE, and SITE? |


## Footprinting FTP service

One of the most common tools to gather information about a FTP service is NMAP. NMAP has built in scripts(NSE) that are executed against the ports scanned if the flag -sC is passed. NMAP stores the scripts in `/usr/share/nmap/scripts/` and it has scripts for FTP servers. NMAP knows that a port is serving an FTP server when the banner after connecting the first time presents the FTP server details.

Other tools to look at the banner and connect ot the FTP server are netcat and telnet. However if the FTP server runs withs  SSL/TLS encryption we can use a tool called openssl, to communicate with the FTP server. The good thing abou the openssl is that we can look at the SSL certificate and gain more information abou the company certificate.  


## HTB Challenge
```
nmap -p- <IP>
nmap -p 21 -sC -sV <IP>
Version: InFreight FTP v1.1

ftp <IP>
Name: anonymous
password: <Press Enter>

ls 
get flag.txt

Flag: HTB{b7skjr4c76zhsds7fzhd4k3ujg7nhdjre}
```
