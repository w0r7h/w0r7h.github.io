---
layout: post
title: Footprinting - SMB
categories:
- Information
tags:
- Enumeration
- Footprinting
- smb
date: 2023-09-20 14:39 +0100
---

## Footprinting - SMB

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

## Dangerous Settings


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

## Footprinting SMB service

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

## Other Tools

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

## HTB Challenge

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
