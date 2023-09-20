---
layout: post
title: footprinting_nfs
categories:
- Information
tags:
- Enumeration
- Footprinting
- nfs
date: 2023-09-20 15:03 +0100
---

## Footprinting - NFS

Network File System (NFS) is a network file system developed by Sun Microsystems and has the same purpose as SMB. Its purpose is to access file systems over a network as if they were local. However, it uses an entirely different protocol. NFS is used between Linux and Unix systems. This means that NFS clients cannot communicate directly with SMB servers. NFS is an Internet standard that governs the procedures in a distributed file system. While NFS protocol version 3.0 (NFSv3), which has been in use for many years, authenticates the client computer, this changes with NFSv4. Here, as with the Windows SMB protocol, the user must authenticate.

| Version |                                                                                                                                 Features                                                                                                                                |
|:-------:|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------:|
| NFSv2   | It is older but is supported by many systems and was initially operated entirely over UDP.                                                                                                                                                                              |
| NFSv3   | It has more features, including variable file size and better error reporting, but is not fully compatible with NFSv2 clients.                                                                                                                                          |
| NFSv4   | It includes Kerberos, works through firewalls and on the Internet,  no longer requires portmappers, supports ACLs, applies state-based  operations, and provides performance improvements and high security. It  is also the first version to have a stateful protocol. |


NFS is based on the Open Network Computing Remote Procedure Call (ONC-RPC/SUN-RPC) protocol exposed on TCP and UDP ports 111, which uses External Data Representation (XDR) for the system-independent exchange of data. The NFS protocol has no mechanism for authentication or authorization. Instead, authentication is completely shifted to the RPC protocol's options. The authorization is taken from the available information of the file system where the server is responsible for translating the user information supplied by the client to that of the file system and converting the corresponding authorization information as correctly as possible into the syntax required by UNIX.

The most common authentication is via UNIX UID/GID and group memberships, which is why this syntax is most likely to be applied to the NFS protocol. One problem is that the client and server do not necessarily have to have the same mappings of UID/GID to users and groups, and the server does not need to do anything further. No further checks can be made on the part of the server. This is why NFS should only be used with this authentication method in trusted networks.

## Default Configuration

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

## ExportFS

```shell
$ echo '/mnt/nfs  10.129.14.0/24(sync,no_subtree_check)' >> /etc/exports
$ systemctl restart nfs-kernel-server 
$ exportfs

/mnt/nfs      	10.129.14.0/24
```
Here we share the folder `/mnt/nfs` to the subnet 10.129.14.0.
The exportfs command maintains the current table of exports for the NFS server. 

## Dangerous Settings

|     Option     |                                                      Description                                                     |
|:--------------:|:--------------------------------------------------------------------------------------------------------------------:|
| rw             | Read and write permissions.                                                                                          |
| insecure       | Ports above 1024 will be used.                                                                                       |
| nohide         | If another file system was mounted below an exported directory, this directory is exported by its own exports entry. |
| no_root_squash | All files created by root are kept with the UID/GID 0.                                                               |

## Footprinting NFS

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

## HTB Challenge

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


HTB{hjglmvtkjhlkfuhgi734zthrie7rjmdze}
HTB{8o7435zhtuih7fztdrzuhdhkfjcn7ghi4357ndcthzuc7rtfghu34}
```


