---
layout: post
title: Ffuf cheatsheet
date: 2024-02-19 17:45 +0000
categories:
- Information
tags:
- ffuf
- DNS
- fuzzing
---


## Directory Fuzzing

```bash
ffuf -w ~/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ  -u http://94.237.53.58:38606/FUZZ
```
## Page Fuzzing

Web pages normally have an extension identifying the programming language they were developed.
- If the server is apache, then it may be `.php`
- If the server is IIS, the it could be `.asp` or `.aspx`

A typical main page is "index" so we can use web-extensions.txt wordlist against it and try to identify the extension used.

```bash
ffuf -w ~/SecLists/Discovery/Web-Content/web-extensions.txt:FUZZ  -u http://94.237.53.58:38606/indexFUZZ
```
```bash
ffuf -w ~/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ1  -u http://94.237.53.58:38606/blog/FUZZ1.php
```

## Recursive Fuzzing

Recursive Fuzzing essenialy fuzz directories, subdirectories and pages recursively creating anew scan every time it finds a new path.

```bash
ffuf -w ~/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://94.237.58.211:33399/FUZZ -recursion -recursion-depth 1 -e .php -v
```


## Sub-Domains Fuzzing

```bash
ffuf -w ~/SecLists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u https://FUZZ.inlanefreight.com/
```


## Vhosts Fuzzing

```bash
ffuf -w ~/SecLists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://academy.htb:PORT/ -H 'Host: FUZZ.academy.htb'
```

## GET request Fuzzing

```bash
ffuf -w ~/SecLists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://academy.htb:37024/admin/admin.php?FUZZ=key
```

## POST request Fuzzing

```bash
ffuf -w ~/SecLists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded'
```

## Value fuzzing

### Create a list of ids
```bash
for i in $(seq 1 1000); do echo $i >> ids.txt; done
```

### Fuzz POST request ids

```bash
ffuf -w ~/ids.txt:FUZZ -u http://admin.academy.htb:37024/admin/admin.php -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs 798
```

