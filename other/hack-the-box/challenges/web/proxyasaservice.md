---
description: Easy 🔮 Web
cover: https://i.pinimg.com/564x/ce/ea/40/ceea40f94a57049df1a6c6291da3f9e4.jpg
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

# ProxyAsAService

## Source code

<figure><img src="../../../../.gitbook/assets/image (122).png" alt=""><figcaption></figcaption></figure>

From the code above we know which URLs are not allowed. Besides, we are only allowed to access the <mark style="color:red;">**`/environment`**</mark> endpoint when we are at 127.0.0.1

<figure><img src="../../../../.gitbook/assets/image (123).png" alt=""><figcaption></figcaption></figure>

Let's continue:&#x20;

<figure><img src="../../../../.gitbook/assets/image (124).png" alt=""><figcaption></figcaption></figure>

We can see that <mark style="color:red;">**`SITE_NAME`**</mark> is reddit.com, meaning the <mark style="color:red;">**`target_url`**</mark> will be <mark style="color:red;">**`http://reddit.com{url}`**</mark>

Nothing will happen if  <mark style="color:red;">**`reddit.com`**</mark> has a (<mark style="color:red;">**`/`**</mark>) after it. But in this context, it doesn't, which gives us the idea of ​​creating a redirection attack&#x20;

## Exploit

To try exploiting this website, we can start with trial access to <mark style="color:red;">**`http://1.1.1.1 &@2.2.2.2`**</mark> it will bring us to  <mark style="color:red;">**`http://2.2.2.2`**</mark>.&#x20;

So if we append <mark style="color:red;">**`@website`**</mark> at the end of the target URL, it will redirect us to that website.

As we know the localhost, 127.0.0.1... has been restricted. So we can try 0.0.0.0 with port 1337 (what we see in the <mark style="color:red;">**`run.py`**</mark> file) to access <mark style="color:red;">**`/environment`**</mark> endpoint which in the debug route

{% hint style="info" %}
<mark style="color:red;">**`0.0.0.0:1337`**</mark> is the machine local
{% endhint %}

So the final payload is <mark style="color:red;">**`http://94.237.59.199:38687/?url=@0.0.0.0:1337/debug/environment`**</mark>

<figure><img src="../../../../.gitbook/assets/image (127).png" alt=""><figcaption></figcaption></figure>
