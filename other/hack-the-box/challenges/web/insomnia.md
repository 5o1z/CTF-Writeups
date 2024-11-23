---
description: Easy 🔮Web
cover: https://i.pinimg.com/564x/cf/cc/76/cfcc761e0210a6e972a31c7eed9c3527.jpg
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

# Insomnia

## Source code

The source code uses PHP code with the <mark style="color:red;">**`Codeigniter`**</mark> framework

{% hint style="info" %}
[**CodeIgniter**](https://codeigniter.com/) is a PHP full-stack web framework that is light, fast, flexible, and secure.
{% endhint %}

<figure><img src="../../../../.gitbook/assets/image (72).png" alt=""><figcaption></figcaption></figure>

## Web app

<figure><img src="../../../../.gitbook/assets/image (89).png" alt=""><figcaption></figcaption></figure>

The website allows us to sign in and sign up

Let's try to register a test account (<mark style="color:red;">**`test:test`**</mark>):

<figure><img src="../../../../.gitbook/assets/image (88).png" alt=""><figcaption></figcaption></figure>

As we can see, we can get the message above&#x20;

So let's take a look at how this registration system works

I went through the files in the <mark style="color:red;">**`.zip`**</mark> file And I found some files to be particularly noteworthy

As we can see the function Register in the <mark style="color:red;">**`UserController.php`**</mark> may be the operating principle of this registration system

<figure><img src="../../../../.gitbook/assets/image (91).png" alt=""><figcaption></figcaption></figure>

Let's analyze it a bit

<pre class="language-php"><code class="lang-php">$db->table("users")->insert([
    "username" => $username,
    "password" => $password,
    ]);

if ($db->affectedRows() > 0) {
<strong>    return $this->respond(
</strong>            "Registration successful for user: " . $username,200);
    } else {
        return $this->respond("Registration failed", 404);
</code></pre>

This code is the reason the above message appears.

To summarize, when you enter your username and password, the entire Register function will operate, they will check to see if your username and password are fully entered in the field or not. Check to see if they exist in the system.

Next, let's take a look at the other files in the <mark style="color:red;">**`.zip`**</mark> file

<figure><img src="../../../../.gitbook/assets/image (93).png" alt=""><figcaption></figcaption></figure>

This file looks interesting because it tells us that when we log in to the account we registered before, it will produce a welcome line. More specifically, if our username is <mark style="color:red;">**`administrator`**</mark>, it will display a flag

<figure><img src="../../../../.gitbook/assets/image (94).png" alt=""><figcaption></figcaption></figure>

Now let's look at the Login function:

<figure><img src="../../../../.gitbook/assets/image (95).png" alt=""><figcaption></figcaption></figure>

```php
if (!count($json_data) == 2) {
    return $this->respond("Please provide username and password", 404);
}
```

Check if the JSON data has the correct two fields (<mark style="color:red;">**username and password**</mark>). Otherwise, returns an error message with HTTP status code 404.&#x20;

But there's a funny thing here: it's equal to two, meaning the full username and password. This can give us an exploit to get the flag, which is to only use the username without using the password.

JSON example:

```json
{
"username": "test"
"password": "test"
}
```

&#x20;So the correct one must be:

```php
if (!count($json_data) != 2) {
    return $this->respond("Please provide username and password", 404);
}
```

This will be more consistent with the website's logic because if one of the two pieces of information is missing, you will not be able to log in

Next comes

```php
$key = (string) getenv("JWT_SECRET");
$iat = time();
$exp = $iat + 36000;
$headers = [
    "alg" => "HS256",
    "typ" => "JWT",
];
$payload = [
    "iat" => $iat,
    "exp" => $exp,
    "username" => $result["username"],
];
$token = JWT::encode($payload, $key, "HS256");
```

The above code performs the following tasks:

* Get the secret key from the <mark style="color:red;">**`JWT_SECRET`**</mark> environment variable. Set current time (<mark style="color:red;">**`iat`**</mark>) and expiration time (<mark style="color:red;">**`exp`**</mark>).&#x20;
* Create the header and content (<mark style="color:red;">**`payload`**</mark>) of the JWT.&#x20;
* Encode the body and header of the JWT to create a token using the JWT library

This is the code to create the user token

{% hint style="info" %}
Visit this [page](https://datatracker.ietf.org/doc/html/rfc7519) for more information about JWT
{% endhint %}

If we intend to counterfeit tokens, we should probably stop

<figure><img src="../../../../.gitbook/assets/image (96).png" alt=""><figcaption></figcaption></figure>

Let's analyze it a bit

```php
if (is_null($token)) {
    $view = Services::renderer()->setData([
        'content' => "I can't see the JWT token :("
    ])->render('ErrorPage');
    
    return Services::response()->setBody($view)->setStatusCode(403);
}
try {
    JWT::decode($token, new Key($key, 'HS256'));
} catch (\Exception $ex) {
    $view = Services::renderer()->setData([
        'content' => "Your JWT token is broken!!!"
    ])->render('ErrorPage');
    
    return Services::response()->setBody($view)->setStatusCode(403);
}
```

If the token does not exist, render an error page with the message "I can't see the JWT token :(" and return HTTP status code 403 (access prohibited).&#x20;

Decode the token and handle errors if the token is invalid:

* Decode token: Use JWT library to decode the token with a secret key and HS256 algorithm.&#x20;
* Error handling: If the decryption process encounters an error (for example, the token is invalid or expired), render an error page with the message "Your JWT token is broken!!!" and return HTTP status code 403.

In short, this method is used to check and validate JWT tokens in an application. If the token does not exist or is invalid, the user will receive an error page with HTTP status code 403.

## Exploit

As we analyzed above, in the login function of <mark style="color:red;">**`UserController.php`**</mark>, there exists a conditional statement that causes errors in its logic, so we can use it to exploit, by only using the username without the password. For example:

<figure><img src="../../../../.gitbook/assets/image (97).png" alt=""><figcaption></figcaption></figure>

This is not our desired outcome. But what if we remove the password variable?

<figure><img src="../../../../.gitbook/assets/image (98).png" alt=""><figcaption></figcaption></figure>

As you can see we have the token and Login Successful message

Do the same method with the administration to get the admin token

<figure><img src="../../../../.gitbook/assets/image (99).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
If you don't you Burp repeater, you can do the same method but just forward the request using Burp intercept
{% endhint %}

Use that token and send the next GET request to <mark style="color:red;">**`/index.php/profile`**</mark> to get the flag:

<figure><img src="../../../../.gitbook/assets/image (102).png" alt=""><figcaption></figcaption></figure>
