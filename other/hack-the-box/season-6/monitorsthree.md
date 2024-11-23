---
description: Linux 🔮 Medium
cover: https://i.pinimg.com/736x/17/ac/04/17ac04393268e560c203c8977a7430a6.jpg
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

# MonitorsThree

## Recon

### Nmap

```
PORT     STATE    SERVICE VERSION
22/tcp   open     ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 86:f8:7d:6f:42:91:bb:89:72:91:af:72:f3:01:ff:5b (ECDSA)
|_  256 50:f9:ed:8e:73:64:9e:aa:f6:08:95:14:f0:a6:0d:57 (ED25519)
80/tcp   open     http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: MonitorsThree - Networking Solutions
8084/tcp filtered websnp
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

The Nmap scan results indicate the following:

* **Port 22/tcp (SSH)**: This port is open and running SSH using OpenSSH 8.9p1 on Ubuntu. The system uses the SSH protocol version 2.0. The presence of SSH keys (ECDSA and ED25519) confirms secure remote access is enabled. This service is generally used for secure remote login and management.
* **Port 80/tcp (HTTP)**: This port is open and running an HTTP service using nginx 1.18.0 on Ubuntu. The web server is likely hosting a site or service called <mark style="color:red;">**`MonitorsThree - Networking Solutions`**</mark>.The Nginx version isn’t the latest, so it’s important to check for any security updates.
* **Port 8084/tcp**: This port is filtered, meaning Nmap couldn't determine the service running on it due to firewall or security rules blocking access.

The system is running on a Linux-based OS, likely Ubuntu, and is hosting both SSH and web services. Security measures should be checked, particularly for the outdated Nginx version and the filtered port.

### Web app

The main content area has a heading that reads, "The Best Networking Solutions," with a subheading that explains MonitorsThree's focus on providing top-tier networking solutions tailored to business needs. The text highlights the company's expertise in enhancing network infrastructure, improving security, and ensuring seamless connectivity.

<figure><img src="../../../.gitbook/assets/image (150).png" alt=""><figcaption></figcaption></figure>

[http://monitorsthree.htb/login.php](http://monitorsthree.htb/login.php) page:

<figure><img src="../../../.gitbook/assets/image (151).png" alt=""><figcaption></figcaption></figure>

If we provide a random username for the parameter here, it returns **"Unable to process the request, try again!"**. But if we provide a username admin, the server will then send a request to the user, which means the admin user exists.

Enumerate vHost:

<figure><img src="../../../.gitbook/assets/image (28).png" alt=""><figcaption></figcaption></figure>

[http://cacti.monitorsthree.htb/cacti/](http://cacti.monitorsthree.htb/cacti/) page:

<figure><img src="../../../.gitbook/assets/image (148).png" alt=""><figcaption></figcaption></figure>

<mark style="color:red;">**`Cacti`**</mark>, an open-source, web-based network monitoring and graphing tool, is widely utilized for tracking network traffic, server performance, and other critical infrastructure metrics through its robust data visualization capabilities. By leveraging the Simple Network Management Protocol (SNMP), Cacti efficiently gathers and presents real-time data from various network devices, offering comprehensive insights into network health and performance.

However, a significant security vulnerability, identified as <mark style="color:red;">**`CVE-2024-25641`**</mark>, has been discovered in Cacti versions before <mark style="color:red;">**`1.2.27`**</mark>. This vulnerability allows for arbitrary file write, which attackers could exploit to execute remote code on the affected systems. This **Remote Code Execution (RCE)** flaw presents a critical risk, as it could potentially allow unauthorized users to gain control over the network monitoring system, leading to unauthorized access, data manipulation, or even complete system compromise. Users are strongly advised to update to the latest version of Cacti to mitigate this vulnerability and protect their infrastructure from potential attacks.

## WWW-Data

There are two POST requests made to [http://monitorsthree.htb/login.php](http://monitorsthree.htb/login.php) and [http://monitorsthree.htb/forget\_password.php](http://monitorsthree.htb/forget_password.php). By intercepting and saving these requests using BurpSuite's proxy, we can effectively analyze them for potential SQL injection vulnerabilities. This process allows us to identify and exploit any weaknesses in the system, ensuring a thorough security assessment.

Use Burp Intercept to copy request to file:&#x20;

{% code title="request.txt" %}
```
POST /forgot_password.php HTTP/1.1
Host: monitorsthree.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 14
Origin: http://monitorsthree.htb
Connection: keep-alive
Referer: http://monitorsthree.htb/forgot_password.php
Cookie: PHPSESSID=8si6gvrh8d709tbjhkdcjr47a6
Upgrade-Insecure-Requests: 1

username=admin
```
{% endcode %}

Checking database name:&#x20;

{% code overflow="wrap" %}
```bash
sqlmap -r request.txt --dbs --batch --dump --level=1 --risk=1 --threads=10 --dbms=mysql --time-sec=1 --flush-session
```
{% endcode %}

<figure><img src="../../../.gitbook/assets/image (149).png" alt=""><figcaption></figcaption></figure>

Dump the <mark style="color:red;">**`monitorsthree_db`**</mark> table:

{% code overflow="wrap" %}
```bash
sqlmap -r request.txt --batch -T users -C username,password --where="username='admin'" -D monitorsthree_db --dump --level=3 --risk=3 --threads=10 --technique=T --skip=dbs,hostname --no-cast --no-escape --crawl=0 --fresh-queries --test-filter=timed
```
{% endcode %}

<figure><img src="../../../.gitbook/assets/image (26).png" alt=""><figcaption></figcaption></figure>

Decode that hash password and log to the page

Since it's [CVE-2024-25641](https://nvd.nist.gov/vuln/detail/CVE-2024-25641), we can use Metasploit to exploit it more easily:

<figure><img src="../../../.gitbook/assets/image (32).png" alt=""><figcaption></figcaption></figure>

Check the config files, such as <mark style="color:red;">**`/var/www/html/cacti/include/config.php`**</mark>, containing MySQL login credentials:

```php
#$rdatabase_type     = 'mysql';
#$rdatabase_default  = 'cacti';
#$rdatabase_hostname = 'localhost';
#$rdatabase_username = 'cactiuser';
#$rdatabase_password = 'cactiuser';
#$rdatabase_port     = '3306';
#$rdatabase_retries  = 5;
#$rdatabase_ssl      = false;
#$rdatabase_ssl_key  = '';
#$rdatabase_ssl_cert = '';
#$rdatabase_ssl_ca   = '';
```

Connect to database on the remote machine:

```
mysql -u cactiuser -p cacti
```

<figure><img src="../../../.gitbook/assets/image (33).png" alt=""><figcaption></figcaption></figure>

Cracking the password for <mark style="color:red;">**`marcus`**</mark> user:

<figure><img src="../../../.gitbook/assets/image (27).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (34).png" alt=""><figcaption></figcaption></figure>

## Marcus

We have successfully obtained the credentials for the user <mark style="color:red;">**`marcus`**</mark> , but we're unable to use them to remotely log in to the machine via SSH. This is because the SSH service on the machine is configured to accept only RSA keys for authentication, meaning that password-based logins are disabled. To gain access, we'll need to generate or obtain the appropriate RSA private key associated with Marcus's account, which will allow us to authenticate and establish an SSH connection to the target machine.

<figure><img src="../../../.gitbook/assets/image (36).png" alt=""><figcaption></figcaption></figure>

In the remote machine, use <mark style="color:red;">**`su marcus`**</mark> and copy the <mark style="color:red;">**`id_rsa`**</mark> file content:&#x20;

<figure><img src="../../../.gitbook/assets/image (37).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (38).png" alt=""><figcaption></figcaption></figure>

## Root

### Enumerate&#x20;

Enum with [**LinPEAS**](https://github.com/peass-ng/PEASS-ng/blob/master/linPEAS/README.md):&#x20;

<figure><img src="../../../.gitbook/assets/image (39).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (40).png" alt=""><figcaption></figcaption></figure>

Several database files have been discovered, and some appear to be associated with the popular backup solution, [**Duplicati**](https://duplicati.com/).

**Duplicati**, which we identified during the enumeration phase, is a widely used open-source backup solution designed to securely store encrypted backups across various platforms, including popular cloud services like Google Drive, Amazon S3, Microsoft OneDrive, and more. This software allows users to seamlessly back up files and directories to both remote and local storage destinations, with robust encryption ensuring data security both in transit and at rest.

Our investigation revealed that Duplicati typically operates on port **8200**, a detail that stood out during our initial scans. This port, often used by Duplicati, can be leveraged for further exploitation if found accessible. To begin exploiting this potential vulnerability, the first step involves setting up Port Forwarding. This will allow us to redirect traffic from this port, giving us access to Duplicati's web interface where we can further probe for weaknesses and potential entry points for unauthorized access.

For a comprehensive guide on exploiting **Duplicati**, you can refer to this detailed article that also highlights key aspects of the software's security features and common misconfigurations.

```bash
ssh -L 8200:127.0.0.1:8200 marcus@monitorsthree.htb -i id_rsa
```

{% hint style="info" %}
More information [**here**](https://medium.com/@STarXT/duplicati-bypassing-login-authentication-with-server-passphrase-024d6991e9ee)
{% endhint %}

Download the <mark style="color:red;">**`Duplicati-server.sqlite`**</mark> file located at <mark style="color:red;">**`/opt/duplicati/config`**</mark>:

Upon examining the database, we uncovered several credentials associated with Duplicati. However, these credentials are not straightforward copy-paste passwords, which means additional steps will be required to decode or manipulate them for access.

<figure><img src="../../../.gitbook/assets/image (41).png" alt=""><figcaption></figcaption></figure>

As demonstrated above, we have identified two critical pieces of information: the <mark style="color:red;">**`server-passphrase`**</mark> (encoded in Base64) and the <mark style="color:red;">**`server passphrase-salt`**</mark>. These elements are essential for us to either bypass the current authentication mechanism or generate a valid login password. By leveraging these details, we can potentially reverse-engineer or decrypt the passphrase required to gain access.

Additionally, by inspecting the source code of the login page, we can further our analysis. Specifically, by examining the JavaScript file responsible for the login process, located at <mark style="color:red;">**view-source:http://127.0.0.1:8200/login/login.js?v=2.0.8.1**</mark>, we can gain deeper insights into how the authentication logic is implemented. This may reveal potential vulnerabilities or weaknesses in the login mechanism that could be exploited to gain unauthorized access to the system

<pre class="language-javascript" data-title="login.js"><code class="lang-javascript"><strong>$(document).ready(function() {
</strong>    var processing = false;

    $('#login-button').click(function() {

        if (processing)
            return;

        processing = true;

        // First we grab the nonce and salt
        $.ajax({
            url: './login.cgi',
            type: 'POST',
            dataType: 'json',
            data: {'get-nonce': 1}
        })
        .done(function(data) {
            var saltedpwd = CryptoJS.SHA256(CryptoJS.enc.Hex.parse(CryptoJS.enc.Utf8.parse($('#login-password').val()) + CryptoJS.enc.Base64.parse(data.Salt)));

            var noncedpwd = CryptoJS.SHA256(CryptoJS.enc.Hex.parse(CryptoJS.enc.Base64.parse(data.Nonce) + saltedpwd)).toString(CryptoJS.enc.Base64);

            $.ajax({
                url: './login.cgi',
                type: 'POST',
                dataType: 'json',
                data: {'password': noncedpwd }
            })
            .done(function(data) {
                window.location = './';
            })
            .fail(function(data) {
                var txt = data;
                if (txt &#x26;&#x26; txt.statusText)
                    txt = txt.statusText;
                alert('Login failed: ' + txt);
                processing = false;
            });
        })
        .fail(function(data) {
            var txt = data;
            if (txt &#x26;&#x26; txt.statusText)
                txt = txt.statusText;

            alert('Failed to get nonce: ' + txt);
            processing = false;
        });

        return false;
    });

});
</code></pre>

By focusing on the variables <mark style="color:red;">**`var saltedpwd`**</mark> and <mark style="color:red;">**`var noncedpwd`**</mark>, we uncover the cryptographic operations used to authenticate users. The script utilizes these variables to compute a **SHA-256** hash by combining the user's password with a salt and a nonce. This process, known as salting and nonce-based authentication, significantly enhances security by ensuring that even if two users have the same password, their hashed values will be different due to the unique salt and nonce. This approach makes it much more difficult for attackers to crack the password, as they would need to know both the salt and the nonce in addition to the password itself. By analyzing how these variables are handled in the script, we can better understand the authentication mechanism and potentially identify ways to bypass or exploit it.

### Bypass Duplicati Authentication

We can use BurpSuite to review traffic to understand how the authentication works. The first POST request asks for a <mark style="color:red;">**`nounce`**</mark>:

<figure><img src="../../../.gitbook/assets/image (153).png" alt=""><figcaption></figcaption></figure>

If we check the response for this request in Repeater, we’ll find a JSON output containing the Nounce and the Salt. Notably, this data matches perfectly with the values we previously identified in the database file:&#x20;

<figure><img src="../../../.gitbook/assets/image (154).png" alt=""><figcaption></figcaption></figure>

Then the password we provided as the input will be encrypted as a new request:

<figure><img src="../../../.gitbook/assets/image (155).png" alt=""><figcaption></figcaption></figure>

Once we understand how this process works visually, we can attempt to generate a valid <mark style="color:red;">**`noncedpwd`**</mark> to log in. The steps involve: **Server-passphrase from DB > Base64 Decode > Convert it to Hex.**

```sql
-2||server-passphrase|Wb6e855L3sN9LTaCuwPXuautswTIQbekmMAr7BrK2Ho=
-2||server-passphrase-salt|xTfykWV1dATpFZvPhClEJLJzYA5A4L74hX7FK8XmY0I=
-2||server-passphrase-trayicon|85f1c87b-821f-463a-9980-fbced4f2ab54
-2||server-passphrase-trayicon-hash|VnE0XrLTcUUSNnnPu3f27J1ljZqDth3wLIep9tcLPeY=
```

<figure><img src="../../../.gitbook/assets/image (156).png" alt=""><figcaption></figcaption></figure>

With the Hex output in hand, we can now attempt to generate a valid password using the browser console. Below is the original definition of `noncedpwd` as found in the source code of <mark style="color:red;">**`login.js`**</mark>:

```javascript
var noncedpwd = CryptoJS.SHA256(CryptoJS.enc.Hex.parse(CryptoJS.enc.Base64.parse(data.Nonce) + saltedpwd)).toString(CryptoJS.enc.Base64);
```

Therefore, we are now ready to generate a password using the Server-passphrase. We still need to intercept the first POST request for a new Nonce, which is one-time for use. Forwarding the request and checking the <mark style="color:red;">**`session-nounce`**</mark> (require URL decode for use):

<figure><img src="../../../.gitbook/assets/image (157).png" alt=""><figcaption></figcaption></figure>

Now we can replace the newly generated Nonce and the hexed Server-passphrase (<mark style="color:red;">**`saltedpwd`**</mark>) to the variable <mark style="color:red;">**`noncedpwd`**</mark>, and run the command in **Browser Console**:

<figure><img src="../../../.gitbook/assets/image (158).png" alt=""><figcaption></figcaption></figure>

Replacing the password parameter with a new <mark style="color:red;">**`nouncedpwd`**</mark> and forward the request

{% hint style="info" %}
Don't forget to URL encode (Ctrl+U in BurpSuite) the password string before releasing the intercept button (Usually we don't need to URL encode our body text in **POST** request, but surely this case we must, we can identify this rule according to previous normal traffic).
{% endhint %}

Now we can bypass authentication and enter the Duplicati dashboard:

<figure><img src="../../../.gitbook/assets/image (159).png" alt=""><figcaption></figcaption></figure>

Now that we have access to Duplicati, which requires root privileges to execute advanced backup functions, we have several potential paths to escalate our privileges to root. By carefully reviewing the documentation, we can explore various methods such as leveraging vulnerabilities within the Duplicati setup, exploiting misconfigurations, or using specific commands that allow privilege escalation. Understanding these techniques provides us with multiple options to gain root access and perform the necessary backup operations.

We can use a backup function to get <mark style="color:red;">**`root.txt`**</mark> by following these steps:

**Step 1:** Click on **"Add Backup**"

**Step 2:** Select **"Configure a new backup"**

**Step 3:** Give the Backup a Name: And choose **"No encryption"** for convenience.

**Step 4:** Choose Backup Destination - Set it to a temporary saving of the backup files, such as <mark style="color:red;">**`/source/tmp`**</mark>:

<figure><img src="../../../.gitbook/assets/image (160).png" alt=""><figcaption></figcaption></figure>

* We are aware that Duplicati is running in docker, whose <mark style="color:red;">**`/`**</mark> is mounted on <mark style="color:red;">**`/source`**</mark>.

Step 5: Choose Backup Source - Add the path for the public key we copied before <mark style="color:red;">**`/source/root/root.txt`**</mark>:

Step 6: Disable **Auto Backup**

Step 7. Run the Backup - Once we've configured the backup, refresh the main page and run now immediately, until the "<mark style="color:red;">**`Last successful backup`**</mark>" is updated:

<figure><img src="../../../.gitbook/assets/image (161).png" alt=""><figcaption></figcaption></figure>

* Note: Just need to click run now 1 time

Step 8: Restore File

<figure><img src="../../../.gitbook/assets/image (162).png" alt=""><figcaption></figcaption></figure>

Select whether we want to restore the entire backup or specific files:

<figure><img src="../../../.gitbook/assets/image (163).png" alt=""><figcaption></figcaption></figure>

* Tick the <mark style="color:red;">**`root.txt`**</mark>

Choose the path for the restored files/directory. And check read/write permission because we want to read that root-owned target:

<figure><img src="../../../.gitbook/assets/image (164).png" alt=""><figcaption></figcaption></figure>

Once the backup is done, we will see this (otherwise check the warning or error logs for details):

<figure><img src="../../../.gitbook/assets/image (165).png" alt=""><figcaption></figcaption></figure>

Then go back to Marcus shell, we will find the newly added folder and <mark style="color:red;">**`root.txt`**</mark>
