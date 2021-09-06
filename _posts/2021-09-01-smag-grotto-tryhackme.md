---
title: Smag Grotto - TryHackMe
author: Vishnu Sudhakaran
date: 2021-09-01 22:30:00 +0530
categories: [TryHackMe]
tags: [ easy, wireshark, privesc, linux, gtfobin ]
---

![](/assets/img/posts/smag/1.png)

Room : [https://tryhackme.com/room/smaggrotto](https://tryhackme.com/room/smaggrotto)

Author : [@jakeyee](https://tryhackme.com/p/jakeyee)

## Reconnaissance:

Let's start with `nmap` scan.

![](/assets/img/posts/smag/2.png)

Discoverd 2 Ports, Let's check port 80.

![](/assets/img/posts/smag/3.png)

## Enumeration:

From `gobuster` result we will get directory called `/mail`

![](/assets/img/posts/smag/4.png)

![](/assets/img/posts/smag/5.png)

It has a `pcap` file to download, let's analize it with `wireshark`.

![](/assets/img/posts/smag/6.png)

Taking good look at it, We can find HTTP POST request to `development.smag.thm/login.php` and also username and password that used to login on clear text.

Now add `development.smag.thm` to our `/etc/hosts` file.

![](/assets/img/posts/smag/7.png)

![](/assets/img/posts/smag/8.png)

There is a login portal, So now we can login with credentials we found on `.pcap` file. and it will redirect to `/admin.php`.

![](/assets/img/posts/smag/9.png)

its a webshell, So let's input [reverse shell](https://www.revshells.com/) command to get reverse connection.

![](/assets/img/posts/smag/10.png)

Spawn a python shell using ; `python3 -c 'import pty;pty.spawn("/bin/bash")'` 

Enumerating further more we can see interesting job running on `/etc/crontab`

![](/assets/img/posts/smag/11.png)

Here we can manipulate that to get user privilege.

![](/assets/img/posts/smag/12.png)

We have write permission, So we can add our public key to `/opt/.backups/jake_id_rsa.pub.backup` get User jake.

![](/assets/img/posts/smag/13.png)

Now we can login via `SSH` to user `jake` without password.

![](/assets/img/posts/smag/14.png)

## Privilege Escalation:

Let's check sudo privilege for `jake` with command `sudo -l`

![](/assets/img/posts/smag/15.png)

Now get exploit on [GTFObins](https://gtfobins.github.io/gtfobins/apt-get/) for `/usr/bin/apt-get` to get root shell.
```bash
sudo apt-get update -o APT::Update::Pre-Invoke::=/bin/sh
```
![](/assets/img/posts/smag/16.png)

### Happy Hacking!!
