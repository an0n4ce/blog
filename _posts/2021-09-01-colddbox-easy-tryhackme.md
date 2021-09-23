---
title: ColddBox:Easy - TryHackMe
author: Vishnu Sudhakaran
date: 2021-09-01 23:30:00 +0530
categories: [Boot2Root, TryHackMe]
tags: [ security, box, wordpress, privesc, linux, gtfobin ]
---

![](/assets/img/posts/coldd/1.png)

Room : [https://tryhackme.com/room/colddboxeasy](https://tryhackme.com/room/colddboxeasy)

Author : [@martinfriasc](https://twitter.com/martinfriasc)

## Reconnaissance:

Let's start with `nmap` scan.

![](/assets/img/posts/coldd/2.png)

Only port 80 is open lets's check it.

![](/assets/img/posts/coldd/3.png)

We can see server is running `wordpress` with an old version `4.1.31`.

## Enumeration

From `Gobuster` result we get directory called `/hidden`

![](/assets/img/posts/coldd/6.png)
![](/assets/img/posts/coldd/7.png)

From the directory we get some usernames maybe.
Let's run the `wpscan`

![](/assets/img/posts/coldd/4.png)
![](/assets/img/posts/coldd/5.png)

So users confirmed, Give a try login with bruteforce method.

![](/assets/img/posts/coldd/8.png)

We get Username:Password, let's login via `/wp-login.php`

And add php-reverse shell on `404 Template` and call it.

![](/assets/img/posts/coldd/9.png)
![](/assets/img/posts/coldd/10.png)

It's a wordpress server so let's check for `/wp-config.php` file to get credentials.

![](/assets/img/posts/coldd/11.png)

Now we can Switch user to `c0ldd` and get user flag.

![](/assets/img/posts/coldd/12.png)

## Privilege Escalation:

Running `sudo -l` we see that we can run some certain binaries as the root user.

![](/assets/img/posts/coldd/13.png)

Here iam using `chmod` which will changes permission of a binary file or executable,

Add a SUID bit on bash and get a root shell that way `sudo chmod +s /bin/bash`

![](/assets/img/posts/coldd/14.png)

Now run `/bin/bash -p` to get root shell

![](/assets/img/posts/coldd/15.png)

## Thank you for reading my writeup!
