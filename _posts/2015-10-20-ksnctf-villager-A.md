---
layout: post
title: ksnctf Villager A write-up
---

![placeholder](../image/vil_a.png "Large example image")
[ksnctf](http://ksnctf.sweetduet.info) is one of the beginner level CTF websites. This article is the write-up for the question 4 [Villager A](http://ksnctf.sweetduet.info/problem/4), in which you need to exploit the *Format String Vulnerability* to capture the flag!  

### Write-up
1. Connect
Using given information, access to the server `ssh -p 10022 q4@ctfq.sweetduet.info`  
In the server, you can find
```bash
[q4@localhost ~]$ ls -al
total 36
drwxr-xr-x.  2 root root 4096 May 22  2012 .
drwxr-xr-x. 17 root root 4096 Oct  6  2014 ..
-rw-r--r--.  1 root root   18 Dec  2  2011 .bash_logout
-rw-r--r--.  1 root root  176 Dec  2  2011 .bash_profile
-rw-r--r--.  1 root root  124 Dec  2  2011 .bashrc
-r--------.  2 q4a  q4a    22 May 22  2012 flag.txt
-rwsr-xr-x.  1 q4a  q4a  5857 May 22  2012 q4
-rw-r--r--.  1 root root  151 Jun  1  2012 readme.txt
```
