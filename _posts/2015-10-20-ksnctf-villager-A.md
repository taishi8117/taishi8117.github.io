---
layout: post
title: ksnctf Villager A write-up
---

![placeholder](../image/vil_a.png "Large example image")
[ksnctf](http://ksnctf.sweetduet.info) is one of the beginner level CTF websites. This article is the write-up for the question 4 [Villager A](http://ksnctf.sweetduet.info/problem/4), in which you need to exploit the *Format String Vulnerability* to capture the flag!  

# What is *Format String Vulnerability*?
In C standard library, there exists a number of *format string* functions. One of the most common examples includes `printf()` function, which you're most likely familar with. 

