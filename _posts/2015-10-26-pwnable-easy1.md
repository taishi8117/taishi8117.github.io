---
layout : post
title : pwnable.kr Toddler's Bottle (easy) write-up
comments : true
---

[pwnable.kr](http://pwnable.kr) has a collection of pwning problems with a wide range of difficulty. This article is the write-up for Toddler's Bottle (easy) section.  

##fd  (10/26/2015)  

This is the easiest problem and is about Linux file descriptor. As given, connect to the server `ssh fd@pwnable.kr -p 2222`.  

```
fd@ubuntu:~$ ls -al
total 32
drwxr-x---  4 root fd   4096 Aug 20  2014 .
dr-xr-xr-x 55 root root 4096 Sep 20 23:22 ..
d---------  2 root root 4096 Jun 12  2014 .bash_history
-r-sr-x---  1 fd2  fd   7322 Jun 11  2014 fd
-rw-r--r--  1 root root  418 Jun 11  2014 fd.c
-r--r-----  1 fd2  root   50 Jun 11  2014 flag
dr-xr-xr-x  2 root root 4096 Aug 20  2014 .irssi
```

It seems that you can read the source code for the program `fd`.

```C
char buf[32];
int main(int argc, char* argv[], char* envp[]){
	if(argc<2){
		printf("pass argv[1] a number\n");
		return 0;
	}
	int fd = atoi( argv[1] ) - 0x1234;
	int len = 0;
	len = read(fd, buf, 32);
	if(!strcmp("LETMEWIN\n", buf)){
		printf("good job :)\n");
		system("/bin/cat flag");
		exit(0);
	}
	printf("learn about Linux file IO\n");
	return 0;

}
```

So it seems that when `buf == "LETMEWIN\n`, you can get the flag. Since `fd == 0` is `stdin`, all you need to do is to give 0x1234 (4660 in decimal) as argv[1] and input "LETMEWIN\n"  

```
fd@ubuntu:~$ ./fd 4660
LETMEWIN
good job :)
mommy! I think I know what a file descriptor is!!
```

Flag is: __mommy! I think I know what a file descriptor is!!__  
  

##collision (10/26/2015)  
Similar to `fd`, you can read the source code for the program `col`.  

```C
#include <stdio.h>
#include <string.h>
unsigned long hashcode = 0x21DD09EC;
unsigned long check_password(const char* p){
	int* ip = (int*)p;
	int i;
	int res=0;
	for(i=0; i<5; i++){
		res += ip[i];
	}
	return res;
}

int main(int argc, char* argv[]){
	if(argc<2){
		printf("usage : %s [passcode]\n", argv[0]);
		return 0;
	}
	if(strlen(argv[1]) != 20){
		printf("passcode length should be 20 bytes\n");
		return 0;
	}

	if(hashcode == check_password( argv[1] )){
		system("/bin/cat flag");
		return 0;
	}
	else
		printf("wrong passcode.\n");
	return 0;
}
```

At `int *ip = (int*)p`, `const char *p` is casted to `int *`. Since the size of `int` is 4 bytes, the size of `char` is 1 byte and the length of `passcode` is 20 bytes, you can read the flag when the sum of five `int` blocks is `0x21DD09EC`. Since `0x21DD09EC = 0x06C5CEC8 * 4 + 0x06C5CECC` and the system is little-endian, your injection code should be:  

```
col@ubuntu:~$ ./col $(perl -e 'print "\xc8\xce\xc5\x06"x4 . "\xcc\xce\xc5\x06"')
daddy! I just managed to create a hash collision :)
```

Flag is: __daddy! I just managed to create a hash collision :)__  
  

##flag (10/26/2015)  
This is a reversing problem. You can download the file `flag` [here](http://pwnable.kr/bin/flag).  


```
taishi@sirius:~/blackhat_python/ctf/pwnable.kr|master⚡
⇒  file flag
flag: ELF 64-bit LSB  executable, x86-64, version 1 (GNU/Linux), statically linked, stripped
taishi@sirius:~/blackhat_python/ctf/pwnable.kr|master⚡
⇒  ./flag
I will malloc() and strcpy the flag there. take it.
```

As you execute, you see a weird message. However, you can't analyze this program using GDB as shown below.

```
taishi@sirius:~/blackhat_python/ctf/pwnable.kr|master⚡
⇒  gdb -q flag            

warning: ~/.gdbinit.local: No such file or directory
Reading symbols from flag...(no debugging symbols found)...done.
gdb$ info files
Symbols from "/home/taishi/blackhat_python/ctf/pwnable.kr/flag".
gdb$ info functions
All defined functions:
```

This implies that some kind of anti-debugging techniques are applied to this program.  

```
taishi@sirius:~/blackhat_python/ctf/pwnable.kr|master⚡
⇒  strings flag | grep UPX
UPX!
$Info: This file is packed with the UPX executable packer http://upx.sf.net $
$Id: UPX 3.08 Copyright (C) 1996-2011 the UPX Team. All Rights Reserved. $
UPX!
UPX!
```

And here we go. `flag` file was packed with UPX. You can easily unpack it (you can download the official UPX packer/unpacker [here](http://upx.sourceforge.net/#downloadupx)).  

```
taishi@sirius:~/blackhat_python/ctf/pwnable.kr|master⚡
⇒  ./upx-3.91-i386_linux/upx -d flag 
Ultimate Packer for eXecutables
Copyright (C) 1996 - 2013
UPX 3.91        Markus Oberhumer, Laszlo Molnar & John Reiser   Sep 30th 2013

File size         Ratio      Format      Name
--------------------   ------   -----------   -----------
887219 <-    335288   37.79%  linux/ElfAMD   flag

Unpacked 1 file.
```

Then you can analyze it with GDB. 

```
taishi@sirius:~/blackhat_python/ctf/pwnable.kr|master⚡
⇒  gdb -q flag
gdb$ disassemble main
Dump of assembler code for function main:
0x0000000000401164 <+0>:	push   rbp
0x0000000000401165 <+1>:	mov    rbp,rsp
0x0000000000401168 <+4>:	sub    rsp,0x10
0x000000000040116c <+8>:	mov    edi,0x496658
0x0000000000401171 <+13>:	call   0x402080 <puts>
0x0000000000401176 <+18>:	mov    edi,0x64
0x000000000040117b <+23>:	call   0x4099d0 <malloc>
0x0000000000401180 <+28>:	mov    QWORD PTR [rbp-0x8],rax
0x0000000000401184 <+32>:	mov    rdx,QWORD PTR [rip+0x2c0ee5]        # 0x6c2070 <flag>
0x000000000040118b <+39>:	mov    rax,QWORD PTR [rbp-0x8]
0x000000000040118f <+43>:	mov    rsi,rdx
0x0000000000401192 <+46>:	mov    rdi,rax
0x0000000000401195 <+49>:	call   0x400320
0x000000000040119a <+54>:	mov    eax,0x0
0x000000000040119f <+59>:	leave  
0x00000000004011a0 <+60>:	ret    
End of assembler dump.
```

`mov rdx, QWORD PTR [rip+0x2c0ee5]` at \<main+32\> is interesting. Let's set the breakpoint right after (\<main+39\>), and analyze what was passed to rdx.  


```
gdb$ break *0x000000000040118b
Breakpoint 2 at 0x40118b
gdb$ c
Continuing.
gdb$ x/s $rdx
0x496628:	"UPX...? sounds like a delivery service :)"
```

Here it is! Flag is: __UPX...? sounds like a delivery service :)__
