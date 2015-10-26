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

{% highlight C %}
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
{% endhighlight %}

So it seems that
