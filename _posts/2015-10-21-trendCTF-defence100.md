---
layout: post
title : Trend Micro CTF 2015 - Analysis Defence 100 Write-up
comments: true
---

[Trend Micro CTF 2015](http://www.trendmicro.co.jp/jp/sp/ctf2015_en/index.html) was held on 9/26-9/27 2015. Although I could not fully participate, I will post some write-ups. This article is a write-up for __Analysis Defence 100__, in which you need to analyze a malware-like program called `vonn` to capture the flag. It can be found [here](https://www.dropbox.com/s/n3tfamtxwuobpte/vonn.zip?dl=0).  
After decompressing vonn.zip, you can find `vonn` executable (ELF 64-bit)  

```
taishi@sirius:~/trend_ctf|⇒  file vonn 
vonn: ELF 64-bit LSB  executable, x86-64, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=7f89c2bb36cc9d0882a4980a99d44a7674fb09e2, not stripped
```

When I run `vonn`, it seems to check if it is executed on VM.  

```
taishi@sirius:~/trend_ctf|⇒  ./vonn 
You are not on VMM
taishi@sirius:~/trend_ctf|⇒
```

I was quite confused because I was running it on virtual machine actually (Parallels). Later, I found out that some other people could actually capture the flag just by executing `vonn` on VM. But it didn't happen to me (maybe because I'm using Parallels not VMWare). By the way, Trend Micro is a Japanese anti-virus software company working a lot on VM detection, and I guess that's why VM detection is involved in this problem. Let's disassemble `main`.  

```
gdb$ disassemble
Dump of assembler code for function main:
0x00400b8d <+0>:	push   rbp
0x00400b8e <+1>:	mov    rbp,rsp
=> 0x00400b91 <+4>:	sub    rsp,0xd0
0x00400b98 <+11>:	mov    DWORD PTR [rbp-0xc4],edi
0x00400b9e <+17>:	mov    QWORD PTR [rbp-0xd0],rsi
0x00400ba5 <+24>:	cpuid
0x00400ba7 <+26>:	rdtsc  
0x00400ba9 <+28>:	mov    QWORD PTR [rbp-0xb8],rax
0x00400bb0 <+35>:	mov    QWORD PTR [rbp-0xb0],rdx
0x00400bb7 <+42>:	rdtsc  
...
0x00400cb4 <+295>:	mov    rax,rdx
0x00400cb7 <+298>:	mov    QWORD PTR [rbp-0x8],rax
0x00400cbb <+302>:	mov    rax,QWORD PTR [rbp-0x18]
0x00400cbf <+306>:	cmp    rax,QWORD PTR [rbp-0x10]
0x00400cc3 <+310>:	je     0x400cfc <main+367>
0x00400cc5 <+312>:	mov    rax,QWORD PTR [rbp-0x10]
0x00400cc9 <+316>:	cmp    rax,QWORD PTR [rbp-0x8]
0x00400ccd <+320>:	je     0x400cfc <main+367>
0x00400ccf <+322>:	mov    rax,QWORD PTR [rbp-0x18]
0x00400cd3 <+326>:	cmp    rax,QWORD PTR [rbp-0x8]
0x00400cd7 <+330>:	je     0x400cfc <main+367>
0x00400cd9 <+332>:	mov    edi,0x401100		<== "You are on VMM!"
0x00400cde <+337>:	call   0x400990 <puts@plt>
0x00400ce3 <+342>:	mov    rax,QWORD PTR [rbp-0xd0]
0x00400cea <+349>:	mov    rax,QWORD PTR [rax]
0x00400ced <+352>:	mov    rdi,rax
0x00400cf0 <+355>:	mov    eax,0x0
0x00400cf5 <+360>:	call   0x400d08 <ldex()>
0x00400cfa <+365>:	jmp    0x400d06 <main+377>
0x00400cfc <+367>:	mov    edi,0x401110		<== "You are not on VMM"
0x00400d01 <+372>:	call   0x400990 <puts@plt>
0x00400d06 <+377>:	leave  
0x00400d07 <+378>:	ret
```

```
gdb$ x/s 0x401110
0x401110:	"You are not on VMM"
gdb$ x/s 0x401100
0x401100:	"You are on VMM!"
```

It seems that `vonn` first checks if the program is run on VM (from \<main+24\> onwards). Then, if it's run on VM, `ldex()` function is called at \<main+360\>. If not, it just exits after printing out "You are not on VMM" message.  
My instinct is that `ldex()` is responsible for capturing the flag. So let's disassemble `ldex()` too.

```
gdb$ disassemble ldex
[...]
0x00400d82 <+122>:	mov    DWORD PTR [rbp-0xec],eax
0x00400d88 <+128>:	mov    esi,0x42
0x00400d8d <+133>:	mov    edi,0x401123			<== "/tmp/...,,,...,,"
0x00400d92 <+138>:	mov    eax,0x0
0x00400d97 <+143>:	call   0x400a90 <open@plt>	<== creating /tmp/...,,,...,,
0x00400d9c <+148>:	mov    DWORD PTR [rbp-0xe8],eax
0x00400da2 <+154>:	lea    rdx,[rbp-0xd0]
0x00400da9 <+161>:	mov    eax,DWORD PTR [rbp-0xec]
0x00400daf <+167>:	mov    rsi,rdx
0x00400db2 <+170>:	mov    edi,eax
0x00400db4 <+172>:	call   0x4010e0 <fstat>
0x00400db9 <+177>:	mov    rax,QWORD PTR [rbp-0xa0]
0x00400dc0 <+184>:	cmp    rax,0x5000
0x00400dc6 <+190>:	jle    0x400eb5 <ldex()+429>
[...]
0x00400e6a <+354>:	mov    rcx,rdx
0x00400e6d <+357>:	mov    rdx,rdi
0x00400e70 <+360>:	mov    rdi,rax
0x00400e73 <+363>:	mov    eax,0x0
0x00400e78 <+368>:	call   0x400f26 <Decrypt>	<== call Decrypt()
0x00400e7d <+373>:	mov    rax,QWORD PTR [rbp-0xa0]
0x00400e84 <+380>:	sub    rax,0x5000
0x00400e8a <+386>:	mov    rdx,rax
0x00400e8d <+389>:	mov    rcx,QWORD PTR [rbp-0xd8]
0x00400e94 <+396>:	mov    eax,DWORD PTR [rbp-0xe8]
0x00400e9a <+402>:	mov    rsi,rcx
0x00400e9d <+405>:	mov    edi,eax
0x00400e9f <+407>:	call   0x400a80 <write@plt>
0x00400ea4 <+412>:	mov    DWORD PTR [rbp-0xe4],eax
0x00400eaa <+418>:	cmp    DWORD PTR [rbp-0xe4],0x0
0x00400eb1 <+425>:	jns    0x400ed3 <ldex()+459>
0x00400eb3 <+427>:	jmp    0x400ec9 <ldex()+449>
0x00400eb5 <+429>:	mov    edi,0x401123
0x00400eba <+434>:	call   0x4009f0 <unlink@plt>	<== unlink /tmp/...,,,...,,
0x00400ebf <+439>:	mov    edi,0xffffffff
0x00400ec4 <+444>:	call   0x4009a0 <exit@plt>
0x00400ec9 <+449>:	mov    edi,0xffffffff
0x00400ece <+454>:	call   0x4009a0 <exit@plt>
[...]
```

```
gdb$ x/s 0x401123
0x401123:	"/tmp/...,,,...,,"
```

As I examined, `vonn` creates a malware-like file called `/tmp/...,,,...,,`, then call `Decrypt` and unlink (delete) it before `ldex()` returns. It seems that `/tmp/...,,,...,,` would be the key to capture the flag.  

Now, what I need to do is by using GDB to somehow make the program executes `ldex()` function. Actually, it seems that `rdtsc` (time stamp counter) is responsible for determining whether it is on VM. If the number of cycles is small, the program recognizes that it is run on VM.  

```
0x00400ba5 <+24>:	cpuid  
0x00400ba7 <+26>:	rdtsc  
0x00400ba9 <+28>:	mov    QWORD PTR [rbp-0xb8],rax
0x00400bb0 <+35>:	mov    QWORD PTR [rbp-0xb0],rdx
0x00400bb7 <+42>:	rdtsc							<== time stamp counter
0x00400bb9 <+44>:	mov    QWORD PTR [rbp-0xa8],rax
0x00400bc0 <+51>:	mov    QWORD PTR [rbp-0xa0],rdx
0x00400bc7 <+58>:	rdtsc  
0x00400bc9 <+60>:	mov    QWORD PTR [rbp-0x98],rax
0x00400bd0 <+67>:	mov    QWORD PTR [rbp-0x90],rdx
0x00400bd7 <+74>:	rdtsc  
0x00400bd9 <+76>:	mov    QWORD PTR [rbp-0x88],rax
```

That means that if I manually `nexti` relatively slowly from \<main+26\> to \<main+74\> in GDB, the program thinks it's running on VM, thus `ldex()` should be executed.  
  
Now, I'm inside `ldex()`. All I need to do is to read `/tmp/...,,,...,,`. Set breakpoint right before `unlink()` (at 0x00400eba).  

```
gdb$ break *0x00400eba
Breakpoint 3 at 0x400eba
gdb$ c
Continuing.
process 15200 is executing new program: /tmp/...,,,...,,
[...]
```

Open another terminal, and read the file. 

```
taishi@sirius:~/trend_ctf|⇒  file /tmp/...,,,...,, 
/tmp/...,,,...,,: ELF 64-bit LSB  executable, x86-64, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0caffac67e07fa450f8da2f6ed2579e8de43ea46, not stripped
```

It seems that `/tmp/...,,,...,,` is an executable. Running it...  

```
taishi@sirius:~/trend_ctf|⇒  /tmp/...,,,...,, 
TMCTF{ce5d8bb4d5efe86d25098bec300d6954}
```

Got the flag! __TMCTF{ce5d8bb4d5efe86d25098bec300d6954}__  
