---
layout : post
title : Awake Security BlackHat 2017 Soirée PCAP Challenge Write-up - Analyzing a PCAP file in a hard way
comments : true
---

Hi! It's been a real while since the last post (I said the same in the last post)...
But this summer, I'm working in one of the security teams at Facebook as an intern,
and one of my colleagues told me about an interesting PCAP analysis challenge.

Solving this was a ticket for an after party for this year's BlackHat organized by [Awake Security](http://fortune.com/2017/07/17/cyber-security-startup-awake/).  
Although I couldn't go to the BlackHat this year nor the after party, I found this challenge
very interesting and worth a post.

If anyone wants to try the challenge, [this](/download/awake/awake-puzzle-bh2017.pcap) is
the actual PCAP file downloaded from [this registration form](https://docs.google.com/forms/d/e/1FAIpQLSd0yUXDMdPwqPSU9nnToG01qDPrOIL1R_snp3yT_Bj1wpk2cA/viewform).

Let's dive in!

-----------

## Reading the instruction

When you open up the PCAP file, you'll notice that there's a HTTP GET request to `/instructions.hello`. 
Let's see what's in there first by "Follow HTTP Stream".

![placeholder](/image/awake/http_get.png "Follow HTTP Stream")  
![placeholder](/image/awake/readme.png "instruction.hello")  

Well, it looks like a normal instruction except one thing:
`Accept-Encoding: gzip, xor`. Never heard of `xor` encoding for HTTP request,
maybe a clue for the flag.

## Weird stuff in mDNS

When you look through other frames, you'll notice a few [mDNS](https://en.wikipedia.org/wiki/Multicast_DNS) packets buried in a bunch of TCP packets.
But the search queries definitely don't look legit, like `alert.msg`, `cyberchef.helps` and `key.version`? They might be another clue for the flag!

![placeholder](/image/awake/mdns.png "Weird message in mDNS packets")  

## Are they really just TCP?

You might be stuck at this point (well, I was), as what's left were five similar
TCP connections between `75.101.121.222:44344` and `192.168.1.116`
in which you can find little human readable strings, except for "Agbogbloshie" and "Golden Showers Far East Import" (WTF?).

![placeholder](/image/awake/cant_read.png "Can you read this?")  

But if you look closely enough, you'll realize that the data payload of many of these packets
starts with the bytestring `16 03 03 00`.

![placeholder](/image/awake/data.png "16 03 03 00")

Unfortunately, I don't know the header bytestring of every common protocol by heart,
so I just [googled it](https://www.google.com/search?site=&source=hp&q=16+03+03+00)
and found that it's a header for TLS packet!
([This web page](http://blog.fourthbit.com/2014/12/23/traffic-analysis-of-an-ssl-slash-tls-session) has a great explanation for the protocol format.)

Now, all you need to do is to decode these packets as SSL stream.

![placeholder](/image/awake/decode.png "Decode as SSL")


## Finding the flag

Once you decode them as SSL and go through them, you'll realize one weird thing:
`Encrypted Alert` in the frame 524.

![placeholder](/image/awake/alert.png "Encrypted Alert")

If you remember the earlier clue `alert.message`, you'll realize this packet probably has some clue. 
The packet header says the message length is 308 (or `0x0134` if you prefer hex),
so I extracted the message part (from the bytestring `50 4b 03` to the end, which is
right after the length header)
and use [Cyberchef](https://gchq.github.io/CyberChef/) to figure out what it is.
(`cyberchef.helps` was another clue from mDNS packet.)

When you use [the Detect File Type operation](http://bit.ly/2hNEYae), you'll see that
this is a zip file! 

![placeholder](/image/awake/its_zip.png "It's a zip!")

Cool, let's just unzip it --- this is [the unzipped file](http://bit.ly/2hLf1I6) in Cyberchef.

![placeholder](/image/awake/unzipped.png "Can you read this?")

Umm, it's still not really readable... But remember, you still have two remaining clues:
`key.version` from mDNS and `xor` from the instruction page. 


Aha, maybe XORing this file with the Encrypted Alert's version (`0x00de`)?

![placeholder](/image/awake/flag.png "Flag!!")

And here it is, found the flag!
