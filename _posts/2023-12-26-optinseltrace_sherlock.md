---
title: Operation Tinsel Trace 2023 - Writeups
time: 2023-12-26 12:00:00
categories: [sherlocks]
tags: [operation,htb]
image: 
---

Operation Tinsel Trace consists of five exclusive Sherlocks following the compromise of Father Christmas’s festive operations by a formidable, infamous adversary: The Grinch! As the festive season approaches, the North Pole is buzzing with activity. But not all is merry in Santa's workshop as a series of sophisticated cyber attacks threaten to disrupt Christmas. In Operation Tinsel Trace, you will impersonate Santa's chosen elf to lead the cybersecurity response team and unravel the tangled tinsel of these incidents. It all starts with an elf named "Elfin" acting rather suspiciously lately. He's been working at odd hours and seems to be bypassing some of Santa's security protocols. The Grinch got a little bit too tipsy on egg nog and made mention of an insider elf! You will start by running an audit of Elfin’s workstation and email communications. Operation Tinsel Trace will lead you inside the technology of Santa’s tech, configuration, logs, and servers until, at a certain point, everything seems to be doomed. Will you be able to recover from this advanced attack?

## OpTinselTrace-1
### Scenario
An elf named "Elfin" has been acting rather suspiciously lately. He's been working at odd hours and seems to be bypassing some of Santa's security protocols. Santa's network of intelligence elves has told Santa that the Grinch got a little bit too tipsy on egg nog and made mention of an insider elf! Santa is very busy with his naughty and nice list, so he’s put you in charge of figuring this one out. Please audit Elfin’s workstation and email communications.

### Task 1 
Question: What is the name of the email client that Elfin is using?

Answer: `eM client`

Since the question is asking for Elfin's email client, it is probably a program downloaded in his machine. Hence, I went ahead to `\optinseltrace1\TriageData\C\users\Elfin\Appdata` and looked around both the Local and Roaming directory. In the Roaming directory, `eM client` was found.

![elf1](https://github.com/warlocksmurf/HTB-writeups/assets/121353711/e5c6d693-0ff3-4c2c-baba-a171661c3781)

### Task 2  
Question: What is the email the threat is using?

Answer: `definitelynotthegrinch@gmail.com`

One easy way to solve this whole Sherlock is to just utilize `eM client` to search for clues about Elfin and the threat actor. After downloading `eM client` and importing the configuration files, we can see the Grinch sending an email to Elfin.

![elf2](https://github.com/warlocksmurf/HTB-writeups/assets/121353711/6caa0bd8-5b3f-4f0f-9469-95befbb47208)

### Task 3 
Question: When does the threat actor reach out to Elfin?

Answer: `2023-11-27 17:27:26`

Similar to Task 2, just open up the replies (make sure the time is converted to UTC).

![elf3](https://github.com/warlocksmurf/HTB-writeups/assets/121353711/d25e4cc9-6ff3-4da9-9a1d-0c9e5ca04bda)

### Task 4 
Question: What is the name of Elfins boss?

Answer: `elfuttin bigelf`

Pretty straightforward, just look through the emails.

![elf4](https://github.com/warlocksmurf/HTB-writeups/assets/121353711/6ec4bac0-1d22-46ac-afc8-3f702a62a5c1)

### Task 5 
Question: What is the title of the email in which Elfin first mentions his access to Santas special files?

Answer: `Re: work`

Pretty straightforward, just look through the emails and focus on the subject line.

![elf5](https://github.com/warlocksmurf/HTB-writeups/assets/121353711/23ac4ce4-cbc9-44eb-bde2-7cf41a50597c)

### Task 6 
Question: The threat actor changes their name, what is the new name + the date of the first email Elfin receives with it?

Answer: `wendy elflower, 2023-11-28 10:00:21`

Look through the emails for suspicious users and open up the replies. The threat actor can be identified as `wendy elflower`.

![elf6](https://github.com/warlocksmurf/HTB-writeups/assets/121353711/323d2e59-0b8f-4060-b8ef-35afd75f9a78)

### Task 7
Question: What is the name of the bar that Elfin offers to meet the threat actor at?

Answer: `SnowGlobe`

Pretty straightforward, just look through the emails from Elfin and `wendy elflower`.

![elf7](https://github.com/warlocksmurf/HTB-writeups/assets/121353711/efd3097c-2dd3-4fb5-b1d8-4fda193d1a6c)

### Task 8
Question: When does Elfin offer to send the secret files to the actor?

Answer: `2023-11-28 16:56:13`

Similar to Task 7.

![elf8](https://github.com/warlocksmurf/HTB-writeups/assets/121353711/4c464425-3d39-4ee4-9174-2975c2c268a6)

### Task 9
Question: What is the search string for the first suspicious google search from Elfin? (Format: string)

Answer: `how to get around work security`

Since the question asked about Google search, I assumed we have to analyze the Elfin's browser history on Google. So I extracted several Chrome artifacts located in `\optinseltrace1\TriageData\C\users\Elfin\Appdata\Local\Google\Chrome\User Data\Default\` and analyzed them using DB Browser. There were several suspicious search results found in the `History` file.

![elf9](https://github.com/warlocksmurf/HTB-writeups/assets/121353711/310bac04-9440-41d5-88f3-57cc8ca9568c)

### Task 10
Question: What is the name of the author who wrote the article from the CIA field manual?

Answer: `Joost Minnaar`

Similar to Task 9, you can find the article search results.

![elf10](https://github.com/warlocksmurf/HTB-writeups/assets/121353711/a77cb620-31ea-4402-903d-b2d2df597fe8)

![elf10 1](https://github.com/warlocksmurf/HTB-writeups/assets/121353711/6e956313-279f-4e3b-8f78-2025d5d4fee8)

### Task 11
Question: What is the name of Santas secret file that Elfin sent to the actor?

Answer: `santa_deliveries.zip`

The secret file can be found in Elfin's machine located in `\optinseltrace1\TriageData\C\users\Elfin\Appdata\Roaming\top-secret\`

### Task 12
Question: According to the filesystem, what is the exact CreationTime of the secret file on Elfins host?

Answer: `2023-11-28 17:01:29`

One way to find the exact creation time is to analyze the MFT. The MFT can be parsed using MFTEcmd and analyzed using Timeline Explorer.

![elf12](https://github.com/warlocksmurf/HTB-writeups/assets/121353711/ffe00ae6-7e0b-4fe5-b87d-fc6846ff5797)

### Task 13
Question: What is the full directory name that Elfin stored the file in?

Answer: `C:\users\Elfin\Appdata\Roaming\top-secret`

Similar to Task 11.

### Task 14
Question: What is the name of the bar that Elfin offers to meet the threat actor at?

Answer: `Greece`

Similarly, you can find suspicious Google Chrome search results about flying to Greece from North Pole.

![image](https://github.com/warlocksmurf/HTB-writeups/assets/121353711/f51eb564-1125-4591-9e94-d27b03dcef27)

### Task 15
Question: What is the email address of the apology letter the user (elfin) wrote out but didn’t send?

Answer: `Santa.claus@gmail.com`

Check the Drafts section in `eM Client`.

![elf15](https://github.com/warlocksmurf/HTB-writeups/assets/121353711/792a9fd6-34ca-44dc-8d0a-ffe9ec719181)

### Task 16
Question: The head elf PixelPeppermint has requested any passwords of Elfins to assist in the investigation down the line. What’s the windows password of Elfin’s host?

Answer: `Santaknowskungfu`

Impacket and MD5 cracker ftw. By using Impacket, we can extract the SAM database located in `\optinseltrace1\TriageData\C\Windows\system32\config\` directory to crack passwords.

![elf16](https://github.com/warlocksmurf/HTB-writeups/assets/121353711/215eb681-5d52-4834-b92e-15b6cd56ece1)

![elf16 1](https://github.com/warlocksmurf/HTB-writeups/assets/121353711/4d58923a-6fd8-4df2-b181-01422cf5191d)

## OpTinselTrace-2
### Scenario
It seems our precious technology has been leaked to the threat actor. Our head Elf, PixelPepermint, seems to think that there were some hard-coded sensitive URLs within the technology sent. 
Please audit our Sparky Cloud logs and confirm if anything was stolen! PS - Santa likes his answers in UTC...

### Task 1 
Question: What is the MD5 sum of the binary the Threat Actor found the S3 bucket location in?
<br>Answer: `62d5c1f1f9020c98f97d8085b9456b05`

Check the MD5 sum of the binary file in `OpTinsel-1`.

![aws1](https://github.com/warlocksmurf/HTB-writeups/assets/121353711/ae660d19-76bf-47a1-b589-0fd0e56677a0)

### Task 2  
Question: What time did the Threat Actor begin their automated retrieval of the contents of our exposed S3 bucket?
<br>Answer: `2023-11-29 08:24:07`

I was new at AWS cloudtrail forensics so I had to utilize a cheetsheet created by @njw on HTB Discord.

```
find . -type f -exec jq '.Records[] | [.eventTime, .sourceIPAddress, .userIdentity.arn, .eventName] | @tsv' {} ; | sort | grep -iE '(GetObject)'
```

![aws2](https://github.com/warlocksmurf/HTB-writeups/assets/121353711/707636b2-bcc7-42ad-ad8c-4db3d07a8c9a)

### Task 3 
Question: What time did the Threat Actor complete their automated retrieval of the contents of our exposed S3 bucket?
<br>Answer: `2023-11-29 08:24:16`

Check the end of Task 2 enumeration logs.

### Task 4 
Question: Based on the Threat Actor's user agent - what scripting language did the TA likely utilise to retrieve the files?
<br>Answer: `python`

I just guessed it, have no idea how to solve this.

### Task 5 
Question: Which file did the Threat Actor locate some hard coded credentials within?
<br>Answer: `claus.py`

By checking the binary file, we can find the AWS URL (https://papa-noel.s3.eu-west-3.amazonaws.com/). In the AWS bucket, we find a commit (COMMIT_EDITMSG) mentioning that claus.py was modified to remove credentials. This suggests that the hidden credentials were indeed stored in the python script.

![image](https://github.com/warlocksmurf/HTB-writeups/assets/121353711/ca0a1d9f-0055-4345-b6df-71ad857f562e)

```
# Please enter the commit message for your changes. Lines starting
# with '#' will be ignored, and an empty message aborts the commit.
#
# Author:    Author Name <bytesparkle@papanoel.co.uk>
#
# On branch master
# Changes to be committed:
#	modified:   claus.py
#
Removed the sparkly creds from the script! How silly of me! Sometimes I'm about as useful as a screen saver on Santa's Sleigh!!!!!!
```

![aws5](https://github.com/warlocksmurf/HTB-writeups/assets/121353711/57b7e287-5121-4698-b612-54802a75cc0a)

![image](https://github.com/warlocksmurf/HTB-writeups/assets/121353711/95dcdcb3-bdc0-4d54-848e-4ba9de1fc619)

### Task 6 
Question: Please detail all confirmed malicious IP addresses. (Ascending Order)
<br>Answer: `45.133.193.41, 191.101.31.57`

We know one of the IP address from Task 2, 192.101.31.57. Now we have to find the other, which can be found using the command 

```
find . -type f -exec jq '.Records[] | [.sourceIPAddress, .userIdentity.userName] | @tsv' {} \; | sort -u
```

![aws6](https://github.com/warlocksmurf/HTB-writeups/assets/121353711/eca44655-1e08-447d-8fdd-8de5158b43d9)

### Task 7
Question: We are extremely concerned the TA managed to compromise our private S3 bucket, which contains an important VPN file. Please confirm the name of this VPN file and the time it was retrieved by the TA.
<br>Answer: `bytesparkle.ovpn, 2023-11-29 10:16:53`

Pretty straightforward, just grep vpn and get your answer.

```
find . -type f -exec jq '.Records[] | [.eventTime, .sourceIPAddress, .userIdentity.arn, .eventName, .requestParameters.key] | @tsv' {} ; | sort | grep -iE '(List|Get|Describe)' | grep "vpn"
```

![aws7](https://github.com/warlocksmurf/HTB-writeups/assets/121353711/b2acc605-f292-4d13-9db4-4433c5df0877)

### Task 8
Question: Please confirm the username of the compromised AWS account?
<br>Answer: `elfadmin`

Similar to Task 6.

### Task 9
Question: Based on the analysis completed Santa Claus has asked for some advice. What is the ARN of the S3 Bucket that requires locking down?
<br>Answer: `arn:aws:s3:::papa-noel`

Using this command, we can find the ARM of the S3 Bucket via the compromised AWS account's GetObject requests. 

```
find . -type f -exec jq '.Records[] | [.sourceIPAddress=="191.101.31.57", .eventName=="GetObject", .requestParameters.bucketName, .resources[0].ARN] | @tsv' {} \; | sort -u
```

![image](https://github.com/warlocksmurf/HTB-writeups/assets/121353711/2009aa6d-767d-4d0a-9847-3da431babbac)

![aws9](https://github.com/warlocksmurf/HTB-writeups/assets/121353711/eccec6e4-0a3b-494d-b9cc-89502e05a328)

## OpTinselTrace-3
### Scenario
Oh no! Our IT admin is a bit of a cotton-headed ninny-muggins, ByteSparkle left his VPN configuration file in our fancy private S3 location! The nasty attackers may have gained access to our internal network. We think they compromised one of our TinkerTech workstations. Our security team has managed to grab you a memory dump - please analyse it and answer the questions! Santa is waiting…

### Task 1 
Question: What is the name of the file that is likely copied from the shared folder (including the file extension)?
<br>Answer: `present_for_santa.zip`

Reading the scenario, I tried scanning the files in the memory dump with grep santa. A suspicious zip file can be located in santa claus's Desktop.
```
python3 vol.py -f /mnt/hgfs/shared/HTB/Optinseltrace/optinseltrace3/santaclaus.bin windows.filescan | grep "santa"
```

![vol1](https://github.com/warlocksmurf/HTB-writeups/assets/121353711/c23ab528-f609-4a33-823f-b068b74895cb)

### Task 2 
Question: What is the file name used to trigger the attack (including the file extension)?
<br>Answer: `click_for_present.lnk`

By dumping and extracting the zip file, we can find a lnk file and a vbs file.
```
python3 vol.py -f /mnt/hgfs/shared/HTB/Optinseltrace/optinseltrace3/santaclaus.bin windows.dumpfiles --virtaddr 0xa48df8fb42a0
```

![vol2](https://github.com/warlocksmurf/HTB-writeups/assets/121353711/f9a3dade-1ca9-4092-b706-704adb4c1f3c)

### Task 3 
Question: What is the name of the file executed by click_for_present.lnk (including the file extension)?
<br>Answer: `present.vbs`

Check the metadata of the lnk file.

![vol3](https://github.com/warlocksmurf/HTB-writeups/assets/121353711/29d8688d-8c0b-4b84-99e0-d17812179f3d)

### Task 4 
Question: What is the name of the program used by the vbs script to execute the next stage?
<br>Answer: `powershell.exe`

Using [VirusTotal](https://www.virustotal.com/gui/file/78ba1ea3ac992391010f23b346eedee69c383bc3fd2d3a125ede6cba3ce77243/behavior), we can easily find the processes of this vbs script.

![vol4](https://github.com/warlocksmurf/HTB-writeups/assets/121353711/5586e600-cbf8-4606-b503-0955c8de4e92)

### Task 5 
Question: What is the name of the function used for the powershell script obfuscation?
<br>Answer: `WrapPresent`

Using [VirusTotal](https://www.virustotal.com/gui/file/78ba1ea3ac992391010f23b346eedee69c383bc3fd2d3a125ede6cba3ce77243/behavior), we can easily find the fuction.

![vol5](https://github.com/warlocksmurf/HTB-writeups/assets/121353711/0610eae6-e86d-47c9-a0a4-411b3f1ac6fa)

### Task 6
Question: What is the URL that the next stage was downloaded from?
<br>Answer: `http://77.74.198.52/destroy_christmas/evil_present.jpg`

Using [VirusTotal](https://www.virustotal.com/gui/file/78ba1ea3ac992391010f23b346eedee69c383bc3fd2d3a125ede6cba3ce77243/behavior), we can easily find the HTTP request.

![vol6](https://github.com/warlocksmurf/HTB-writeups/assets/121353711/f49a2de7-c866-4a44-876e-624b6b728044)

### Task 7
Question: What is the IP and port that the executable downloaded the shellcode from (IP:Port)?
<br>Answer: `77.74.198.52:445`

For this question, we have to analyze the whole zip file instead of the vbs file. As shown in [VirusTotal](https://www.virustotal.com/gui/file/31ef280a565a53f1432a1292f3d3850066c0ae8af18a4824e59ac6be3aa6ea9c/detection)  the IP address and port can be found.

![vol7](https://github.com/warlocksmurf/HTB-writeups/assets/121353711/637619cd-daef-4d59-bb29-e290673eb7b4)

### Task 8
Question: What is the process ID of the remote process that the shellcode was injected into?
<br>Answer: `724`

Since we know what IP address is associated with the vbs script, we can use netstat to discover its process.
```
python3 vol.py -f /mnt/hgfs/shared/HTB/Optinseltrace/optinseltrace3/santaclaus.bin windows.netstat
```

![vol7](https://github.com/warlocksmurf/HTB-writeups/assets/121353711/6a6915aa-6f9f-4284-bd68-bc25dfbf837d)

### Task 9
Question: After the attacker established a Command & Control connection, what command did they use to clear all event logs?
<br>Answer: `Get-EventLog -List | ForEach-Object { Clear-EventLog -LogName $_.Log }`

At this point, I was stuck and required hints from @tmechen on HTB Discord. He gave a hint on evtx logs and hence I dumped the Powershell evtx log since the script runs on powershell.
Task 9-13 can be solved with the evtx log.

```
python3 vol.py -f /mnt/hgfs/shared/HTB/Optinseltrace/optinseltrace3/santaclaus.bin windows.filescan | grep "evtx"
```

![vol8](https://github.com/warlocksmurf/HTB-writeups/assets/121353711/997a7aae-f953-400f-83d4-34f0e8c104d1)

### Task 10
Question: What is the full path of the folder that was excluded from defender?
<br>Answer: `C:\users\public`

![vol9](https://github.com/warlocksmurf/HTB-writeups/assets/121353711/3f393955-7268-4542-ad79-7e5aed5cdce5)

### Task 11
Question: What is the original name of the file that was ingressed to the victim?
<br>Answer: `procdump.exe`

Since the question wants the original name, the PresentForNaughtyChild.exe file has to be extracted via Volatility first before analyzing it on [VirusTotal](https://www.virustotal.com/gui/file/337c24c2e6016a9bdca30f2820df9c1dae7b827ad73c93a14e1dc78906b63890).

![vol10](https://github.com/warlocksmurf/HTB-writeups/assets/121353711/668649dc-da33-4e1c-8e4c-55d5d88b677f)
![vol11](https://github.com/warlocksmurf/HTB-writeups/assets/121353711/2ff6fc76-efc0-4414-9182-336c8408e026)

### Task 12
Question: What is the name of the process targeted by procdump.exe?
<br>Answer: `lsass.exe`

The powershell command from Task 11 shows the targeted process.

## OpTinselTrace-4
### Scenario
Printers are important in Santa’s workshops, but we haven’t really tried to secure them! The Grinch and his team of elite hackers may try and use this against us! Please investigate using the packet capture provided! The printer server IP Address is 192.168.68.128

### Task 1 
Question: The performance of the network printer server has become sluggish, causing interruptions in the workflow at the North Pole workshop. Santa has directed us to generate a support request and examine the network data to pinpoint the source of the issue. He suspects that the Grinch and his group may be involved in this situation. Could you verify if there is an IP Address that is sending an excessive amount of traffic to the printer server?
<br>Answer: `172.17.79.133`

We are given a pcap and reading the scenario, the printer server's IP address is 192.168.68.128. So the first step is to find out which IP address sent the most requests to this IP.

![wire1](https://github.com/warlocksmurf/HTB-writeups/assets/121353711/2a4f0852-d3f7-477a-b8cc-0390c2ac67cb)

### Task 2 
Question: Bytesparkle being the technical Lead, found traces of port scanning from the same IP identified in previous attack. Which port was then targeted for initial compromise of the printer?
<br>Answer: `9100`

By filtering the malicious IP address, we can see the IP targetting a specific port using TCP.

![wire2](https://github.com/warlocksmurf/HTB-writeups/assets/121353711/6dc93f89-b99a-4c19-8e30-d318dca4dfc4)

### Task 3 
Question: What is the full name of printer running on the server?
<br>Answer: `Northpole HP LaserJet 4200n`

After filtering, the TCP streams can be followed to read its content. At TCP stream 28, we can find readable strings of text.

![wire3](https://github.com/warlocksmurf/HTB-writeups/assets/121353711/9c9db392-68ea-454c-9f96-475e327b7724)

### Task 4 
Question: Grinch intercepted a list of nice and naughty children created by Santa. What was name of the second child on the nice list?
<br>Answer: `Douglas Price`

Similar to Task 3, just analyze the contents in TCP stream 28.

![wire4](https://github.com/warlocksmurf/HTB-writeups/assets/121353711/b81ea456-440e-44f1-83c6-e41a38995e0f)

### Task 5
Question: The Grinch obtained a print job instruction file intended for a printer used by an employee named Elfin. It appears that Santa and the North Pole management team have made the decision to dismiss Elfin. Could you please provide the word for word rationale behind the decision to terminate Elfin's employment?
<br>Answer: `The addressed employee is confirmed to be working with grinch and team. According to Clause 69 , This calls for an immediate expulsion.`

Similar to Task 3 and 4, just analyze the contents in TCP stream 28.

![wire5](https://github.com/warlocksmurf/HTB-writeups/assets/121353711/7f7ab97f-18be-4ff4-9323-0214271d7ec1)

### Task 6 
Question: What was the name of the scheduled print job?
<br>Answer: `MerryChristmas+BonusAnnouncment`

After fully analyzing the contents in TCP stream 28, I analyzed other streams and found TCP stream 46 to have strings of text too.

![wire6](https://github.com/warlocksmurf/HTB-writeups/assets/121353711/46a837c1-8d89-4976-bccc-6ddf85025d8d)

### Task 7
Question: Amidst our ongoing analysis of the current packet capture, the situation has escalated alarmingly. Our security system has detected signs of post-exploitation activities on a highly critical server, which was supposed to be secure with SSH key-only access. This development has raised serious concerns within the security team. While Bytesparkle is investigating the breach, he speculated that this security incident might be connected to the earlier printer issue. Could you determine and provide the complete path of the file on the printer server that enabled the Grinch to laterally move to this critical server?
<br>Answer: `/Administration/securitykeys/ssh_systems/id_rsa`

Similar to Task 6, just analyze the contents in TCP stream 46.

![wire7](https://github.com/warlocksmurf/HTB-writeups/assets/121353711/a5b2b32a-f7b3-416b-b1b6-ef3c6b141a18)

### Task 8
Question: What is size of this file in bytes?
<br>Answer: `1914`

Similar to Task 7, the file size can be found.

### Task 9
Question: What was the hostname of the other compromised critical server?
<br>Answer: `christmas.gifts`

Similar to Task 6 and 7, the hostname can be found in the comments.
```
#This is a backup key for christmas.gifts server. Bytesparkle recommended me this since in christmas days everything gets mixed up in all the chaos and we can lose our access keys to the server just like we did back in 2022 christmas.
```

### Task 10
Question: When did the Grinch attempt to delete a file from the printer? (UTC)
<br>Answer: `2023-12-08 12:18:14`

After fully analyzing the contents in TCP stream 46, I analyzed the final TCP stream 71. After finding the delete file packet, I just analyze the arrival time of the packet.

![wire10](https://github.com/warlocksmurf/HTB-writeups/assets/121353711/ebdbf240-a5de-4016-8639-74a72a2a088e)

![wire10 1](https://github.com/warlocksmurf/HTB-writeups/assets/121353711/77339bc2-9e79-49ca-a486-6c9a345291de)

## OpTinselTrace-5
### Scenario
You'll notice a lot of our critical server infrastructure was recently transferred from the domain of our MSSP - Forela.local over to Northpole.local. We actually managed to purchase some second hand servers from the MSSP who have confirmed they are as secure as Christmas is! It seems not as we believe christmas is doomed and the attackers seemed to have the stealth of a clattering sleigh bell, or they didn’t want to hide at all!!!!!! We have found nasty notes from the Grinch on all of our TinkerTech workstations and servers! Christmas seems doomed. Please help us recover from whoever committed this naughty attack!

### Task 1 
Question: Which CVE did the Threat Actor (TA) initially exploit to gain access to DC01?
<br>Answer: `CVE-2020-1472`

Using Hayabusa, the evtx directory can be scanned to determine the vulnerability using rules.

```
.\hayabusa-2.11.0-win-x64.exe csv-timeline -d 'C:\HTB\Optinseltrace\optinseltrace5\DC01.northpole.local-KAPE\uploads\auto\C%3A\Windows\System32\winevt' -o results.csv

╔╗ ╔╦═══╦╗  ╔╦═══╦══╗╔╗ ╔╦═══╦═══╗
║║ ║║╔═╗║╚╗╔╝║╔═╗║╔╗║║║ ║║╔═╗║╔═╗║
║╚═╝║║ ║╠╗╚╝╔╣║ ║║╚╝╚╣║ ║║╚══╣║ ║║
║╔═╗║╚═╝║╚╗╔╝║╚═╝║╔═╗║║ ║╠══╗║╚═╝║
║║ ║║╔═╗║ ║║ ║╔═╗║╚═╝║╚═╝║╚═╝║╔═╗║
╚╝ ╚╩╝ ╚╝ ╚╝ ╚╝ ╚╩═══╩═══╩═══╩╝ ╚╝
   by Yamato Security

Start time: 2023/12/29 14:41

Total event log files: 146
Total file size: 261.4 MB

Scan wizard:

✔ Which set of detection rules would you like to load? · 5. All event and alert rules (4270 rules) ( status: * | level: informational+ )
✔ Include deprecated rules? (193 rules) · no
✔ Include unsupported rules? (45 rules) · no
✔ Include noisy rules? (12 rules) · no
✔ Include sysmon rules? (2083 rules) · yes

```

![win1](https://github.com/warlocksmurf/HTB-writeups/assets/121353711/98d66849-9602-4023-ba86-26881401ebc6)

Hayabusa mentioned that most critical events happened on 13/12/2022. So I used Timeline Explorer to analyze the csv file from Hayabusa and found a suspicious logon from an unknown user (192.168.68.200) using an exploit called Zerologon.

![image](https://github.com/warlocksmurf/HTB-writeups/assets/121353711/fcc482fe-5133-4a57-9603-bda9ba046a52)

Scrolling further down, the unknown user seems to perform Mimikatz DC Sync multiple times. So I googled it to confirm if it's related to Zerologon and it does!

![image](https://github.com/warlocksmurf/HTB-writeups/assets/121353711/c3d0d8de-3535-469d-888f-0d64a8f4aa76)

![win2](https://github.com/warlocksmurf/HTB-writeups/assets/121353711/0ebb55bd-a1e0-4838-aff4-14f41c07d7f6)

### Task 2 
Question: What time did the TA initially exploit the CVE? (UTC)
<br>Answer: `2023-12-13 09:24:23`

Reading this [blog](https://0xbandar.medium.com/detecting-the-cve-2020-1472-zerologon-attacks-6f6ec0730a9e) about the CVE, it mentioned an easy way to detect the exploit using the Security.evtx.

> Successful exploitation resulting in a rest of the computer account password and it will be shown in security logs with event id 4742 “A computer account was changed”, password last set change, performed by Anonymous Logon.

![win2 1](https://github.com/warlocksmurf/HTB-writeups/assets/121353711/8307d503-2500-485b-9f84-9f20da3d1fed)

### Task 3
Question: What is the name of the executable related to the unusual service installed on the system around the time of the CVE exploitation?
<br>Answer: `hAvbdksT.exe`

Since we know the exact timeline for IoC, the executable related to the "vulnerable_to_zerologon" service can be easily found in the System.evtx by filtering the time and eventID.

![win3](https://github.com/warlocksmurf/HTB-writeups/assets/121353711/e54e82e9-45ae-4e87-b078-7484cfeb94d0)

### Task 4 
Question: What date & time was the unusual service start?
<br>Answer: `2023-12-13 09:24:24`

Similar to Task 3, just look for "vulnerable_to_zerologon" service starting.

![win4](https://github.com/warlocksmurf/HTB-writeups/assets/121353711/6dc67f43-deb9-487f-bdd1-4f8b53488d6b)

### Task 5 
Question: What was the TA's IP address within our internal network?
<br>Answer: `192.168.68.200`

Similar to Task 1, the TA's IP address can be identified from the malicious activity.

### Task 6 
Question: Please list all user accounts the TA utilised during their access. (Ascending order)
<br>Answer: `Administrator, Bytesparkle`

Using Hayabusa, we can find out the logon attempts and since we already know the TA's IP address from Task 5, we just have to find the user accounts. So I just filter out the specific IP address to find the second user.

```
.\hayabusa-2.11.0-win-x64.exe logon-summary -d 'C:\HTB\Optinseltrace\optinseltrace5\DC01.northpole.local-KAPE\uploads\auto\C%3A\Windows\System32\winevt\Logs | Select-String 192.168.68.200'
```

![win6](https://github.com/warlocksmurf/HTB-writeups/assets/121353711/676b3958-cdf9-4c7e-9a14-0a66b0fd443a)

To confirm this, we can refer back to Timeline Explorer to analyze the IP address connections.

![image](https://github.com/warlocksmurf/HTB-writeups/assets/121353711/ca59b54b-645e-4024-b962-cef531f01963)

### Task 7 
Question: What was the name of the scheduled task created by the TA?
<br>Answer: `svc_vnc`

Just look for the Microsoft-Windows-TaskScheduler%254Operational.evtx file and filter by eventID 106 (Task registered). Two schedule tasks was created and one of them was suspicious.

![win7](https://github.com/warlocksmurf/HTB-writeups/assets/121353711/f517c46e-1397-4c9d-9741-706dc1b7a367)

### Task 8 
Question: Santa's memory is a little bad recently! He tends to write a lot of stuff down, but all our critical files have been encrypted! Which creature is Santa's new sleigh design planning to use?
<br>Answer: `Unicorn`

Initially, we were given several encrypted files and the encryption program (splunk_svc.dll). So it is obvious we have to perform reverse engineering on splunk_svc.dll to decrypt the files. Using Ghidra, I managed to find the malware function that encrypted the files. Analyzing the function, the encryption method was discovered to be a simple XOR with the key `EncryptingC4Fun!`. So we can use CyberChef to decrypt the files easily and discover Santa's plan.

![win8](https://github.com/warlocksmurf/HTB-writeups/assets/121353711/a665d12f-a6a4-46cd-8463-bf0f89f06fe7)

![win8 2](https://github.com/warlocksmurf/HTB-writeups/assets/121353711/4137037d-0797-4c1e-919b-7be3bded88b2)

### Task 9 
Question: Please confirm the process ID of the process that encrypted our files.
<br>Answer: `5828`

Using the output from EVTXCmd and Timeline Explorer, we can filter by the file extension of encrypted files (.xmax) and discover that they were stored in the Microsoft-Windows-UAC-FileVirtualization/Operational channel. Hence, we can analyze the Microsoft-Windows-UAC-FileVirtualization/Operational.evtx file to obtain the process ID.

![win9](https://github.com/warlocksmurf/HTB-writeups/assets/121353711/c1c564be-85e9-4850-9c1b-34527c3094d2)

![win9 1](https://github.com/warlocksmurf/HTB-writeups/assets/121353711/7c5b26f8-53db-4cef-af70-f228c2ccd7c7)

## Ranking
![optinsel1](https://github.com/warlocksmurf/HTB-writeups/assets/121353711/16faeb30-23d5-4372-b6f5-467e3e24e4ab)
![optinsel2](https://github.com/warlocksmurf/HTB-writeups/assets/121353711/77755cc9-5b30-4784-ac1a-b5c3b591e223)
![optinsel3](https://github.com/warlocksmurf/HTB-writeups/assets/121353711/c942e1b7-ecae-4c6a-b782-983be4b16686)
![optinsel4](https://github.com/warlocksmurf/HTB-writeups/assets/121353711/771ab274-2948-427c-9e70-267638135711)
![optinsel5](https://github.com/warlocksmurf/HTB-writeups/assets/121353711/98e8fe19-bfdc-418d-ac96-8b0ee5a0fe66)
