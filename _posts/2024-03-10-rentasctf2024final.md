---
title: rENTAS CTF 2024 (Finals) - Writeups
time: 2024-03-10 12:00:00
categories: [ctf,local]
tags: [dfir,networking,web,hardware]
image: /assets/posts/rentasctf2024/icon.jpg
---

This is a writeup for some DFIR, networking, web and hardware challenges from rENTAS CTF 2024 (Finals) organized by rawSec. After the qualifying round, me and my team continued forward to compete in the final round with 30 teams from different universities. In the end, we only managed to achieve 20th place out of 30 teams. However, it was still an enjoyable experience as I get to meet so many new friends from M53 and SherpaSec.

## Hidden zombie [DFIR]
**Question:**

**Flag:** `RWSC{z0mb13_4tt4ck_1nc0m1ng}`

We are given a PNG file to investigate. Unfortunately I could not solve this before the CTF ended, but I still attempted it at home. Looking back at the challenge, it was actually pretty simple (and it's definitely not DFIR ffs). Essentially, the PNG image had issues errors on the IHDR chunk, so I went to fix it.

```
└─$ pngcheck -v zomba.png
zlib warning:  different version (expected 1.2.13, using 1.3)

File: zomba.png (1536669 bytes)
  chunk IHDR at offset 0x0000c, length 13
    1024 x 921 image, 32-bit RGB+alpha, non-interlaced
  CRC error in chunk IHDR (computed 80d35286, expected 7f1d2b83)
ERRORS DETECTED in zomba.png
```

After fixing the IHDR chunk:
```
00000000   89 50 4E 47  0D 0A 1A 0A  00 00 00 0D  49 48 44 52  00 00 04 00  00 00 03 99  08 06 00 00  .PNG........IHDR............
0000001C   00 80 D3 52  86 00 00 00  01 73 52 47  42 00 AE CE  1C E9 00 00  00 04 67 41  4D 41 00 00  ...R.....sRGB.........gAMA..
00000038   B1 8F 0B FC  61 05 00 00  00 09 70 48  59 73 00 00  0E C4 00 00  0E C4 01 95  2B 0E 1B 00  ....a.....pHYs..........+...
```

Checking the PNG image again, it seems that there are several IDAT chunks having incorrect lengths. So I tried adjusting the height and width of the image to find hidden data below or above the picture.

```
└─$ python2 PCRT.py -i ~/Desktop/sharedfolder/zomba-modified.png -o ../output.png 

         ____   ____ ____ _____ 
        |  _ \ / ___|  _ \_   _|
        | |_) | |   | |_) || |  
        |  __/| |___|  _ < | |  
        |_|    \____|_| \_\|_|  

        PNG Check & Repair Tool 

Project address: https://github.com/sherlly/PCRT
Author: sherlly
Version: 1.1

[Finished] Correct PNG header
[Finished] Correct IHDR CRC (offset: 0x1D): 80D35286
[Finished] IHDR chunk check complete (offset: 0x8)
[Finished] Correct IDAT chunk data length (offset: 0x53 length: FFA5)
[Finished] Correct IDAT CRC (offset: 0x10000): E413EAD2
[Detected] Error IDAT chunk data length! (offset: 0x10004)
chunk length:FFF4
actual length:FFA5
[Notice] Try fixing it? (y or n) [default:y] n
[Detected] Error IDAT chunk data length! (offset: 0x1FFB5)
chunk length:41FD3640
actual length:FFA5
[Notice] Try fixing it? (y or n) [default:y] n
[Detected] Error IDAT chunk data length! (offset: 0x2FF66)
...
```

After awhile, it seems that the height was the culprit.
```
00000000   89 50 4E 47  0D 0A 1A 0A  00 00 00 0D  49 48 44 52  00 00 04 00  00 00 03 99  08 06 00 00  00 80 D3 52  .PNG........IHDR...............R
to
00000000   89 50 4E 47  0D 0A 1A 0A  00 00 00 0D  49 48 44 52  00 00 04 00  00 00 04 00  08 06 00 00  00 80 D3 52  .PNG........IHDR...............R
```

![zombie1](/assets/posts/rentasctf2024final/zombie1.png)

Additionally, a great tool recommended by another rENTAS member told me about [FotoForensics](https://fotoforensics.com/), that explains how they got first blood in a minute.

## I Hope You Have The Software [Networking]
**Question:**

**Flag:** `RWSC{!t5_a_t4c3r_f!l3_:D}`

We are given a Packet Tracer file to investigate. Analyzing the network connections, it seems that there were extra servers overlapping one another.

![pk1](/assets/posts/rentasctf2024final/pk1.png)

Analyzing each server configuration, only server 6 had an `index.html`. Checking its contents, the flag can be found.

![pk2](/assets/posts/rentasctf2024final/pk2.png)

## Anti-Brute [Web]
**Question:**

**Flag:** `RWSC{n0_brut3f0rc3_pl34s3}`

We are given a password text file. So just brute force password of admin with list given. The password was revealed to be `secretpass`.

![web1](/assets/posts/rentasctf2024final/web1.png)

## Water Sensor [Hardware]
**Question:**

**Flag:** `RWSC{ILUVU1337}`

```
ZX Company has released their brand new water sensing Arduino-based device. This innovative system is designed to detect the presence or absence of water using various sensors connected to an Arduino microcontroller board. The device typically includes one or more types of water sensors, such as resistive or capacitive sensors, which are capable of detecting changes in conductivity or capacitance when in contact with water. This advanced technology allows for accurate and reliable water detection, making it suitable for various applications ranging from flood detection to irrigation system management.

The Arduino board serves as the central processing unit, receiving input from the water sensors and executing programmed logic to interpret the sensor data and trigger appropriate actions or alerts. This can include activating pumps to remove water, sounding alarms to warn of flooding, or sending notifications to a connected device or network. This water sensor device consists of a memory size of 700MB. Every 1 minutes, it will respectively load a new set of data without clearing the old one. This allows for continuous monitoring and storage of water sensor readings over time. The device may also incorporate additional components such as relays, actuators, and communication modules (e.g., Wi-Fi, GSM) to enable more advanced functionality or remote monitoring capabilities.

Overall, this water sensing Arduino device provides a cost-effective and customizable solution for monitoring and managing water levels in various applications, including flood detection, irrigation systems, and leak detection in buildings.

Can you hack the device physically and look for any bugs according to info given?
```

According to the question, we had to perform buffer overflow on the water sensor since the memory can only hold 700 MB and it loads a new set of data every minute without clearing the old one. So we placed the water sensor for 7 minutes so that the memory will keep loading until it crashes. After it crashes, the flag can be obtained.

![water1](/assets/posts/rentasctf2024final/water1.png)

## Scoreboard
### Team HLG

![hlg](/assets/posts/rentasctf2024final/hlg.png)
