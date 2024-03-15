---
title: IrisCTF 2024 - Writeups
date: 2023-10-28 12:00:00
categories: [ctf]
tags: [forensics,networking,osint,iris]
---

## Task 1: Not Just Media [Forensics]
Question: I downloaded a video from the internet, but I think I got the wrong subtitles. Note: The flag is all lowercase.

Flag: `irisctf{mkvm3rg3_my_b3l0v3d}`

We are given a weird .mkv video file and reading the scenario, we have to probably analyze the subtitles. So doing my research online, we can use [mkvinfo](https://linux.die.net/man/1/mkvinfo) to find multiple tracks and subtitles embedded within the video.

![media1](/assets/posts/irisctf24/media1)

Analyzing the metadata, we notice 1 of the font files called FakeFont.ttf (kinda suspicious). So we extract this font file and also the subtitle of the video. Inside the subtitle file, several chinese letters can be found.

![media2](/assets/posts/irisctf24/media2)

![media3](/assets/posts/irisctf24/media3)

So we just have to combine both files together using [fontdrop.io](https://fontdrop.info/#/?darkmode=true).

![media4](/assets/posts/irisctf24/media4)

## Task 2: skat's SD card [Forensics]
Question: "Do I love being manager? I love my kids. I love real estate. I love ceramics. I love chocolate. I love computers. I love trains."

Flag: `irisctf{0h_cr4p_ive_left_my_k3ys_out_4nd_ab0ut}`

We are given a Linux file system, so I opened up Autopsy and started my investigation. The first thing to check is the User's directory for clues, and analyzing the bash history of the user skat, he probably downloaded a repository from GitHub called `skats-interesting-things.git`. 

![skat1](/assets/posts/irisctf24/skat1)

So I attempted to clone the repository myself but it requires a secret key. At this point I was stuck and could not solve it before the CTF ended, but I asked several members on Discord and they told me we can actually extract the public key from the hidden files. Going through the directories, we can find another hidden directory called .ssh and within it the RSA keys.

![skat2](/assets/posts/irisctf24/skat2)

Since its a private key, we can brute force it using John the Ripper to obtain the passphrase.
```
ssh2john id_rsa > id_rsa.hash
john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa.hash
```

The password is `password` (that's not very secure skat!). Now we can start cloning the suspicious files from the repository. Before that, we have to also copy both the private key and public key to my `~/.ssh` directory to be used for authorisation. After cloning the repository, we can find multiple text files, README, and a hidden .git directory.

![skat3](/assets/posts/irisctf24/skat3)

@seal on Discord mentioned that we can use a tool called [packfile_reader](https://github.com/robisonsantos/packfile_reader) to extract and parse .git data to some text files. Navigating to `.git/objects/pack`, we can utilize the tool and just grep the flag from the parsed text files.

![skat4](/assets/posts/irisctf24/skat3)

## Task 1: Where's skat? [Networks]
Question: While traveling over the holidays, I was doing some casual wardriving (as I often do). Can you use my capture to find where I went? Note: the flag is irisctf{the_location}, where the_location is the full name of my destination location, not the street address. For example, irisctf{Washington_Monument}. Note that the flag is not case sensitive.

Flag: `irisctf{los_angeles_union_station}`

We are given a pcap file to investigate where teh user might be. Looking around the pcap file, I noticed the user's device communicating with nearby routers and it seems to lead to the same place everytime (according to the SSID).

![where1](/assets/posts/irisctf24/where1)

From what I understand, it seems that skat is being in some station as it shows multiple Metro SSIDs and by checking LAUS with Morlin together (I thought Morlin was a hotel), we can get the location.

![where2](/assets/posts/irisctf24/where2)

## Task 2: skat's Network History [Networks]
Question: "I love cats." Note: this challenge is a continuation to Forensics/skat's SD Card. You are dealing with the same scenario. skats-sd-card.tar.gz is the same file from that challenge (SHA-1: 4cd743d125b5d27c1b284f89e299422af1c37ffc).

Flag: `irisctf{i_sp3nd_m0st_of_my_t1me_0n_th3_1nt3rnet_w4tch1ng_c4t_v1d30s}`

We are given a pcap file again and some encrypted 802.11 packets. Unfortunately, I could not solve this challenge before the CTF ended, but @seal taught me the method so big shoutout to him/her!!

Poking around the skat's directory in the SD card from the Forensics challenge, the Bookshelf folder has a PDF manual for setting up a Raspberry Pi. So checking on the `skatnet.nmconnection` file located in `/etc/NetworkManager/system-connection/`, we can see it contains a WiFi password (PSK).

```
[connection]
id=skatnet
uuid=470a7376-d569-444c-a135-39f5e57ea095
type=wifi
interface-name=wlan0

[wifi]
mode=infrastructure
ssid=skatnet

[wifi-security]
auth-alg=open
key-mgmt=wpa-psk
psk=agdifbe7dv1iruf7ei2v5op

[ipv4]
method=auto

[ipv6]
addr-gen-mode=default
method=auto

[proxy]
```

With the PSK, we can decrypt the packets using Wireshark by navigating to `Preferences > Protocols > IEEE 802.11 > Edit` to add the PSK as the wpa-pwd.

![history1](/assets/posts/irisctf24/history1)

We are also given some SSL keys in a file called sslkeyfile, so we can utilize them by navigating to `Protocols > TLS > (Pre)-Master-Secret log filename` and placing them to the pcap that it allows us decrypt certain packets.

![history2](/assets/posts/irisctf24/history2)

After decrypting, we can find several HTTP/2 packets (first time hearing about this) when analyzing the traffic. A pastebin entry can be found in the traffic and the data response for it has the flag.

![history3](/assets/posts/irisctf24/history3)

## Task 1: Czech Where? [OSINT]
Question: Iris visited this cool shop a while back, but forgot where it was! What street is it on?

Flag: `irisctf{zlata_ulicka_u_daliborky}`

We are given an image of a supposedly Czech location. Just perform a Google reverse search to at least identify the location's name.

![czech1](/assets/posts/irisctf24/czech1)

The location's name can be found in a Japanese blog. Looking into Google Maps for Czech Golden Lane, the street name can be obtained.

![czech2](/assets/posts/irisctf24/czech2)

![czech3](/assets/posts/irisctf24/czech3)

## Task 2: Away on Vacation [OSINT]
Question: Iris and her assistant are away on vacation. She left an audio message explaining how to get in touch with her assistant. See what you can learn about the assistant.

Flag: `irisctf{pub1ic_4cc0unt5_4r3_51tt1ng_duck5}`

We are given a voicemail of a person named 'Iris'. 

The transcript:
```
Hello, you’ve reached Iris Stein, head of the HR department! I’m currently away on vacation, please contact my assistant Michel. You can reach out to him at michelangelocorning0490@gmail.com. Have a good day and take care.
```

Funny thing is I actually went to email Michel since the admin told me its allowed and I actually got an automatic reply from Michel stating that he is also on vacation now and I can reach out to him via social media.

![vac1](/assets/posts/irisctf24/vac1)

So I tried finding him on Instagram and one of the post gave the flag.

![vac2](/assets/posts/irisctf24/vac2)

![vac3](/assets/posts/irisctf24/vac3)

## Task 3: Personal Breach [OSINT]
Question: Security questions can be solved by reconnaissance. The weakest link in security could be the people around you.

Flag: `irisctf{s0c1al_m3d1a_1s_an_1nf3cti0n}`

We are tasked to look for information about a person called Iris Stein:
```
1. How old is Iris? 
2. What hospital was Iris born in?
3. What company does Iris work for?
```
Since we know Iris is associated with Michel in some way, we can find her in Michel's Instagram followers list. Going through all Iris Stein's posts, we find that even her mom, Elaina Stein, has a social media account.

![iris1](/assets/posts/irisctf24/iris1)

![iris2](/assets/posts/irisctf24/iris2)

Looking everywhere for her mom, the only place I got information was Facebook (based and chad).

![iris3](/assets/posts/irisctf24/iris3)

Going through Eleina's posts, we find a life event post on her daughter's birth. There we can find Iris Stein's age to be `27 years old`.

![iris4](/assets/posts/irisctf24/iris4)

Just Google reverse search the hospital picture and the name of the hospital can be found. The name of the specific hospital was `Lenox Hill Hospital`.

![iris5](/assets/posts/irisctf24/iris5)

Our last task was to find her company. These work-related stuff should probably be on Linkedin. Remember to type in HR for easier search since we know she is the HR department from the voicemail from previous tasks.

![iris6](/assets/posts/irisctf24/iris6)

![iris7](/assets/posts/irisctf24/iris7)

Answering all the questions, the flag is given.

![iris8](/assets/posts/irisctf24/iris7)

## Task 4: A Harsh Reality of Passwords [OSINT]
Question: Recently, Iris’s company had a breach. Her password’s hash has been exposed. This challenge is focused on understanding Iris as a person. Hash: $2b$04$DkQOnBXHNLw2cnsmSEdM0uyN3NHLUb9I5IIUF3akpLwoy7dlhgyEC

Flag: `irisctf{PortofinoItalyTiramisu0481965}`

I was not able to solve this question before the CTF ended, however, I did attempt it later on and found it quite interesting. Basically from what the scenario mentioned, we have to find several characters and digits to create our own password dictionary to crack the hash given. Doing some research on the hash, it is probably a `bcrypt $2*$, Blowfish (Unix)`

We can see that she calls her Mothers birthday a 'very important date' so thats one of the details we can extract for our dictionary.

![hash1](/assets/posts/irisctf24/hash1)

Here, she mentions her love for Tiramisu, that's going on the dictionary.

![hash2](/assets/posts/irisctf24/hash2)

In this post she talks about an important place in Italy, Portofino.

![hash3](/assets/posts/irisctf24/hash3)

A dictionary file can then be created with the important words and her mother's birthdate (the admins gave us a hint on this).
```
from itertools import permutations

words = ["Iris", "Stein", "Elaine", "Tiramisu", "Portofino", "Mimosas", "Italy"]
word_combinations = permutations(words, 3)
all_word_combinations = [''.join(combo) for combo in word_combinations]

date_numbers = "8041965"
num_combinations = permutations(date_numbers, len(date_numbers))
all_num_combinations = [''.join(combo) for combo in num_combinations]

combined_results = [word_combo + num_combo for word_combo in all_word_combinations for num_combo in all_num_combinations]

# Save the output to a text file
output_file_path = "output.txt"
with open(output_file_path, 'w') as output_file:
    for result in combined_results:
        output_file.write(result + '\n')

print(f"Output saved to {output_file_path}")
```

Using hashcat, we can crack the hash and obtain the password.
```
hashcat -m 3200 hash output.txt
```

![hash4](/assets/posts/irisctf24/hash4)
