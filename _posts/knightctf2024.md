---
title: KnightCTF 2024 - Writeups
date: 2024-01-21 12:00:00
categories: [ctf]
tags: [forensics,networking,steganography,web,knight]
---

# Forensics
## Scenario
> My boss, Muhammad, sent me this dump file of a memory. He told me that this OS has a malware virus that runs automatically. I need to find some more information about this OS, and the hacker also created some files in this OS. He gave me a task to solve this within 24 hours. I am afraid. Will you please help me? My boss sent some questions; please solve them on my behalf. There are total 7 challenges in this series. Best of luck.

## Task 1: OS
Question: What is the OS version?

Flag: `KCTF{7.1.7601.24214}`

Use Windbg with this command `!analyze -v`.

![forensics1](/assets/posts/knightctf2024/forensics1.png)

## Task 2: IP Addr
Question: What is the IP address of this system?

Flag: `KCTF{10.0.2.15}`

Use Windbg with this command `du poi(poi(srvnet!SrvAdminIpAddressList))` and keep inputting `du` command to load each lines.

![forensics4](/assets/posts/knightctf2024/forensics4.png)

## Task 3: Password
Question: What is the login password of the OS? 

Flag: `KCTF{squad}`

Use Volatility2 hashdump plugin to get password hashes and crack it.

![forensics2](/assets/posts/knightctf2024/forensics2.png)

![forensics3](/assets/posts/knightctf2024/forensics3.png)

## Task 4: Note
Question: My boss has written something in the text file. Could you please help me find it? 

Flag: `KCTF{Respect_Y0ur_Her4nki}`

Use Volatility2 and dump the suspicious text file and you can find an encoded flag.

![forensics5](/assets/posts/knightctf2024/forensics5.png)

![forensics6](/assets/posts/knightctf2024/forensics6.png)

![forensics7](/assets/posts/knightctf2024/forensics7.png)

## Task 5: Execution
Question: My leader, Noman Prodhan, executed something in the cmd of this infected machine. Could you please figure out what he actually executed? 

Flag: `KCTF{W3_AR3_tH3_Kn1GHt}`

I just strings grep the memory dump and found the flag lol.
Intended way: Use Volatility2 consoles plugin and find the executable and command.

![forensics8](/assets/posts/knightctf2024/forensics8.png)

## Task 6: Path of the Executable
Question: What is the path folder of the executable file which execute privious flag? 

Flag: `KCTF{C:\Users\siam\Documents}`

Take the path of the executable obtained in Task 5.

## Task 7: Malicious
Question: What is the malicious software name? 

Flag: `KCTF{MadMan.exe}`

Use Volatility2 autoruns plugin, a suspicious software can be found.

![forensics9](/assets/posts/knightctf2024/forensics9.png)

# Networking
## Scenario
> Recently one of Knight Squad's asset was compromised. We've figured out most but need your help to investigate the case deeply. As a SOC analyst, analyze the pacp file & identify the issues.

## Task 1: Vicker IP
Question: What is the victim & attacker ip?

Flag: `KCTF{192.168.1.8_192.168.1.7}`

Checking the conversations in Wireshark, the attacker (192.168.1.7) seems to be communicating with our server (192.168.1.8).

![network1](/assets/posts/knightctf2024/network1.png)

## Task 2: Basic Enum
Question: What tool did the attacker use to do basic enumeration of the server? 

Flag: `KCTF{nikto}`

Filter victim or attacker's IP address and slowly analyze the packets, Nikto logs can be found in TCP stream 43.

![network2](/assets/posts/knightctf2024/network2.png)

## Task 3: Vulnerable Service
Question: What service was vulnerable to the main server?

Flag: `KCTF{vsftpd_2.3.4}`

Looking at the packets, suspicious FTP data can be seen being sent. Looking into FTP packets, it is shown that vFTPd 2.3.4 is indeed being exploited.

![network3](/assets/posts/knightctf2024/network3.png)

## Task 4: CVE ID
Question: What's the CVE id for the vulnerable service?

Flag: `KCTF{CVE-2011-2523}`

Just research online on vsFTPd exploits.

![network4](/assets/posts/knightctf2024/network4.png)

## Task 5: Famous Tool
Question: The attacker used a popular tool to gain access of the server. Can you name it?

Flag: `KCTF{metasploit}`

Researching more on the CVE, several video demonstrations shown that the attacker probably used Metasploit to gain access.

![network5](/assets/posts/knightctf2024/network5.png)

## Task 6: PORT
Question: What was the port number of the reverse shell of the server?

Flag: `KCTF{6200}`

Similarly, the CVE already explains which port is exploits.

![network6](/assets/posts/knightctf2024/network6.png)

![network7](/assets/posts/knightctf2024/network7.png)

## Task 7: Hidden File
Question: What's the flag of the hidden file?

Flag: `KCTF{ExPloItiNg_S3RvEr_Is_fUN}`

The flag can be found in the tcp stream previously, however, I could not decode it before the CTF ended. After asking other players on Discord, the true method is `Twin Hex` (that is too guessy).

![network8](/assets/posts/knightctf2024/network8.png)

![network9](/assets/posts/knightctf2024/network9.png)

## Task 8: Confidential
Question: There's something confidential. Can you find it?

Flag: `KCTF{Y0U_Ar3_N3tW0rk_M1n3r}`

Extract the `confidential.zip` file from Wireshark and within the zip, there is a .docx file. Analyzing the doc file, we can see the flag being somewhere in the file.

![network10](/assets/posts/knightctf2024/network10.png)

![network11](/assets/posts/knightctf2024/network11.png)

Pretty straightforward, just resize the image and colorize every text.

![network12](/assets/posts/knightctf2024/network12.png)

## Task 9: BackDoor
Question: What is the backdoor file name?

Flag: `KCTF{.621b4CkD0oR.php5}`

Analyzing the TCP stream again, we can find a php file being created and renamed.

![network13](/assets/posts/knightctf2024/network13.png)

## Task 10: BackDoor Path
Question: What is the full path of the backdoor in the server?

Just take the path of the php file from Task 9.

Flag: `KCTF{/var/www/html/app/assets/.621b4CkD0oR.php5}`

Analyzing the TCP stream again, we can find a php file being created and renamed.

![network13](/assets/posts/knightctf2024/network13.png)

## Task 11: Super Admin
Question: What is the super admin password in the web application?

Flag: `KCTF{letmeinroot}`

We are given a SQL database attachment called `backup.sql` and the root password hash can be found within it. We also know its MD5 from the `process_login.php`.

![network14](/assets/posts/knightctf2024/network14.png)

![network15](/assets/posts/knightctf2024/network15.png)

## Task 12: Admin Flag
Question: Can you find the Admin Flag of the web server?

Flag: `KCTF{y0U_G0t_tHe_AdMin_Fl4g}`

After analyzing everything, I came across the other zip file obtain previous, the `app.zip` file. Looking through the app files, we stumble across `dashboard.php` where a seemingly encoded cookie can be found.

![network16](/assets/posts/knightctf2024/network16.png)

![network17](/assets/posts/knightctf2024/network17.png)

## Task 13: Vuln
Question: What was the vulnerability on the edit task page & what parameter was vulnerable?

Flag: `KCTF{sqli_taskId}`

By following HTTP traffic in the pcap, we can see a supposedly SQL injection attack going on. So we can check the vulnerable source code in `process_edit_task.php` and the parameter can be found.

![network18](/assets/posts/knightctf2024/network18.png)

![network19](/assets/posts/knightctf2024/network19.png)

So the vulnerablility is SQLi and the parameter is taskId.

## Task 14: Famous Tool 2
Question: What tool did the attacker use to identify the vulnerability of edit task page?  

Flag: `KCTF{sqlmap/1.7.10#stable}`

Check the http stream of the attack, the tool used was SQLMap 1.7.10#stable

![network20](/assets/posts/knightctf2024/network20.png)

## Task 15: Something Interesting
Question: What is the super admin password in the web application? 

Flag: `KCTF{Y0u_aRe_InTeREsTiNg}`

I had no clue how to solve this, so I asked other members on Discord and they mentioned a suspicious query in the previous SQL database.
I guess it's another guessy challenge, I tried ROT47 and it worked out.

![network21](/assets/posts/knightctf2024/network21.png)

![network22](/assets/posts/knightctf2024/network22.png)

## Task 16: Hidden Page
Question: There was a hidden page which was only accessible to root & was removed from the web app for security purpose. Can you find it?

Flag: `KCTF{terminal-13337.php}`

A suspicious php file for root can be found in `tasks.php`.

![network23](/assets/posts/knightctf2024/network23.png)

## Task 17: DB Details
Question: What is the database username & databasename?

Flag: `KCTF{db_user_kctf2024}`

After spending several minutes on looking at the app files, I actually found the username and password in the previous vFTPd stream. So the username is actually 'db_user' not 'root', and the password is 'kctf2024' as seen in `db.php`.

![network24](/assets/posts/knightctf2024/network24.png)

## Task 18: API Key
Question: What's the API Key?

Flag: `KCTF{6eea9135-2801-4560-b44c-f297b5f46f2f}`

The API key can be found in `db.php`.

![network25](/assets/posts/knightctf2024/network25.png)

# Steganography
## Task 1: Oceanic
Question: The ocean's beauty is in its clear waters, but its strength lies in its dark depths.

Flag: `KCTF{mul71_l4y3r3d_57360_ec4dacb5}`

We are given an image and a .wav audio file. So I tried analyzing the audio file on Audacity but nothing relevant was found.

So I exiftool the image file to find an encoded message in it. It is probably a hint to find the flag, so I did some research on "deepaudio" and came across a 
[blog](https://medium.com/@ibnshehu/deepsound-audio-steganography-tool-f7ca0a897576) on audio steganography with the tool called `DeepSound`, kinda sus as it represents the challenge and the hint given.

![deep1](/assets/posts/knightctf2024/deep1.png)

Using the password obtained in exiftool, we can extract a `flag.png` from it. So we binwalk the png and find the flag.

![deep2](/assets/posts/knightctf2024/deep2.png)

![deep3](/assets/posts/knightctf2024/deep3.png)

## Task 2: Flag Hunt!
Question: Hunt your way through the challenge and Capture The hidden Flag!!!

Flag: `KCTF{3mb3d_53cr37_4nd_z1pp17_4ll_up_ba6df32ce}`

We are given a protected Zip file. Using binwalk, we can find multiple jpg files, text files and a wav file. So, since I have no clue what the password is, I just brute-force it with John.
```
zip2john chall.zip > hash
john --wordlist=$rockyou hash
```

![zip1](/assets/posts/knightctf2024/zip1.png)

After extracting the zip with the password, we can start analyzing the text files. I used `files *` to analyze all files and found out img725.jpg is different from the rest.

![zip2](/assets/posts/knightctf2024/zip2.png)

![zip3](/assets/posts/knightctf2024/zip3.png)

Listening to .wav audio file, it is a Morse code. Tried the code obtained in Morse code as the flag, sadly it was incorrect. 
So I tried stegsolve on the outlier image file and got the real flag.

![zip4](/assets/posts/knightctf2024/zip4.png)

![zip5](/assets/posts/knightctf2024/zip5.png)

# Web
## Task 1: Kitty
Question: Tetanus is a serious, potentially life-threatening infection that can be transmitted by an animal bite.

Flag: `KCTF{Fram3S_n3vE9_L1e_4_toGEtH3R}`

We are given a login page, so I analyzed the page source and stumbled across the Javascript file. It says that the credentials are 'username' and 'password' (Not very secure).

![kitty1](/assets/posts/knightctf2024/kitty1.png)

```
document.getElementById('login-form').addEventListener('submit', function(event) {
    event.preventDefault();

    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;

    const data = {
        "username": username,
        "password": password
    };

    fetch('/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(data)
    })
    .then(response => response.json())
    .then(data => {
        // You can handle the response here as needed
        if (data.message === "Login successful!") {
            window.location.href = '/dashboard'; // Redirect to the dashboard
        } else {
            // Display an error message for invalid login
            const errorMessage = document.createElement('p');
            errorMessage.textContent = "Invalid username or password";
            document.getElementById('login-form').appendChild(errorMessage);

            // Remove the error message after 4 seconds
            setTimeout(() => {
                errorMessage.remove();
            }, 4000);
        }
    })
    .catch(error => {
        console.error('Error:', error);
    });
});
```

After logging it, we are redirected to another page, the dashboard. Same thing I analyzed the page source and found a script field.

![kitty2](/assets/posts/knightctf2024/kitty2.png)

```
<script>
    function addPost(event) {
        event.preventDefault();
        const post_in = document.getElementById('post_input').value;
        
        if (post_in.startsWith('cat flag.txt')) {
            fetch('/execute', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                body: `post_input=${encodeURIComponent(post_in)}`
            })
            .then(response => response.text())
            .then(result => {
                const contentSection = document.querySelector('.content');
                const newPost = document.createElement('div');
                newPost.classList.add('post');
                newPost.innerHTML = `<h3>Flag Post</h3><p>${result}</p>`;
                contentSection.appendChild(newPost);
            });
        } else {
            const contentSection = document.querySelector('.content');
            const newPost = document.createElement('div');
            newPost.classList.add('post');
            newPost.innerHTML = `<h3>User Post</h3><p>${post_in}</p>`;
            contentSection.appendChild(newPost);
        }
    }
</script>
```

The script mentioned by using sending a command `cat flag.txt` in the input field, we can get the flag.

![kitty3](/assets/posts/knightctf2024/kitty3.png)

## Task 2: Levi Ackerman
Question: Levi Ackerman is a robot!

Flag: `KCTF{1m_d01n6_17_b3c4u53_1_h4v3_70}`

We are given a website with a picture of Levi from Attack on Titan, nothing else. So by reading the question, I navigated to robots.txt.

![levi1](/assets/posts/knightctf2024/levi1.png)

![levi2](/assets/posts/knightctf2024/levi2.png)
