0x00:netdicover/nmap 主机发现和端口扫描

```shell
Last login: Mon Feb 12 01:37:22 2024 from 10.37.129.2
┌──(root㉿kali)-[~]
└─# netdiscover -i eth0
 Currently scanning: 192.168.13.0/16   |   Screen View: Unique Hosts

 7 Captured ARP Req/Rep packets, from 7 hosts.   Total size: 348
 _____________________________________________________________________________
   IP            At MAC Address     Count     Len  MAC Vendor / Hostname
 -----------------------------------------------------------------------------
 192.168.1.5     80:65:7c:e5:ff:80      1      42  Apple, Inc.
 192.168.1.1     90:86:9b:83:58:38      1      42  zte corporation
 192.168.1.7     00:0c:29:f3:67:53      1      60  VMware, Inc.
 192.168.1.14    b0:7b:25:26:24:78      1      60  Dell Inc.
 192.168.1.8     a0:4a:5e:e4:e7:99      1      42  Microsoft Corporation
 192.168.1.202   68:f7:28:7f:cd:07      1      60  LCFC(HeFei) Electronics Technology co., ltd
 192.168.1.12    8c:c8:4b:1c:da:b7      1      42  CHONGQING FUGUI ELECTRONICS CO.,LTD.

┌──(root㉿kali)-[~]
└─# nmap -sS -sV -A -T5 -p- 192.168.1.7
Starting Nmap 7.92 ( https://nmap.org ) at 2024-02-13 18:16 CST
Warning: 192.168.1.7 giving up on port because retransmission cap hit (2).
Nmap scan report for 192.168.1.7 (192.168.1.7)
Host is up (0.026s latency).
Not shown: 65521 closed tcp ports (reset)
PORT      STATE    SERVICE VERSION
22/tcp    open     ssh     OpenSSH 6.7p1 Debian 5+deb8u4 (protocol 2.0)
| ssh-hostkey:
|   1024 26:81:c1:f3:5e:01:ef:93:49:3d:91:1e:ae:8b:3c:fc (DSA)
|   2048 31:58:01:19:4d:a2:80:a6:b9:0d:40:98:1c:97:aa:53 (RSA)
|   256 1f:77:31:19:de:b0:e1:6d:ca:77:07:76:84:d3:a9:a0 (ECDSA)
|_  256 0e:85:71:a8:a2:c3:08:69:9c:91:c0:3f:84:18:df:ae (ED25519)
80/tcp    open     http    Apache httpd 2.4.10 ((Debian))
|_http-title: Raven Security
|_http-server-header: Apache/2.4.10 (Debian)
111/tcp   open     rpcbind 2-4 (RPC #100000)
| rpcinfo:
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100024  1          48807/tcp   status
|   100024  1          49620/udp6  status
|   100024  1          54589/udp   status
|_  100024  1          56255/tcp6  status
6237/tcp  filtered unknown
7245/tcp  filtered unknown
12305/tcp filtered unknown
14111/tcp filtered unknown
20878/tcp filtered unknown
20889/tcp filtered unknown
25527/tcp filtered unknown
27541/tcp filtered unknown
48807/tcp open     status  1 (RPC #100024)
49309/tcp filtered unknown
57495/tcp filtered unknown
MAC Address: 00:0C:29:F3:67:53 (VMware)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT      ADDRESS
1   25.97 ms 192.168.1.7 (192.168.1.7)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 60.69 seconds
```

0x01: 扫描目录 dirb

```shell
dirb http://192.168.1.7 /usr/share/wordlists/dirb/big.txt -o /root/oscp/raven2/out.txt
```





```html
# Security notices relating to PHPMailer

Please disclose any vulnerabilities found responsibly - report any security problems found to the maintainers privately.

PHPMailer versions prior to 5.2.18 (released December 2016) are vulnerable to [CVE-2016-10033](https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2016-10033) a remote code execution vulnerability, responsibly reported by [Dawid Golunski](https://legalhackers.com).

PHPMailer versions prior to 5.2.14 (released November 2015) are vulnerable to [CVE-2015-8476](https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2015-8476) an SMTP CRLF injection bug permitting arbitrary message sending.

PHPMailer versions prior to 5.2.10 (released May 2015) are vulnerable to [CVE-2008-5619](https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2008-5619), a remote code execution vulnerability in the bundled html2text library. This file was removed in 5.2.10, so if you are using a version prior to that and make use of the html2text function, it's vitally important that you upgrade and remove this file.

PHPMailer versions prior to 2.0.7 and 2.2.1 are vulnerable to [CVE-2012-0796](https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2012-0796), an email header injection attack.

Joomla 1.6.0 uses PHPMailer in an unsafe way, allowing it to reveal local file paths, reported in [CVE-2011-3747](https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2011-3747).

PHPMailer didn't sanitise the `$lang_path` parameter in `SetLanguage`. This wasn't a problem in itself, but some apps (PHPClassifieds, ATutor) also failed to sanitise user-provided parameters passed to it, permitting semi-arbitrary local file inclusion, reported in [CVE-2010-4914](https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2010-4914), [CVE-2007-2021](https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2007-2021) and [CVE-2006-5734](https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2006-5734).

PHPMailer 1.7.2 and earlier contained a possible DDoS vulnerability reported in [CVE-2005-1807](https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2005-1807).

PHPMailer 1.7 and earlier (June 2003) have a possible vulnerability in the `SendmailSend` method where shell commands may not be sanitised. Reported in [CVE-2007-3215](https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2007-3215).
```



```shell
http://192.168.1.7/vendor/VERSION

5.2.16

```





```shell
──(root㉿kali)-[~/oscp/raven2]
└─# searchsploit PHPMailer
------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                     |  Path
------------------------------------------------------------------- ---------------------------------
PHPMailer 1.7 - 'Data()' Remote Denial of Service                  | php/dos/25752.txt
PHPMailer < 5.2.18 - Remote Code Execution                         | php/webapps/40968.sh
PHPMailer < 5.2.18 - Remote Code Execution                         | php/webapps/40970.php
PHPMailer < 5.2.18 - Remote Code Execution                         | php/webapps/40974.py
PHPMailer < 5.2.19 - Sendmail Argument Injection (Metasploit)      | multiple/webapps/41688.rb
PHPMailer < 5.2.20 - Remote Code Execution                         | php/webapps/40969.py
PHPMailer < 5.2.20 / SwiftMailer < 5.4.5-DEV / Zend Framework / ze | php/webapps/40986.py
PHPMailer < 5.2.20 with Exim MTA - Remote Code Execution           | php/webapps/42221.py
PHPMailer < 5.2.21 - Local File Disclosure                         | php/webapps/43056.py
WordPress Plugin PHPMailer 4.6 - Host Header Command Injection (Me | php/remote/42024.rb
------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results

```

