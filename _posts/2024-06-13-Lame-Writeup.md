---
title: Lame HackTheBox Writeup 
date: 2024-06-09
categories: [HackTheBox]
tags: [Pentest, HTB, CTF, OSCP, Linux]
---

# Lame (10.10.10.3)

Lame is a very easy HTB machine and a part of old TJ Null list (2021). It requires only one exploit to root the machine. The following exploit can be easily executed with Metasploit or we can use the public exploit script to get the shell as well.

## Recon

### Nmap Scan

Getting started with nmap scan first

![Untitled](Lame%203ee145cbcc7f4e33b4e117343d4b1292/Untitled.png)

Then I ran the full vuln nmap scan and got this output. 

```jsx
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-21 06:03 IST
Nmap scan report for 10.10.10.3
Host is up (0.18s latency).

PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 2.3.4
22/tcp   open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
| vulners: 
|   cpe:/a:openbsd:openssh:4.7p1: 
|     	SECURITYVULNS:VULN:8166	7.5	https://vulners.com/securityvulns/SECURITYVULNS:VULN:8166
|     	CVE-2010-4478	7.5	https://vulners.com/cve/CVE-2010-4478
|     	CVE-2008-1657	6.5	https://vulners.com/cve/CVE-2008-1657
|     	SSV:60656	5.0	https://vulners.com/seebug/SSV:60656	*EXPLOIT*
|     	CVE-2010-5107	5.0	https://vulners.com/cve/CVE-2010-5107
|     	CVE-2012-0814	3.5	https://vulners.com/cve/CVE-2012-0814
|     	CVE-2011-5000	3.5	https://vulners.com/cve/CVE-2011-5000
|     	CVE-2008-5161	2.6	https://vulners.com/cve/CVE-2008-5161
|     	CVE-2011-4327	2.1	https://vulners.com/cve/CVE-2011-4327
|     	CVE-2008-3259	1.2	https://vulners.com/cve/CVE-2008-3259
|_    	SECURITYVULNS:VULN:9455	0.0	https://vulners.com/securityvulns/SECURITYVULNS:VULN:9455
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
3632/tcp open  distccd     distccd v1 ((GNU) 4.2.4 (Ubuntu 4.2.4-1ubuntu4))
| distcc-cve2004-2687: 
|   VULNERABLE:
|   distcc Daemon Command Execution
|     State: VULNERABLE (Exploitable)
|     IDs:  CVE:CVE-2004-2687
|     Risk factor: High  CVSSv2: 9.3 (HIGH) (AV:N/AC:M/Au:N/C:C/I:C/A:C)
|       Allows executing of arbitrary commands on systems running distccd 3.1 and
|       earlier. The vulnerability is the consequence of weak service configuration.
|       
|     Disclosure date: 2002-02-01
|     Extra information:
|       
|     uid=1(daemon) gid=1(daemon) groups=1(daemon)
|   
|     References:
|       https://nvd.nist.gov/vuln/detail/CVE-2004-2687
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-2687
|_      https://distcc.github.io/security.html
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: false
|_smb-vuln-regsvc-dos: ERROR: Script execution failed (use -d to debug)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 261.60 seconds
```


## Enumeration

From the Nmap scan I got the versions of all the servies and started searching for vulnerable services version.

### FTP-Enum (vsftpd 2.3.4)

I searched for FTP version and found that it was vulnerable to  Backdoor Command Execution.

[vsftpd 2.3.4 - Backdoor Command Execution](https://www.exploit-db.com/exploits/49757)

But we need user and password for that.

So, I left that and started enumerating SSH version

### SSH OpenSSH 4.7p1

It is vulnerable to bruteforce attack, but machine was not made to exploit it that way and also the bruteforce was taking it too long 😞

![Untitled](Lame%203ee145cbcc7f4e33b4e117343d4b1292/Untitled%201.png)

It didn’t worked out well. So, I moved on to SMB Enum

### Samba smbd 3.X - 4.X

I searced for its version and found the exploit.


![Untitled](Lame%203ee145cbcc7f4e33b4e117343d4b1292/Untitled%202.png)

[Msf Exploit Link](https://www.rapid7.com/db/modules/exploit/multi/samba/usermap_script/) - You can follow the exact steps to get it running and root the box.

## Exploit - Root

And the first msf exploit worked and I got root.

![Untitled](Lame%203ee145cbcc7f4e33b4e117343d4b1292/Untitled%203.png)

GG Rooted 🙂

![Untitled](Lame%203ee145cbcc7f4e33b4e117343d4b1292/Untitled%204.png)