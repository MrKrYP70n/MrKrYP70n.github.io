---
title: Analyzing Banking Trojan - Reversing Apk
date: 2025-04-03
categories: [Reverse Engineering]
tags: [Malware, Reverse Engineering, Apk]
---

Hi Everyone, In this blog we are going to look at the malicious android application that I got on text which looked like this.

<figure><center><img src="/assets/Malware/Banking-Trojan/Malicious.jpg" alt="Banner"  width="252" height="500"></center></figure>

We are going to look at the behaviour and the capabilities of the malicious application. If you look at the message, the malicious actor has tried to create a sense of urgency. Any normal user would have fallen for that. So let's started with analyzing how the application is working.

## Basic Analysis

First I uploaded the apk to virustotal for analysis. 
<figure><img src="/assets/Malware/Banking-Trojan/Virustotal.png" alt="Virustotal Result"></figure>

After uploading the APK to VirusTotal, I examined its SHA-256 hash and other key details from the analysis report. The report provided insights into detections by various antivirus engines, file metadata, and potential malicious behaviors. Here are some interesting findings:

```
MD5 : 89169d7f297915abda2a0d8a0933f981
 
SHA-1 : fe329b52e6b9f9638e67b334ee49f7dfb5cb52a7

SHA-256 Hash: 9de2b7bdfec291cf6d091f01494be5203a90d2672f4bf37948e7d638471ae801

File Name: Indusind Bank i09.apk

File Size: 4.61 MB (4837764 bytes)

File type: Android | executable | mobile | android | apk

Detection Rate: As of now 20/66 security vendors flagged it as malicious

Embedded Certificates: Found potential code signing certificates used for validation
```
<strong>Certificates Attr:<strong>
<figure><img src="/assets/Malware/Banking-Trojan/Certificate.png" alt="Certificate Signing"></figure>

By analyzing these details, I could get an initial understanding of the application's potential threats before diving deeper into static and dynamic analysis. Now let's get into the static analysis.

## Static Analysis

