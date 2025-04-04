---
title: Analyzing Banking Trojan - Reversing Apk
date: 2025-04-03
categories: [Reverse Engineering]
tags: [Malware, Reverse Engineering, Apk]
---

Hi Everyone, In this blog we are going to look at the malicious android application that I got on text which looked like this.

<figure><center><img src="/assets/Malware/Malicious.jpg" alt="Banner"  width="252" height="500"></center></figure>

In this blog we are going to look at the behaviour and the capabilities of the malicious application. If you look at the message, the malicious actor has tried to create a sense of urgency. Any normal user would have fallen for that. So let's started with analyzing how the application is working.

## Basic Analysis

First I uploaded the apk to virustotal for analysis. 
<figure><img src="/assets/Malware/Virustotal.png" alt="Virustotal Result"></figure>

After uploading the APK to VirusTotal, I examined its SHA-256 hash and other key details from the analysis report. The report provided insights into detections by various antivirus engines, file metadata, and potential malicious behaviors. Here are some interesting findings:

```
SHA-256 Hash: 9de2b7bdfec291cf6d091f01494be5203a90d2672f4bf37948e7d638471ae801

File Size: 4.61 MB (4837764 bytes)

Detection Rate: 20/66 security vendors flagged it as malicious

Embedded Certificates: Found potential code signing certificates used for validation

Network Indicators: Observed suspicious domains or IPs contacted by the APK

```

By analyzing these details, I could get an initial understanding of the APK’s potential threats before diving deeper into static and dynamic analysis.
