---
title: Analyzing Banking Trojan - Reversing Apk (Part 2)
date: 2025-04-11
categories: [Reverse Engineering]
tags: [Malware, Reverse Engineering, Apk]
---

Welcome Back to the Part2 of Analyzing the Banking trojan. In this part we are going to look at the main payload application that the dropper has installed on our device. As always we are going to start with the Basic Analysis by uploading apk to the virustotal for getting the overview of application's behaviour.

## Basic Analysis

<figure><img src="/assets/Malware/Banking-Trojan/Virustotal_payload.png" alt="Virustotal Result"></figure>

The virustotal has given a detailed analysis report and categorized the threat label to be `banker bot`. Let's note all the necessary information and proceed with the static analysis of the application. 

```
MD5 : d2b29820705cf68cecdf260a72836184
 
SHA-1 : 7c223157f6e51f27048bde243b1de6cc9cbd82e1

SHA-256 : dbb0d8566ea1845719deb840396ccb42d0439d6a26aed56e202ed95db3aeb52a

File Name: payload.apk

File Size: 1.53 MB (1600455 bytes)

File type: Android | executable | mobile | android | apk

Detection Rate: As of now 19/65 security vendors flagged it as malicious

Embedded Certificates: Found potential code signing certificates used for validation
```

Okay, So now we have enough info for the identification of this malware. Let's get into the static analysis.

## Static Analysis

To statically analyze the application, I used `jadx-gui` to extract and decompile the apk. You can use apktool or the jadx CLI version to extract the application too. Now let's take a look the `AndroidManifest.xml` which serves as a entrypoint for the analysing the application.

<figure><img src="/assets/Malware/Banking-Trojan/AndroidManifestXml2.png" alt="AndroidManifest XML"></figure>

<strong>Things to note:</strong>

```xml
Package Name:
    indieba.indi.indi

User Permissions: 
    <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE"/>
    <uses-permission android:name="android.permission.RECEIVE_SMS"/>
    <uses-permission android:name="android.permission.INTERNET"/>
    <uses-permission android:name="android.permission.SEND_SMS"/>
    <uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED"/>
    <uses-permission android:name="android.permission.FOREGROUND_SERVICE"/>
    <uses-permission android:name="android.permission.READ_SMS"/>
    <uses-permission android:name="android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS"/>
    <uses-permission android:name="android.permission.FOREGROUND_SERVICE_DATA_SYNC"/>
    <uses-permission android:name="android.permission.WAKE_LOCK"/>

Main activity:
    android:name="indieba.indi.indi.myodyrurjpvobweyo"
```

The permission that is asking is very dangerous, granting the access will give the attacker basically full control over the device. The attacker can send/read/recieve messages, the permission `android.permission.FOREGROUND_SERVICE`, `android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS`, `android.permission.FOREGROUND_SERVICE_DATA_SYNC` allows attacker to continously run the app in the backgroud irrespective of restrictions like battery optimizations, the app will continiously send the data to the attacker.

Now the main question is where and how the data is being sent to the attacker because there is no point of collecting this much data and not sending it anywhere ..... this sparked my intrest more to reverse enginner the application, So I looked at the main activity `indieba.indi.indi.myodyrurjpvobweyo`.

<figure><img src="/assets/Malware/Banking-Trojan/Malware_main.png" alt="Main Function"></figure>


