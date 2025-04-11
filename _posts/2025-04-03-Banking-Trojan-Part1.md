---
title: Analyzing Banking Trojan - Reversing Apk (Part 1)
date: 2025-04-03
categories: [Reverse Engineering]
tags: [Malware, Reverse Engineering, Apk]
---

Hi Everyone, In this blog we are going to look at the malicious android application that my friend got on text.

<figure><center><img src="/assets/Malware/Banking-Trojan/Malicious.jpg" alt="Banner"  width="252" height="500"></center></figure>

We are going to look at the behaviour and the capabilities of the malicious application. If you look at the message, the malicious actor has tried to create a sense of urgency to lure normal user. So let's started with analyzing how the application is working.

## Basic Analysis

First I uploaded the apk to virustotal for analysis. 
<figure><img src="/assets/Malware/Banking-Trojan/Virustotal.png" alt="Virustotal Result"></figure>

After uploading the APK to VirusTotal, I examined its SHA-256 hash and other key details from the analysis report. The report provided insights into detections by various antivirus engines, file metadata, and potential malicious behaviors. Here are some interesting findings:

```
MD5 : 89169d7f297915abda2a0d8a0933f981
 
SHA-1 : fe329b52e6b9f9638e67b334ee49f7dfb5cb52a7

SHA-256 : 9de2b7bdfec291cf6d091f01494be5203a90d2672f4bf37948e7d638471ae801

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

To statically analyze the application, I opened the application in `jadx-gui`. JADX GUI is a user-friendly tool for reverse-engineering Android APKs by decompiling DEX (Dalvik Executable) files into readable Java source code. It provides a graphical interface to explore an APK's structure, making it easier to analyze its components.

So let's take a look at the `AndroidManifest.xml`. 

<figure><img src="/assets/Malware/Banking-Trojan/AndroidManifestXml.png" alt="AndroidManifestXML"></figure>

<strong>Things to note:</strong>

```
<uses-permission android:name="android.permission.REQUEST_INSTALL_PACKAGES"/>

<package android:name="indieba.indi.indi"/>

android:name="indi.c.c.indichedgvyhedg"
```

Looking at the permission we can conclude that the application is trying to install packages. It’s likely used to drop secondary payloads, dynamically extending the trojan’s capabilities post-installation. This technique is commonly used to evade detection by dynamic analysis sandboxes and static scanners, as the full malicious behavior is deferred until after the initial app is installed. And the `indi.c.c.indichedgvyhedg` is the entry point of the android application.

Now, let's take a look at the class `indi.c.c.indichedgvyhedg`:

<figure><img src="/assets/Malware/Banking-Trojan/mainFunction.png" alt="Main Function"></figure>

The app is basically trying to install 👀 `base.apk` and it was just a stager application. It is first creating a `PackageInstaller.Session`, which enables the application to install the base.apk that is most probably bundled within the assets or dropped somewhere in internal storage.

## Getting the Main Payload (Stage 2)

In the `Resources > assets` folder we can find the `base.apk` that is being installed. We can simply export the base.apk and start the analysis.
<figure><img src="/assets/Malware/Banking-Trojan/Stage_2_baseapk.png" alt="Base APK"></figure>

There is one more way to extract the apk i.e by using the dynamic analysis(adb pull). So let's take a look into it :) 

After this part, it's totally optional so you can skip to next part as we have extracted the main payload apk.

## Dynamic Analysis

For dynamic analysis, I quickly booted up the android device using genymotion running Andriod 11 ... because the genymotion only support the root access upto Android 11 version for the free users. 

Install the apk into the android device just by dropping the file(`apk`) on the device. If you look into the application the drawer the application is installed.
<figure><center><img src="/assets/Malware/Banking-Trojan/Application_Install.png" alt="APK install" width="390" height="580"></center></figure>

Let's take a look at the application and the already installed packages simultaneously using the `adb shell`. To look at the installed packages you can simply go to `/data/data` inside the android device. Note the `indi.c.c` package.

<figure><img src="/assets/Malware/Banking-Trojan/Package_Listing.png" alt="list packages"></figure>

If we click on the Proceed to install, it will ask for the permission to install unknown packages. We also saw this while doing the static analysis

<figure><center><img src="/assets/Malware/Banking-Trojan/Installation Source.png" alt="Install Unknown packages" width="390" height="580"></center></figure>

After approving, in the app it will ask for downloading the another application, which is very suspicious and these is where the malicious application presents. 