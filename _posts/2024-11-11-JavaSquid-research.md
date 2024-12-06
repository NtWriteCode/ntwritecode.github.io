---
title: "New JavaSquid Malware Family: Uncovering an Opportunistic Malware Campaign with Filescan.io"
date: 2024-11-11 08:00:00 +0100
categories: [Malware, Research]
tags: [javascript, javasquid, malware, research, malwareresearch, apt, cybersecurity, threat, threatactor, threatresearch]
description: OPSWAT discovered JavaSquid, a new malware family using fake AI software to infect systems. The campaign, ongoing since mid-July 2024, uses evasive JavaScript techniques and links to previous attacks with stolen digital certificates from Chinese companies. Insights gained have enhanced OPSWAT's MetaDefender Sandbox capabilities.
---

# Executive Summary 
Filescan.io's Threat Research Team has identified a wide infection campaign, likely with financial motivation, using fake AI software as a lure for downloading a newly discovered malware family in which we’ve dubbed “JavaSquid” namely for its multiple evasive/slipery JavaScript parts.   
  
Based on our monitoring thanks to Filescan.io's capabilities, we’ve assessed that the campaign remains ongoing and that it started around mid-July of 2024. The threat actors associated with this campaign have conducted previous successful attacks where they stole digital certificates from different Chinese companies.
Besides uncovering a new malware family and a live campaign, the findings of this research and monitoring have allowed the improvement of our Sandbox’s feature/indicator capabilities. Additionally, our investigation provides enough information to implement a comprehensive instance of a Diamond Model of Intrusion Analysis along with the provided IOCs (indicators of compromise) and specific MITRE ATT&CK mappings from Filescan.io's reports.
[You can find Filescan.io report here.](https://www.filescan.io/uploads/672231bb2734cb737d901c74/reports/e5b27d3e-0d46-44fc-9e11-9ca7ce03319b) 

# Uncovering the Campaign 

Filescan.io's Threat Research Team has uncovered an infection campaign that uses AI software as a lure but does not actually utilize AI in its attacks or malware. The investigation started when we observed the suspicious domain, `https[://]my-profai[.]com`. While the domain seems to be already taken down, it was registered on 2024-09-05, meaning that the campaign was very recently launched and is likely still ongoing, based on the information gathered during our investigation. 

According to the title of their website “Epivaravomw: Bringing Your Static Images to Life” it seems that they would offer an AI-based tool to add motion to pictures which points to a potential watering hole attack, which also leverages malvertising on other websites to lead the users to download the malware. However, it is likely an impersonation of https://proai.co, as the Windows executable available for download is named ProAI.exe, which is the malware sample we will analyze ahead. 

![img-description](/assets/img/2024-11-11-JavaSquid-research/ai-site.png)

Such techniques for initial compromise indicate that the threat actors behind the campaign are seeking opportunistic infections and therefore likely acting with financial motivation, potentially as an IAB (Initial Access Broker). Based on the location for the sample submissions, it is very likely that the target of the campaign is mainly Europe. 

The watering hole domain used to trick the victims and serve the malware is protected by Cloudflare. However, their malware sample will contact a different domain which resolves into an IP address that is also pointed by many other domains. Many of the different domains pointing to the same IP address also seem to be related to the AI-tech lure and impersonation of other companies.  

Interestingly, our OSINT research indicated that the C2 IP address was previously related to Lumma and Poseidon stealers. While the Lumma stealer was reportedly based on the old Mars stealer, Poseidon is a very recently discovered malware family written in AppleScript, therefore targeting iOS environments. The fact that this novel family is written in JavaScript could indicate that the threat actor behind the activity could be switching to a scripting language that could be used in different environments. Another aspect to highlight is the fact that the IP address belongs to a Chinese ISP (Chang Way Technologies Co. Limited) while it the host is geolocated within the Russian Federation. 

The initial malware sample had a valid digital signature by the time we first analyzed it (November 9th, 2024), issued by a Chinese company `Taigu Fulong Electronic Tech Co., Ltd`.  However, we observed that during our investigation it had been already revoked. 

| | |
| --- | ----------- |
![img-description](/assets/img/2024-11-11-JavaSquid-research/fs-analysis-1.png)  |  ![img-description](/assets/img/2024-11-11-JavaSquid-research/fs-analysis-2.png)
 
While researching similar samples using our Sandbox hunting engine, we found a set of samples of the same family using the same likely stolen digital certificate, but also two new sets of samples. One of the sets did not have any digital signature while the other used a different digital certificate. All samples followed the same patterns and techniques of pretending to be some legitimate utility tool based on their different given names (`ai_Generation.exe`, `sweethome3d.exe`, `Installer_capcut_pro_x64.exe`...). 

![img-description](/assets/img/2024-11-11-JavaSquid-research/hits.png)

Based on our findings, this campaign started around mid-July and is currently ongoing as we keep observing new samples of the family as recently as the last week of October 2024. Additionally, while the certificate from the initial sample was revoked during our investigation, the other discovered certificate from the different set is still valid and was issued in early September, potentially indicating that the issuer may be compromised, and they were not aware until we contacted them reporting about their certificate being used in malware. 

# Understanding the Malware

While Filescan.io flags many capabilities of the original PE (Report: https://www.filescan.io/uploads/672231bb2734cb737d901c74/reports/e5b27d3e-0d46-44fc-9e11-9ca7ce03319b) and its later stages as explained ahead, at the time of this writing, the initial malware sample remains fully undetected by most AV vendors 

![img-description](/assets/img/2024-11-11-JavaSquid-research/vt.png)
_https://www.virustotal.com/gui/file/999abd365022c5d83dd2db4c0739511a7ac38bcd9e3aa19056d62d3f5c29ca30/detection_

The PE is compiled JavaScript malware, using the [pkg tool](https://github.com/vercel/pkg) to turn the JavaScript code into a Windows PE. Compiled JavaScript appears to be on the rise within the threat landscape, as recently reported by the [other researchers](https://research.checkpoint.com/2024/exploring-compiled-v8-javascript-usage-in-malware/). The mentioned tool packages a JavaScript payload into a Windows PE by embedding a Node JS/V8 interpreter with the option of compiling the code into V8 bytecode, hence embedding into the PE either the plaintext code or a JavaScript Compiled bytecode. The plaintext version extraction is trivial in most cases, though, Filescan.io can extract the compiled code as a JSC (JavaScript Compiled file) and disassemble for later further analysis. 

![img-description](/assets/img/2024-11-11-JavaSquid-research/extracted.png) 

The JavaScript payload holds the relevant payload base64 encoded, decodes it, and executes it using the eval function. This decoded payload starts by running a quick RAM size check, likely to avoid executing on analysis environments. While many traditional sandboxes would not pass through this check, Filescan.io performs deeper analysis of all the JavaScript code, allowing the trigger of relevant indicators. 

 
 

When the check is passed, the sample will execute an HTTP request to a google calendar event URL, which stores in its description a second URL in base64 format. 

 
 

The decoded URL points to a domain controlled by the attacker, which serves a new base64 payload after the corresponding request. Upon decoding the new JavaScript payload, it is also immediately executed using the eval function. This additional JavaScript code decrypts and executes an additional layer hardcoded payload using AES encryption.  

 

 
 
 

 

Interestingly, the IV and AES keys are obtained from the response headers of the last HTTP request, which we have observed are different on every request, meaning that the served payload and headers are dynamically created on every request to the C2 to be decrypted with different keys. Furthermore, the decrypted payload seems to be always the same, but with a different obfuscation, revealing that not only the encryption but also the obfuscation occurs dynamically on every request.  This technique could not only hamper forensic analysis in case of an incident, or threat research, but it would also evade signature-based detections since the obfuscation is different on every request. 

This newly decrypted module is highly obfuscated and brings many more functionality to the sample by adding the code of additional libraries, mainly to deal with file operations and zip functionalities using the adm module. Additionally, it drops different files in different subdirectories %appdata%\Local, using random naming. 

One of the dropped files is a PowerShell script named as run.ps1, which contains the code to install the NodeJS MSI installer for later launching the final JavaScript payload using the installed NodeJS, instead of the initial compiled JavaScript payload. 

 
 

At this point, the execution will trigger an error message for the user in the form of a pop-up, likely to lead the victim into thinking the expected “AI software” (ProAI.exe) may not be able to run on their system, deviating their attention from the ongoing JavaSquid infection. This later-stage JavaScript payload will also download one last JavaScript file using the same mechanism of contacting google calendars, then contacting their controlled domain using the HTTP response headers to decrypt the finally served payload. This time, the final payload will be saved as index.js in a directory with a random name located inside the %appdata%/Romaing directory. 

The previous run.ps1 file will be later replaced with a different PowerShell script using the same name and also immediately executed. As we can see from the screenshot, this script is just used to gain persistence on the machine, while the main malware code was written in index.js. 

 
 

Additional files dropped by the malware: 

     VeqVMR.zip (randomly generated name): Downloaded from the same C2. It only contains a notepad installer (npp.8.6.6.Installer.exe) apparently without impact on the overall behaviour. 
    bypass.ps1: used to execute the previously mentioned run.ps1, while bypassing the powershell script running restriction. 
    NiOihmgUci.msi (randomly generated name): nodejs installer, retrieved from its official website. 
    Update.lnk: Dropped on startup folder, it will point to the PowerShell script run.ps1. 

  

 
As mentioned, the final payload is saved into the victim’s machine as index.js. It is also highly obfuscated and encrypted dynamically on every request, following the same flow described before for the middle stage payload (google calendar, base64 URL, payload decryption). However, since this is the latest stage of the JavaSquid infection chain, the decryption keys are written into the script itself, which allowed Filescan.io to identify, extract, and decrypt the very final payload for thorough analysis. 

https://www.filescan.io/uploads/672232297b6de3d3d3569e26/reports/aff52866-60a2-4b61-bfa6-31f5292aadb3 

 

 
 

Interestingly, we have found out that the current served index.js has been switching to different versions which include improved implementation and slightly different features. This supports the hypothesis that the campaign is still alive, with the JavaSquid final payload still being under development. The file has consistently been served as a one-liner JavaScript with a middle-stage payload encoded in base64, containing hardcoded keys for AES decryption. As shown in the previous screenshot, this decrypts and executes the final payload, highlighting the payload chain in the analysis of index.js. 

The initial served payload implements its communication with C2 through the websocket protocol. It parsed the messages from the C2 in json format looking for the “command” element, which should be received in base64 format. However, the latest served payload had similar functionality but used HTTP request for its C2 communications. Additionally, while this family still being a very basic backdoor, we observed that the latest JavaSquid code that was served included new information gathering and stealing functionalities. 

 
 

Indicators of compromise

File hashes: 

999abd365022c5d83dd2db4c0739511a7ac38bcd9e3aa19056d62d3f5c29ca30 

Aec44665395d4ae7064ea08d6d03b729464715d2169c629f3e3215d61c1299ea 

b216880a67fc2e502ae94928aead75ef870fbb7ba142f7eda355d9ed6e72146d 

Email accounts: 

chackopanikulamskykat@gmail.com 

kendalllopez149@gmail.com 

IP address: 

45.93[.]20.174 

Domains: 

ambisecperu[.]com 

angelswipe [.]com 

nenkinseido[.]com 

URLs: 

hxxps://calendar.app[.]google/X97t5bVooB2ti1QB8 

hxxps://calendar.app[.]google/pPGGk4W26WW7oJxN7 

hxxps://calendar.app[.]google/fD8MeHaN46bfYy3SA 

hxxps://ambisecperu[.]com/a74Uxj9QjqWbeKr2SYOHsw%3D%3D 

hxxps://ambisecperu[.]com/lBdvVW3MiQgpwRGAl5KNwg%3D%3D 

hxxps://ambisecperu[.]com/o2BF9EGgskwn0k5Cwo7kugjt7xChBPSnghiJkDU7MwQ%3D 

wss://ambisecperu[.]com/ss_ss?uuid=L07nKQ%2FEG1qQXwzQ1Tv3vqduOgfze7Yz3Ry%2FrXnr8WY%3D 

hxxp://angelswipe[.]com?uuid=1sdtM0o5b35Uhe6wp9nM5UMMZ8BNrbYwtT1LAvW4rRA%3D 

hxxps://nenkinseido[.]com/a3vNlpuRk6O5S469pG17Gw%3D%3D 

hxxps://nenkinseido[.]com/YMvBag0VXbce5q0WvNrMRg%3D%3D 

Certificate Fingerprints: 

9A:84:A9:7F:AC:26:DF:5C:8A:74:FB:E6:88:0A:0B:5D:A5:17:08:DC 

BB:F9:86:55:F4:D4:ED:39:6F:BC:A9:5F:4A:F8:ED:4E:B0:19:50:A9 

 
Additional IOCs 

Different domains pointing to the same IP address, which have not been used by the analyzed samples, but also seem to be related for faking AI-related websites: 
 
agattiairport[.]com 

aimodel[.]itez-kz[.]com 

akool[.]cleartrip[.]voyage 

akool[.]techdom[.]click 

akordiyondersi[.]com 

albanianvibes[.]com 

albert[.]alcokz[.]store 

albert[.]flora-kz[.]store 

apkportion[.]com 

asd[.]leboncoin-fr[.]eu 

basgitardersi[.]com 

bendiregitimi[.]com 

bybit[.]travel-watch[.]org 

cap[.]cleartrip[.]voyage 

dipo[.]cleartrip[.]voyage 

face[.]techdom[.]click 

facetwo[.]techdom[.]click 

ftp[.]millikanrams[.]com 

haiper[.]techdom[.]click 

haiper[.]travel-watch[.]org 

havoc[.]travel-watch[.]org 

l[.]apple-kz[.]store 

liama[.]cleartrip[.]voyage 

loader[.]waltkz[.]com 

locktgold[.]travel-watch[.]org 

luminarblack[.]techdom[.]click 

millikanrams[.]com 

openaai[.]clear-trip-ae[.]com 

proai[.]travel-watch[.]org 

sweethome[.]travel-watch[.]org 

synthesia[.]flow-kz[.]store 

synthesia[.]techdom[.]click 

uizard[.]flow-kz[.]store 

upscayl[.]cleartrip[.]voyage 