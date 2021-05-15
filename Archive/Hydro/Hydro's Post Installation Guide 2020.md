## Hydro's Post Installation Guide

**Disclaimer
I and other people are absolutely not responsibleif anything goes wrong in your PC, everything I sharehere was carefully tested.**

**Introducion**
Welcome to my guide, here, we will learn what to doafter you completely install your new OS, we willgo through Affinites, Msi mode, NVIDIA tweaking,and more...

This guide is not entirely for stock OS’es, you canuse custom ISO’s like Reversal Windows 8.1 or makeyour own (recommended) by making your own OS throughNTLite or WinToolKit(which I don’t use, I use NTLite)you can make it more customize for you, you
can remove lots of drivers that you don’t need, etc,anyway, let’s not get out of the guide subject.
There are a lot of ways to Post Install, everybodydoes different things, in this guide I’ll show whatI do so you can follow along.

**- Installing an NVIDIA driver**
Let’s first start by installing an NVIDIA driver,easy to do, everyone knows how to do it.
Clickhereto go to the NVIDIA drivers section
If you want older drivers like 339.24 etc, you cangoogle them.
- Choose your graphics card, OS, download type(you mostlikely don’t need to touch it, it should be on GameReady Driver) and language.
- once you’re done, click on search, the latest shouldpop up
- Click on download, it should look like this:
- Don’t run the driver just yet, we still have thingsto do.

**Stripping NVIDIA driver’s bloatware.**


- Clickhereto download NVCleanstall, I choose NVCleanstall to stripNVIDIA drivers, you can do that manually or choose to download something else likeNVSlimmer.
    - Once it finishes downloading, open NVCleanstall_1.7.0.exe.
       - By the way, you can install the latest NVIDIA driverfrom the program but for me it’s slow and takes time,that’s why I go to NVIDIA site to download drivers.
          - Select “Use driver files on disk in the NVCleanstallprogram, and go to the folder where your NVIDIA driveris downloaded, select it and in the program, selectnext.
             - It should look like this now
                - For best performance, I’d suggest to keep “DisplayDriver” only, no ShadowPlay or GeForce Experience,just please don’t ;)
                   - Click on next and it’s now preparing sources, wait1 minute until it finishes copying installer files.
                      - Now it should take you to “Installation Tweaks”, inthis area we can for example, disable installer telemetry,Perform a clean installation etc.
                         - Select “Disable Installer Telemetry & Advertising”,“Perform a Clean Installation”.
                            **- Show Expert Tweaks**
                               - “Disable Driver Telemetry”
                                  - Disable NVIDIA HD Audio device sleep timer”
                                     - “Enable Message Signaled Interrupts”
                                     - Click on next and wait 3 - 4 minutes til it’s done.
                                        - Now it should like this:


- Click on “Install” if you wish to install your driverright now, click on “Show in Folder” if you wishto save the files for later on.
    - Agree to the license → Select Custom(Advanced) →Next, and the driver is going to install on your PC.
       - Wait 2 - 3 minutes.

**Installing NVIDIA Profile Inspector and importing.nip file**

- Clickhereto install NVIDIA Profile Inspector
    - Once finishing download, installRIOT NVIDIA nip filecredit goes to RIOT.
       - By the way, you can always make your own profile,I’m just too lazy to make one.
          - On NVIDIA Profile Inspector top bar, fınd the importprofile(s) button and click on it
             - Search for RIOT profile and select it
                - Everything should now be applied, click on “Applychanges” and exit the program.

**Tweaking NVIDIA Control Panel**

**-** Go to your NVIDIA Control Panel and copy the settingsbelow:
    **- Adjust image settings with preview**


- Select Use my preference emphasizing and drag the line to “Performance” and click on “Use the advanced 3D image settings
    **- Configure Surround, PhysX**
       - On PhysX settings Processor, choose your graphicscard
          **- Set up digital audio**
             - If you have 2 monitors select “Turn off audio” inboth of them, if you have 1, select “Turn off audio”
                **- Adjust desktop size and position**
                   - Scaling → Select a scaling mode → No scaling, ifyou have 2 monitors then select No scaling for the2nd monitor too.
                   **- Adjust video color settings**
                   - Select With the NVIDIA settings → Advanced → Dynamicrange: Full (0-255)
                   **- Adjust video image settings**
                   - In Edge enhancement, select Use the NVIDIA settings
                   - In Noıse reduction, select Use the NVIDIA settıngs
                   - Deinterlacing → use inverse telecine

```
Device Manager Tweaking
```
- Open Device Manager in the top bar, go to vıew andselect “Devices by connection” and copy these settingsbelow;
    - Disable UMBus Root Bus Enumerator
       - Disable Remote Desktop Device Redirector Bus
          - Disable NDIS Virtual Network Adapter Enumerator
             - Disable Microsoft Virtual Drive Enumerator
                - Disable Microsoft System Management BIOS Driver
                   - Disable Composite Bus Enumerator
                      - Disable SM Bus Controller
                         - Disable PCI Memory Controller
                         - Disable PCI Simple Communications Controller
                         - Disable all the PCI-to-PCI that doesn’t have anythinginside them + Disable PCI-to-PCI Bridge that hasPCI-to-PCI Bridge inside it like this:

**DirectX Installation**

- Go tohereto download DirectX
    - When you install DirectX, uncheck “Install the BingBar” it’s a bloatware, you obviously don't need it.

**Visual C++ Installation**

- Clickhereto download Visual C++ all in one pack
- When it finishing downloading unzip the .zip file,and double click on the “install_all.bat” file inthe folder


Sometimes it requires restarting your PC, click Yand let it restart your PC, once you boot into thePC go to the folder again and run the batch fileonce again, give it a few seconds / minutes untileverything is installed on your PC.

**Setting up affinites**

- For example we have 4 cores CPU, we are using Windows10 1809, and we didn’t even touch anything, Microsoftput all theinterruptsinto core 0, instead ofofdividing it into several cores, but, if we’re usingaapplicationthat will
    actually dividing someinterruptsto several cores,we will reduce the the stress on the core 0, andwe will stabilize it to the other cores, so, of coursethe performance will increase.
       - If you want more information about affinities andyou would like to learn more, go to myguıdeaboutaffinities, there is more information there.
          - DownloadMicrosoft Interrupt Affinity Policy Tooland install it
             - Go to C:\Program Files (x86)\Microsoft Corporation\InterruptAffinity Policy Tool and open intPolicy_x64.exe
                **-** Click on set mask if you wish to apply affinity toan interrupt
                   - **Set affinities to:**
                      - Graphics card, PCI-to-PCI Bridges, Network card andUSB
                         - You need to benchmark every core, because every CPUis different


**MSI Mode**

- Download MSI Mode v3here
    - Open the .exe file and it should look similar to this:


- Set Msi mode for:
    - Tick USB driver, High
    - Tick PCI-to-PCI Bridges,High
    - Tick network card, high
    - Tick Graphics card, hıgh
    - Please do not touch your SATA, you might blue screen.

**Registry Tweaks for Windows 10 1709 +**

- Let’s start by the most basic regedit edit tweaks,to open regedit, just hold WinKey + R and in thesearch box search for “regedit”. Just that.
    **- Game tweaks:**
       **- HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games**
       - "GPU Priority"=dword:
       - "Priority"=dword:
       - "Scheduling Category"="High"
       - "SFIO Priority"="High"


**- Disable Power Throttling
- HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling**
    - "PowerThrottlingOff"=dword:
       **- Disable SpectreMeltdown**
          **- HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management**
          - "FeatureSettingsOverride"=dword:
          - "FeatureSettingsOverrideMask"=dword:
             **- MenuShowDelay**
             **- HKEY_CURRENT_USER\Control Panel\Desktop**
             - “MenuShowDelay”=”0”
                **- Disable Enable Prefetch**
                **- HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\SessionManager\Memory Management\PrefetchParameters**
                - "EnablePrefetcher"=dword:
                **- HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters**
                - "EnablePrefetcher"=dword:
                **- Disable Hibernate**
                **- HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Power**
                - "HibernateEnabled"=dword:
                **- HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power**
                - "HibernateEnabled"=dword:
                **- Disable Network Usage**
                **- HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Ndu**
                - "Start"=dword:
                **- Disable MMCSS**
                **- HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MMCSS**
                - "Start"=dword:

**Telemetry**

- Open CMD as administrator and put these reg add commands,these will disable most of the telemetry in Windows 10
**- reg add "HKCU\Control Panel\International\User Profile"/v "HttpAcceptLanguageOptOut" /t REG_DWORD /d "1"/f >nul 2>&
- reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo"/v "Enabled" /t REG_DWORD /d "0" /f >nul 2>&
- reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost"/v "EnableWebContentEvaluation" /t REG_DWORD /d "0"/f >nul 2>&
- reg add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots"/v "value" /t REG_DWORD /d "0" /f >nul 2>&
- reg add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting"/v "value" /t REG_DWORD /d "0" /f >nul 2>&
- reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config"/v "DownloadMode" /t REG_DWORD /d "0" /f >nul 2>&
- reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\ImmersiveShell"/v "UseActionCenterExperience" /t REG_DWORD /d "0"/f >nul 2>&
- reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection"/v "AllowTelemetry" /t REG_DWORD /d "0" /f >nul 2>&
- reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"/v "HideSCAHealth" /t REG_DWORD /d "1" /f >nul 2>&
- reg add "HKLM\Software\Policies\Microsoft\Windows\AdvertisingInfo"/v "DisabledByGroupPolicy" /t REG_DWORD /d "1" /f>nul 2>&
- reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection"/v "AllowTelemetry" /t REG_DWORD /d "0" /f >nul 2>&
- reg add "HKLM\Software\Policies\Microsoft\Windows\EnhancedStorageDevices"/v "TCGSecurityActivationDisabled" /t REG_DWORD /d"0" /f >nul 2>&
- reg add "HKLM\Software\Policies\Microsoft\Windows\OneDrive"/v "DisableFileSyncNGSC" /t REG_DWORD /d "1" /f >nul2>&
- reg add "HKLM\Software\Policies\Microsoft\Windows\safer\codeidentifiers"/v "authenticodeenabled" /t REG_DWORD /d "0" /f >nul2>&
- reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsError Reporting" /v "DontSendAdditionalData" /t REG_DWORD/d "1" /f >nul 2>&
- reg add "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection"/v "AllowTelemetry" /t REG_DWORD /d "0" /f >nul 2>&**

Credit for the commands:Artanis

**Services tweaking**

- I guess some of you already know, I have a servicestweaking script called “Optiz”, it has a lot of tweakingthere, it took me a lot of time to make.
- Clickhereto view the script, make a registry backupbecause you use and please use it only if you’reon Windows 10 1709 / 1809.


# Thank you for reading!

### Thank you so much for reading my guide, if you madeit here, I appreciate it!

### Consider contacting me at:

### Discord

### https://discord.gg/BMmC7jF

### Twitter

### https://twitter.com/ItayHydro

### If you want to donate to me ( you don’t need to, onlyif you want to gift a coffee) it would be appreciatedand kind!

### https://www.paypal.com/paypalme/ItayHydro


