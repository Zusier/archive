:: This is only for Windows 10 - NOT Server because we kill all remote based execution to e.g. RDP.
:: Make a Backup!! BEFORE you run the script!!
:: Do not run ResetBase! It breaks Windows Updates (0x800f081f) and it can not be repaired!
:: The script needs to be run after every sfc /scannow & "Feature Update"
::
:: Check for ":: --------|> TODO <|--------" within the script because this is always and a constant work-in-progress script!
::
:: Change file associations to protect against common ransomware attacks
:: Note that if you legitimately use these extensions, like .bat, you will now need to execute them manually from cmd or via powershell.
:: Alternatively, you can right-click on them and hit 'Run as Administrator' but ensure it's a script you want to run.
@echo off
setlocal DisableDelayedExpansion
:: ---------------------
:: Changing back example (x64):
:: ftype htafile=C:\Windows\SysWOW64\mshta.exe "%1" {1E460BD7-F1C3-4B2E-88BF-4E770A288AF5}%U{1E460BD7-F1C3-4B2E-88BF-4E770A288AF5} %*
ftype batfile="%systemroot%\system32\notepad.exe" "%1"
ftype chmfile="%systemroot%\system32\notepad.exe" "%1"
ftype cmdfile="%systemroot%\system32\notepad.exe" "%1"
ftype htafile="%systemroot%\system32\notepad.exe" "%1"
ftype jsefile="%systemroot%\system32\notepad.exe" "%1"
ftype jsfile="%systemroot%\system32\notepad.exe" "%1"
ftype vbefile="%systemroot%\system32\notepad.exe" "%1"
ftype vbsfile="%systemroot%\system32\notepad.exe" "%1"
ftype wscfile="%systemroot%\system32\notepad.exe" "%1"
ftype wsffile="%systemroot%\system32\notepad.exe" "%1"
ftype wsfile="%systemroot%\system32\notepad.exe" "%1"
ftype wshfile="%systemroot%\system32\notepad.exe" "%1"
ftype sctfile="%systemroot%\system32\notepad.exe" "%1"
ftype urlfile="%systemroot%\system32\notepad.exe" "%1"
:: https://seclists.org/fulldisclosure/2019/Mar/27
ftype regfile="%systemroot%\system32\notepad.exe" "%1"
:: https://www.trustwave.com/Resources/SpiderLabs-Blog/Firework--Leveraging-Microsoft-Workspaces-in-a-Penetration-Test/
ftype wcxfile="%systemroot%\system32\notepad.exe" "%1"
:: https://bohops.com/2018/08/18/abusing-the-com-registry-structure-part-2-loading-techniques-for-evasion-and-persistence/
ftype mscfile="%systemroot%\system32\notepad.exe" "%1"
:: https://www.trustwave.com/Resources/SpiderLabs-Blog/Firework--Leveraging-Microsoft-Workspaces-in-a-Penetration-Test/
:: ftype wsxfile="%systemroot%\system32\notepad.exe" "%1" :: does not work use mitigation from the article above
:: https://posts.specterops.io/the-tale-of-settingcontent-ms-files-f1ea253e4d39
:: Changing back:
:: reg add "HKCR\SettingContent\Shell\Open\Command" /v DelegateExecute /t REG_SZ /d "{0c194cb2-2959-4d14-8964-37fd3e48c32d}" /f
reg delete "HKCR\SettingContent\Shell\Open\Command" /v DelegateExecute /f
reg add "HKCR\SettingContent\Shell\Open\Command" /v DelegateExecute /t REG_SZ /d "" /f
:: https://rinseandrepeatanalysis.blogspot.com/2018/09/dde-downloaders-excel-abuse-and.html
ftype slkfile="%systemroot%\system32\notepad.exe" "%1"
ftype iqyfile="%systemroot%\system32\notepad.exe" "%1"
ftype prnfile="%systemroot%\system32\notepad.exe" "%1"
ftype diffile="%systemroot%\system32\notepad.exe" "%1"
:: https://posts.specterops.io/remote-code-execution-via-path-traversal-in-the-device-metadata-authoring-wizard-a0d5839fc54f
reg delete "HKLM\SOFTWARE\Classes\.devicemetadata-ms" /f
reg delete "HKLM\SOFTWARE\Classes\.devicemanifest-ms" /f
:: CVE-2020-0765 impacting Remote Desktop Connection Manager (RDCMan) configuration files - MS won't fix it
ftype rdgfile="%systemroot%\system32\notepad.exe" "%1"
:: Mitigate ClickOnce .application and .deploy files vector
:: https://blog.redxorblue.com/2020/07/one-click-to-compromise-fun-with.html
ftype applicationfile="%systemroot%\system32\notepad.exe" "%1"
ftype deployfile="%systemroot%\system32\notepad.exe" "%1"
:: TODO mitigate ClickOnce .appref-ms files vector
:: https://www.blackhat.com/us-19/briefings/schedule/#clickonce-and-youre-in---when-appref-ms-abuse-is-operating-as-intended-15375
:: reg delete "HKLM\SOFTWARE\Classes\.appref-ms" /f
::
:: Workarround for CoronaBlue/SMBGhost Worm exploiting CVE-2020-0796
:: https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/ADV200005
:: Active Directory Administrative Templates
:: https://github.com/technion/DisableSMBCompression
:: Disable SMBv3 compression
:: You can disable compression to block unauthenticated attackers from exploiting the vulnerability against an SMBv3 Server with the PowerShell command below.
:: No reboot is needed after making the change. This workaround does not prevent exploitation of SMB clients.
powershell.exe Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" DisableCompression -Type DWORD -Value 1 -Force
:: You can disable the workaround with the PowerShell command below.
:: powershell.exe Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" DisableCompression -Type DWORD -Value 0 -Force
::
::##########################################################################################################################
:: Specifies how the System responds when a user tries to install device driver files that are not digitally signed / 00 - Ignore / 01 - Warn / 02 - Block
reg add "HKLM\Software\Microsoft\Driver Signing" /v "Policy" /t REG_BINARY /d 01 /f
::
:: Prevent device metadata retrieval from the Internet / Do not automatically download manufacturers’ apps and custom icons available for your devices
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Device Metadata" /v "PreventDeviceMetadataFromNetwork" /t REG_DWORD /d 0 /f
sc config "DsmSvc" start= disabled
::
:: Disable Malicious Software Removal Tool offered via Windows Updates (MRT)
:: Disable Heartbeat Telemetry
:: https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.DataCollection::AllowTelemetry
reg add "HKLM\Software\Microsoft\RemovalTools\MpGears" /v "HeartbeatTrackingIndex" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Microsoft\RemovalTools\MpGears" /v "SpyNetReportingLocation" /t REG_MULTI_SZ /d "" /f
reg add "HKLM\Software\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\MRT" /v "DontReportInfectionInformation" /t REG_DWORD /d 1 /f
:: Windows Defender Device Guard - Exploit Guard Policies
:: Enable ASR rules in Win10 ExploitGuard (>= 1709) to mitigate Office malspam
:: Blocks Office childprocs, Office proc injection, Office win32 api calls & executable content creation
:: Note these only work when Defender is your primary AV
:: Sources:
:: https://www.darkoperator.com/blog/2017/11/11/windows-defender-exploit-guard-asr-rules-for-office
:: https://www.darkoperator.com/blog/2017/11/8/windows-defender-exploit-guard-asr-obfuscated-script-rule
:: https://www.darkoperator.com/blog/2017/11/6/windows-defender-exploit-guard-asr-vbscriptjs-rule
:: https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-exploit-guard/enable-attack-surface-reduction
:: https://demo.wd.microsoft.com/Page/ASR2
:: https://www.powershellgallery.com/packages/WindowsDefender_InternalEvaluationSettings/1.2/Content/WindowsDefender_InternalEvaluationSettings.ps1
:: ---------------------
::%programfiles%\"Windows Defender"\MpCmdRun.exe -RestoreDefaults
::
::Enable Windows Defender sandboxing, on Desktops this is not needed because automatically set but enforcing it do not do any harm.
setx /M MP_FORCE_USE_SANDBOX 1
:: Update WD signatures
"%ProgramFiles%"\"Windows Defender"\MpCmdRun.exe -SignatureUpdate
:: Enable Defender signatures for Potentially Unwanted Applications (PUA)
powershell.exe Set-MpPreference -PUAProtection enable
:: https://docs.microsoft.com/en-us/powershell/module/defender/set-mppreference?view=win10-ps
:: Reduce Defender CPU Fingerprint
:: Windows Defender does not exceed the percentage of CPU usage that you specify. The default value is 50%.
powershell.exe Set-MpPreference -ScanAvgCPULoadFactor 30
:: Enable Defender periodic scanning
reg add "HKCU\SOFTWARE\Microsoft\Windows Defender" /v PassiveMode /t REG_DWORD /d 2 /f
::
:: Enable Windows Defender real time monitoring
:: Commented out given consumers often run third party anti-virus. You can run either.
:: powershell.exe -command "Set-MpPreference -DisableRealtimeMonitoring $false"
:: reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" /v DisableRealtimeMonitoring /t REG_DWORD /d 0 /f
::
:: Enable early launch antimalware driver for scan of boot-start drivers
:: 3 is the default which allows good, unknown and 'bad but critical'. Recommend trying 1 for 'good and unknown' or 8 which is 'good only'
reg add "HKCU\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" /v DriverLoadPolicy /t REG_DWORD /d 3 /f
::
:: Enable Microsoft Defender Antivirus Attack Surface Reduction Rules
:: https://twitter.com/duff22b/status/1280166329660497920
:: https://thalpius.com/2020/11/02/microsoft-defender-antivirus-attack-surface-reduction-rules-bypasses/
::
:: Block Office applications from creating child processes
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids D4F940AB-401B-4EFC-AADC-AD5F3C50688A -AttackSurfaceReductionRules_Actions Enabled
::
:: Block Office applications from injecting code into other processes
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84 -AttackSurfaceReductionRules_Actions enable
::
:: Block Win32 API calls from Office macro
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B -AttackSurfaceReductionRules_Actions enable
::
:: Block Office applications from creating executable content
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 3B576869-A4EC-4529-8536-B80A7769E899 -AttackSurfaceReductionRules_Actions enable
::
:: Block Office communication application from creating child processes
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 26190899-1602-49E8-8B27-EB1D0A1CE869 -AttackSurfaceReductionRules_Actions Enabled
::
:: Block Adobe Reader from creating child processes
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C -AttackSurfaceReductionRules_Actions Enabled
::
:: Block execution of potentially obfuscated scripts
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 5BEB7EFE-FD9A-4556-801D-275E5FFC04CC -AttackSurfaceReductionRules_Actions Enabled
::
:: Block executable content from email client and webmail
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 -AttackSurfaceReductionRules_Actions Enabled
::
:: Block JavaScript or VBScript from launching downloaded executable content
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids D3E037E1-3EB8-44C8-A917-57927947596D -AttackSurfaceReductionRules_Actions Enabled
::
:: Block executable files from running unless they meet a prevalence, age, or trusted list criteria
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 01443614-CD74-433A-B99E-2ECDC07BFC25 -AttackSurfaceReductionRules_Actions Enabled
::
:: Use advanced protection against ransomware
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids C1DB55AB-C21A-4637-BB3F-A12568109D35 -AttackSurfaceReductionRules_Actions Enabled
::
:: Block credential stealing from the Windows local security authority subsystem (lsass.exe)
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2 -AttackSurfaceReductionRules_Actions Enabled
::
:: Block untrusted and unsigned processes that run from USB
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4 -AttackSurfaceReductionRules_Actions Enabled
::
:: Block persistence through WMI event subscription
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids E6DB77E5-3DF2-4CF1-B95A-636979351E5B -AttackSurfaceReductionRules_Actions Enabled
::
:: Block process creations originating from PSExec and WMI commands
powershell.exe Set-MpPreference -AttackSurfaceReductionRules_Ids D1E49AAC-8F56-4280-B9BA-993A6D77406C -AttackSurfaceReductionRules_Actions Enabled
::
:: Enable Controlled Folder Access against Ransomware
:: powershell.exe Set-MpPreference -EnableControlledFolderAccess Enabled
::
:: Enable Cloud functionality of Windows Defender
powershell.exe Set-MpPreference -MAPSReporting Advanced
powershell.exe Set-MpPreference -SubmitSamplesConsent Always
::
:: Enable Defender exploit system-wide protection
:: The commented line includes CFG which can cause issues with apps like Discord & Mouse Without Borders
:: powershell.exe Set-Processmitigation -System -Enable DEP,EmulateAtlThunks,BottomUp,HighEntropy,SEHOP,SEHOPTelemetry,TerminateOnError,CFG
powershell.exe Set-Processmitigation -System -Enable DEP,EmulateAtlThunks,BottomUp,HighEntropy,SEHOP,SEHOPTelemetry,TerminateOnError
::
:: Enable Windows Defender Application Guard
:: This setting is commented out as it enables subset of DC/CG which renders other virtualization products unsuable. Can be enabled if you don't use those
:: powershell.exe Enable-WindowsOptionalFeature -online -FeatureName Windows-Defender-ApplicationGuard -norestart
::
:: Enable Windows Defender Credential Guard
:: This setting is commented out as it enables subset of DC/CG which renders other virtualization products unsuable. Can be enabled if you don't use those
:: reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 1 /f
:: reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v RequirePlatformSecurityFeatures /t REG_DWORD /d 3 /f
:: reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v LsaCfgFlags /t REG_DWORD /d 1 /f
::
:: Enable Network protection
:: Enabled - Users will not be able to access malicious IP addresses and domains
:: Disable (Default) - The Network protection feature will not work. Users will not be blocked from accessing malicious domains
:: AuditMode - If a user visits a malicious IP address or domain, an event will be recorded in the Windows event log but the user will not be blocked from visiting the address.
powershell.exe Set-MpPreference -EnableNetworkProtection Enabled
::
::##########################################################################################################################
:: Enable exploit protection (EMET on Windows 10)
:: Sources:
:: https://blogs.windows.com/windowsexperience/2018/03/20/announcing-windows-server-vnext-ltsc-build-17623/
:: https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/exploit-protection-reference
:: Windows10-v1709_ExploitGuard-DefaultSettings.xml is taken from a fresh Windows 10 v1709 Machine
:: Windows10-v1803_ExploitGuard-DefaultSettings.xml is taken from a fresh Windows 10 v1803 Machine
:: Windows10-v1809_ExploitGuard-DefaultSettings.xml is taken from a fresh Windows 10 v1809 Machine
:: Windows10-v1903_ExploitGuard-DefaultSettings.xml is taken from a fresh Windows 10 v1903 Machine
:: Windows10-v1909_ExploitGuard-DefaultSettings.xml is taken from a fresh Windows 10 v1909 Machine (but no Changes to v1903)
:: Windows10-v2004_ExploitGuard-DefaultSettings.xml is taken from a fresh Windows 10 v2004 Machine
:: Windows10-v2009_ExploitGuard-DefaultSettings.xml is taken from a fresh Windows 10 v2009 Machine
:: Windows10-v1709_ExploitGuard-Security-Baseline.xml is taken from the official Microsoft v1709 Baseline
:: Windows10-v1803_ExploitGuard-Security-Baseline.xml is taken from the official Microsoft v1803 Baseline
:: Windows10-v1809_ExploitGuard-Security-Baseline.xml is taken from the official Microsoft v1809 Baseline
:: Windows10-v1903_ExploitGuard-Security-Baseline.xml is taken from the official Microsoft v1903 Baseline
:: Windows10-v1909_ExploitGuard-Security-Baseline.xml is taken from the official Microsoft v1909 Baseline
:: Windows10-v2004_ExploitGuard-Security-Baseline.xml is taken from the official Microsoft v2004 Baseline
:: Windows10-v2009_ExploitGuard-Security-Baseline.xml is taken from the official Microsoft v2009 Baseline
:: ---------------------
powershell.exe Invoke-WebRequest -Uri https://demo.wd.microsoft.com/Content/ProcessMitigation.xml -OutFile ProcessMitigation.xml
powershell.exe Set-ProcessMitigation -PolicyFilePath ProcessMitigation.xml
del ProcessMitigation.xml
::
::##########################################################################################################################
:: Windows Defender Device Guard - Application Control Policies
:: https://www.petri.com/enabling-windows-10-device-guard
:: http://flemmingriis.com/building-a-secure-workstation-one-step-at-a-time-part1/
:: http://www.exploit-monday.com/2016/12/updating-device-guard-code-integrity.html
:: https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-block-rules
:: https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/merge-windows-defender-application-control-policies
:: https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/deploy-windows-defender-application-control-policies-using-group-policy
:: https://github.com/MicrosoftDocs/windows-powershell-docs/blob/master/docset/windows/configci/new-cipolicy.md
:: https://github.com/MicrosoftDocs/windows-powershell-docs/blob/master/docset/windows/configci/merge-cipolicy.md
:: https://github.com/MicrosoftDocs/windows-powershell-docs/blob/master/docset/windows/configci/get-cipolicy.md
:: https://docs.microsoft.com/en-us/powershell/module/configci/new-cipolicy?view=win10-ps
:: https://docs.microsoft.com/en-us/powershell/module/configci/merge-cipolicy?view=win10-ps
:: https://docs.microsoft.com/en-us/powershell/module/configci/get-cipolicy?view=win10-ps
:: https://insights.adaptiva.com/2018/windows-defender-application-control-configmgr-intune/
:: https://improsec.com/tech-blog/one-thousand-and-one-application-blocks
:: --------|> TODO <|--------
::
::##########################################################################################################################
:: Harden all version of MS Office against common malware spam attacks
:: Disables Macros, enables ProtectedView
:: Sources:
:: https://decentsecurity.com/block-office-macros/
:: ---------------------
reg add "HKCU\Software\Policies\Microsoft\Office\12.0\Publisher\Security" /v "vbawarnings" /t REG_DWORD /d 4 /f
reg add "HKCU\Software\Policies\Microsoft\Office\12.0\Word\Security" /v "vbawarnings" /t REG_DWORD /d 4 /f
reg add "HKCU\Software\Policies\Microsoft\Office\14.0\Publisher\Security" /v "vbawarnings" /t REG_DWORD /d 4 /f
reg add "HKCU\Software\Policies\Microsoft\Office\14.0\Word\Security" /v "vbawarnings" /t REG_DWORD /d 4 /f
reg add "HKCU\Software\Policies\Microsoft\Office\15.0\Outlook\Security" /v "markinternalasunsafe" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Policies\Microsoft\Office\15.0\Word\Security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Office\15.0\Excel\Security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Office\15.0\PowerPoint\Security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Office\15.0\Word\Security" /v "vbawarnings" /t REG_DWORD /d 4 /f
reg add "HKCU\Software\Policies\Microsoft\Office\15.0\Publisher\Security" /v "vbawarnings" /t REG_DWORD /d 4 /f
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\Outlook\Security" /v "markinternalasunsafe" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\Word\Security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\Excel\Security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\PowerPoint\Security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\Word\Security" /v "vbawarnings" /t REG_DWORD /d 4 /f
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\Publisher\Security" /v "vbawarnings" /t REG_DWORD /d 4 /f
:: Enable AMSI for all documents by setting the following registry key - Office 2016 or Office 365 installed
:: https://getadmx.com/?Category=Office2016&Policy=office16.Office.Microsoft.Policies.Windows::L_MacroRuntimeScanScope
:: https://malwaretips.com/threads/office-365-and-amsi-support-for-vba-macros.87281/
reg add "HKCU\Software\Microsoft\Office\16.0\Common\Security" /v "MacroRuntimeScanScope" /t REG_DWORD /d 2 /f
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\Common\Security" /v "MacroRuntimeScanScope" /t REG_DWORD /d 2 /f
reg add "HKCU\Software\Microsoft\Office\14.0\Word\Options" /v "DontUpdateLinks" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Office\14.0\Word\Options\WordMail" /v "DontUpdateLinks" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Office\15.0\Word\Options" /v "DontUpdateLinks" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Office\15.0\Word\Options\WordMail" /v "DontUpdateLinks" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Office\16.0\Word\Options" /v "DontUpdateLinks" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Office\16.0\Word\Options\WordMail" /v "DontUpdateLinks" /t REG_DWORD /d 1 /f
::
::##########################################################################################################################
:: Harden Adobe Acrobat Reader against embeded malicious files - block ALL embeded files
:: https://blog.nviso.be/2018/07/26/shortcomings-of-blacklisting-in-adobe-reader-and-what-you-can-do-about-it/
:: https://www.adobe.com/devnet-docs/acrobatetk/tools/Wizard/WizardDC/attachments.html
:: ---------------------
reg add "HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" /v "iFileAttachmentPerms" /t REG_DWORD /d 1 /f
::
::##########################################################################################################################
:: General OS hardening
:: Disable DNS Multicast, NTLM, SMBv1, NetBIOS over TCP/IP, PowerShellV2, AutoRun, 8.3 names, Last Access timestamp and weak TLS/SSL ciphers and protocols
:: Enables UAC, SMB/LDAP Signing, Show hidden files
:: ---------------------
:: Time Zone - Central Europe Standard Time
:: tzutil /s "Central Europe Standard Time"
:: Prevent Kerberos from using DES or RC4
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" /v "SupportedEncryptionTypes" /t REG_DWORD /d 2147483640 /f
:: reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v "EnableMulticast" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v "DisableSmartNameResolution" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "DisableParallelAandAAAA" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "IGMPLevel" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DisableIPSourceRouting" /t REG_DWORD /d 2 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableICMPRedirect" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" /v "DisableIPSourceRouting" /t REG_DWORD /d 2 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "SMB1" /t REG_DWORD /d 0 /f
reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "SMB2" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" /v "RestrictNullSessAccess" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableVirtualization" /t REG_DWORD /d 1 /f
:: reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "SaveZoneInformation" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "NoDataExecutionPrevention" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "NoHeapTerminationOnCorruption" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers" /v "DisableWebPnPDownload" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers" /v "DisableHTTPPrinting" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" /v "AutoConnectAllowedOEM" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" /v "fMinimizeConnections" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netbt\Parameters" /v "NoNameReleaseOnDemand" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" /v "RestrictReceivingNTLMTraffic" /t REG_DWORD /d 2 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" /v "RestrictSendingNTLMTraffic" /t REG_DWORD /d 2 /f
:: No-one will be a member of the built-in group, although it will still be visible in the Object Picker / 1 - all users logging on to a session on the server will be made a member of the TERMINAL SERVER USER group
:: reg add "HKLM\System\CurrentControlSet\Control\Terminal Server" /v "TSUserEnabled" /t REG_DWORD /d 0 /f
:: https://www.top-password.com/blog/prevent-ntlm-credentials-from-being-sent-to-remote-servers/
:: Whitelist IPS for NTLM usage
:: reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" /v "ClientAllowedNTLMServers" /t REG_MULTI_SZ /d "127.0.0.1"\0"127.0.0.2" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" /v "NTLMMinServerSec" /t REG_DWORD /d 537395200 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" /v "NTLMMinClientSec" /t REG_DWORD /d 537395200 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\LSA\MSV1_0" /v "allownullsessionfallback" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "RestrictAnonymousSAM" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "RestrictAnonymous" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "EveryoneIncludesAnonymous" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "RestrictRemoteSAM" /t REG_SZ /d "O:BAG:BAD:(A;;RC;;;BA)" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "UseMachineId" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "LimitBlankPasswordUse" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" /v WpadOverride /t REG_DWORD /d 1 /f
:: https://www.harmj0y.net/blog/redteaming/pass-the-hash-is-dead-long-live-localaccounttokenfilterpolicy/
:: https://en.hackndo.com/pass-the-hash/
:: Affects Windows Remoting (WinRM) deployments
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "LocalAccountTokenFilterPolicy" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "FilterAdministratorToken" /t REG_DWORD /d 1 /f
::
:: https://4sysops.com/archives/mitigating-powershell-risks-with-constrained-language-mode/
:: reg add "HKLM\System\CurrentControlSet\Control\Session Manager\Environment" /v "__PSLockDownPolicy" /t REG_SZ /d 4 /f
:: Disable Powershell Constrained Language Mode (CLM) - (revert to Full Language Mode) needs reboot
:: setx __PSLockdownPolicy 0 /M
:: Enable Powershell Constrained Language Mode (CLM)
setx __PSLockdownPolicy 4 /M
::
:: Always re-process Group Policy even if no changes
:: Commented out as consumers don't typically use Domain joined computers and GPO's
:: reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" /v NoGPOListChanges /t REG_DWORD /d 0 /f
::
:: Force logoff if smart card removed
:: Set to 2 for logoff, set to 1 for lock
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "SCRemoveOption" /t REG_DWORD /d 2 /f
::
:: Prevent unauthenticated RPC connections
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" /v RestrictRemoteClients /t REG_DWORD /d 1 /f
::
:: Disable internet connection sharing
:: Commented out as it's not enabled by default and if it is enabled, may be for a reason
:: reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections" /v NC_ShowSharedAccessUI /t REG_DWORD /d 0 /f
::
:: Enable SMB/LDAP Signing
:: Sources:
:: http://eddiejackson.net/wp/?p=15812
:: https://en.hackndo.com/ntlm-relay/
:: ---------------------
:: Change default DNS Serverto Cloudflare
:: Get-NetIPConfiguration
:: InterfaceIndex 10 differs run above ^ command to check which number your interface has.
:: powershell.exe Set-DnsClientServerAddress -InterfaceIndex 10 -ServerAddresses 1.1.1.1, 1.0.0.1
:: wmic nicconfig get caption,index,TcpipNetbiosOptions
wmic nicconfig where DHCPEnabled=TRUE call SetDNSServerSearchOrder ("1.1.1.1","1.0.0.2")
::
:: ---------------------
:: Disable LMHOSTS Lookup on all adapters
:: 1 - Enable
reg add "HKLM\System\CurrentControlSet\Services\NetBT\Parameters" /v "EnableLMHOSTS" /t REG_DWORD /d 0 /f
::Harden LanMan
reg add "HKLM\System\CurrentControlSet\Services\LanmanWorkStation\Parameters" /v "RequireSecuritySignature" /t REG_DWORD /d 1 /f
reg add "HKLM\System\CurrentControlSet\Services\LanmanWorkStation\Parameters" /v "EnableSecuritySignature" /t REG_DWORD /d 1 /f
reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "RequireSecuritySignature" /t REG_DWORD /d 1 /f
reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "EnableSecuritySignature" /t REG_DWORD /d 1 /f
:: 1- Negotiated; 2-Required
reg add "HKLM\System\CurrentControlSet\Services\NTDS\Parameters" /v "LDAPServerIntegrity" /t REG_DWORD /d 2 /f
reg add "HKLM\System\CurrentControlSet\Services\ldap" /v "LDAPClientIntegrity " /t REG_DWORD /d 1 /f
::
:: Ensure 'Domain member: Digitally encrypt or sign secure channel data (always)' is set to 'Enabled'
reg add "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" /v "RequireSignOrSeal" /t REG_DWORD /d 1 /f
:: Ensure 'Domain member: Digitally encrypt secure channel data (when possible)' is set to 'Enabled'
reg add "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" /v "SealSecureChannel" /t REG_DWORD /d 1 /f
:: Ensure 'Domain member: Digitally sign secure channel data (when possible)' is set to 'Enabled'
reg add "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" /v "SignSecureChannel" /t REG_DWORD /d 1 /f
:: Enforce SmartScreen settings
:: reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "SmartScreenEnabled" /t REG_SZ /d "On" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "ShellSmartScreenLevel" /t REG_SZ /d Block /f
reg add "HKCU\Software\Microsoft\Edge\SmartScreenPuaEnabled" /ve /t REG_DWORD /d 1 /f
:: Enable Windows SmartScreen for Windows Store Apps
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d 1 /f
:: Update apps automatically / 2 - Off / 4 - On
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate" /v "AutoDownload" /t REG_DWORD /d 4 /f
:: Disable Auto-install subscribed/suggested apps (games like Candy Crush Soda Saga/Minecraft)
:: reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "ContentDeliveryAllowed" /t REG_DWORD /d 0 /f
:: reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "OemPreInstalledAppsEnabled" /t REG_DWORD /d 0 /f
:: reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEnabled" /t REG_DWORD /d 0 /f
:: reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEverEnabled" /t REG_DWORD /d 0 /f
:: reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d 0 /f
:: reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d 0 /f
:: reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContentEnabled" /t REG_DWORD /d 0 /f
:: reg add "HKLM\Software\Policies\Microsoft\PushToInstall" /v "DisablePushToInstall" /t REG_DWORD /d 1 /f
:: reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Subscriptions" /f
:: reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" /f
::
:: Remove Smartscreen (to restore run "sfc /scannow")
:: takeown /s %computername% /u %username% /f "%WinDir%\System32\smartscreen.exe"
:: icacls "%WinDir%\System32\smartscreen.exe" /grant:r %username%:F
:: taskkill /im smartscreen.exe /f
:: del "%WinDir%\System32\smartscreen.exe" /s /f /q
:: SmartScreen Master Toggles
:: reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d 0 /f
:: reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SmartScreen" /v "ConfigureAppInstallControl" /t REG_SZ /d Anywhere /f
:: reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SmartScreen" /v "ConfigureAppInstallControlEnabled" /t REG_DWORD /d 0 /f
::
:: Enforce NTLMv2 and refuse NTLM and LM authentication
:: Can impact access to consumer-grade file shares / NAS but it's a recommended setting
:: http://systemmanager.ru/win2k_regestry.en/76052.htm
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "LmCompatibilityLevel" /t REG_DWORD /d 5 /f
::
:: Prevent unencrypted passwords being sent to third-party SMB servers
:: Can impact access to consumer-grade file shares / NAS but it's a recommended setting
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "EnablePlainTextPassword" /t REG_DWORD /d 0 /f
::
:: Prevent guest logons to SMB servers
:: Can impact access to consumer-grade file shares / NAS but it's a recommended setting
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" /v "AllowInsecureGuestAuth" /t REG_DWORD /d 0 /f
::
:: Prevent (remote) DLL Hijacking
:: Sources:
:: https://www.greyhathacker.net/?p=235
:: https://www.verifyit.nl/wp/?p=175464
:: https://support.microsoft.com/en-us/help/2264107/a-new-cwdillegalindllsearch-registry-entry-is-available-to-control-the
:: The value data can be 0x1, 0x2 or 0xFFFFFFFF. If the value name CWDIllegalInDllSearch does not exist or the value data is 0 then the machine will still be vulnerable to attack.
:: Please be aware that the value 0xFFFFFFFF could break certain applications (also blocks dll loading from USB).
:: Blocks a DLL Load from the current working directory if the current working directory is set to a WebDAV folder (set it to 0x1)
:: Blocks a DLL Load from the current working directory if the current working directory is set to a remote folder (such as a WebDAV or UNC location) (set it to 0x2)
:: ---------------------
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v "CWDIllegalInDllSearch" /t REG_DWORD /d 0x2 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v "SafeDLLSearchMode" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v "ProtectionMode" /t REG_DWORD /d 1 /f
::
:: Disable Customer Experience Improvement (CEIP/SQM - Software Quality Management)
:: Causes issues with some Microsoft Apps/Store
:: Not needed anymore since 2004+
:: ---------------------
:: reg add "HKLM\Software\Policies\Microsoft\Internet Explorer\SQM" /v "DisableCustomerImprovementProgram" /t REG_DWORD /d 0 /f
:: reg add "HKLM\Software\Policies\Microsoft\Messenger\Client" /v "CEIP" /t REG_DWORD /d 2 /f
:: reg add "HKLM\Software\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d 0 /f
::
:: Disable (c|w)script.exe to prevent the system from running VBS scripts
:: E.g. Locky ransomware using VBscript (Visual Basic Script)
:: https://blog.avast.com/a-closer-look-at-the-locky-ransomware
:: https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows
:: ---------------------
reg add "HKCU\SOFTWARE\Microsoft\Windows Script Host\Settings" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows Script Host\Settings" /v "ActiveDebugging" /t REG_SZ /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows Script Host\Settings" /v "DisplayLogo" /t REG_SZ /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows Script Host\Settings" /v "SilentTerminate" /t REG_SZ /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows Script Host\Settings" /v "UseWINSAFER" /t REG_SZ /d 1 /f
::
:: Disable IPv6
:: https://support.microsoft.com/en-us/help/929852/guidance-for-configuring-ipv6-in-windows-for-advanced-users
:: ---------------------
netsh int ipv6 isatap set state disabled
netsh int teredo set state disabled
:: Disable Domain Name Devolution (DNS AutoCorrect)
:: 0 - Enabled (Default)
reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v "UseDomainNameDevolution" /t REG_DWORD /d 0 /f
::
:: Windows Update Settings
:: Restart options - Show a reminder when we're going to restart.
:: We use WuMgR or WSUS Offline
:: https://github.com/DavidXanatos/wumgr
:: https://gitlab.com/wsusoffline/wsusoffline/
reg add "HKLM\Software\Microsoft\WindowsUpdate\UX\Settings" /v "RestartNotificationsAllowed" /t REG_DWORD /d 1 /f
:: Change active hours (18 hours) 6am to 0am - Windows Updates will not automatically restart your device during active hours
reg add "HKLM\Software\Microsoft\WindowsUpdate\UX\Settings" /v "ActiveHoursStart" /t REG_DWORD /d 6 /f
reg add "HKLM\Software\Microsoft\WindowsUpdate\UX\Settings" /v "ActiveHoursEnd" /t REG_DWORD /d 0 /f
:: Prevent Delivery Optimization from downloading Updates from other computers across the internet
:: 1 will restrict to LAN only. 0 will disable the feature entirely
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" /v "DODownloadMode" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config\" /v "DODownloadMode" /t REG_DWORD /d 0 /f
:: Do you want Windows to download driver Software / 0 - Never / 1 - Allways / 2 - Install driver Software, if it is not found on my computer
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\DriverSearching" /v "SearchOrderConfig" /t REG_DWORD /d 2 /f
:: Specify search order for device driver source locations
:: reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\DriverSearching" /v "DontSearchWindowsUpdate" /t REG_DWORD /d 1 /f
:: reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\DriverSearching" /v "DriverUpdateWizardWuSearchEnabled" /t REG_DWORD /d 0 /f
:: Disable driver updates in Windows Update
:: reg add "HKLM\Software\Microsoft\PolicyManager\current\device\Update" /v "ExcludeWUDriversInQualityUpdate" /t REG_DWORD /d 1 /f
:: reg add "HKLM\Software\Microsoft\PolicyManager\default\device\Update" /v "ExcludeWUDriversInQualityUpdate" /t REG_DWORD /d 1 /f
:: reg add "HKLM\Software\Microsoft\WindowsUpdate\UX\Settings" /v "ExcludeWUDriversInQualityUpdate" /t REG_DWORD /d 1 /f
:: reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v "ExcludeWUDriversInQualityUpdate" /t REG_DWORD /d 1 /f
:: Avoid the driver signing enforcement for EV cert / SHA256 Microsoft Windows signed drivers which is further enforced via Secure Boot
:: reg add "HKLM\System\ControlSet001\Control\CI\Policy" /v "UpgradedSystem" /t REG_DWORD /d 1 /f
:: Set screen saver inactivity timeout to 15 minutes
::reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "InactivityTimeoutSecs" /t REG_DWORD /d 900 /f
:: Enable password prompt on sleep resume while plugged in and on battery
::reg add "HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" /v ACSettingIndex /t REG_DWORD /d 1 /f
::reg add "HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" /v DCSettingIndex /t REG_DWORD /d 1 /f
::
:: Windows Remote Access Settings
:: Disable Remote Assistance
sc config RemoteRegistry start= disabled
reg add "HKLM\Software\Policies\Microsoft\Windows\WinRM\Service\WinRS" /v "AllowRemoteShellAccess" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "fAllowToGetHelp" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "fAllowUnsolicited" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "fAllowUnsolicitedFullControl" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "fDenyTSConnections" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "TSAppCompat" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "TSEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "TSUserEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "fAllowToGetHelp" /t REG_DWORD /d 0 /f
:: Require encrypted RPC connections to Remote Desktop
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "fEncryptRPCTraffic" /t REG_DWORD /d 1 /f
:: Prevent sharing of local drives via Remote Desktop Session Hosts
::reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "fDisableCdm" /t REG_DWORD /d 1 /f
:: System Protection - Enable System restore and Set the size
:: reg delete "HKLM\Software\Policies\Microsoft\Windows NT\SystemRestore" /v "DisableSR" /f
:: reg delete "HKLM\Software\Policies\Microsoft\Windows NT\SystemRestore" /v "DisableConfig" /f
:: reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\SPP\Clients" /v " {09F7EDC5-294E-4180-AF6A-FB0E6A0E9513}" /t REG_MULTI_SZ /d 1 /f
:: schtasks /Change /TN "Microsoft\Windows\SystemRestore\SR" /Enable
:: vssadmin Resize ShadowStorage /For=C: /On=C: /Maxsize=5GB
:: sc config wbengine start= demand
:: sc config swprv start= demand
:: sc config vds start= demand
:: sc config VSS start= demand
:: System Protection - Disable System restore and Set the size
reg add "HKLM\Software\Policies\Microsoft\Windows NT\SystemRestore" /v "DisableSR" /t REG_DWORD /d 1 /f
:: We disable the System Restore Task because we use other external (and better) backup solutions like Restic or Macrium Reflect
schtasks /Change /TN "Microsoft\Windows\SystemRestore\SR" /Disable
vssadmin Resize ShadowStorage /For=C: /On=C: /Maxsize=320MB
::
:: Removal Media Settings
:: Disable autorun/autoplay on all drives
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "NoAutoplayfornonVolume" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer" /v "NoDriveTypeAutoRun" /t REG_DWORD /d 255 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoAutorun" /t REG_DWORD /d 1 /f
: Disable Autoplay for all media and devices
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" /v "DisableAutoplay" /t REG_DWORD /d 1 /f
::
:: Stop WinRM Service
net stop WinRM
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" /v "AllowUnencryptedTraffic" /t REG_DWORD /d 0 /f
:: Disable WinRM Client Digiest authentication
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" /v "AllowDigest" /t REG_DWORD /d 0 /f
:: Disabling RPC usage from a remote asset interacting with scheduled tasks
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule" /v "DisableRpcOverTcp" /t REG_DWORD /d 1 /f
:: Disabling RPC usage from a remote asset interacting with services
reg add "HKLM\SYSTEM\CurrentControlSet\Control" /v "DisableRemoteScmEndpoints" /t REG_DWORD /d 1 /f
::
:: Stop NetBIOS over TCP/IP
wmic /interactive:off nicconfig where TcpipNetbiosOptions=0 call SetTcpipNetbios 2
wmic /interactive:off nicconfig where TcpipNetbiosOptions=1 call SetTcpipNetbios 2
:: Disable NetBIOS over TCP/IP on all adapters
:: 1 - Enable
:: 0 - Default
wmic nicconfig where TcpipNetbiosOptions=0 call SetTcpipNetbios 2
wmic nicconfig where TcpipNetbiosOptions=1 call SetTcpipNetbios 2
:: rem Disable WinInetCacheServer (WinINet Caching/V01.log/WebCacheV01.dat)
:: https://docs.microsoft.com/en-us/windows/win32/wininet/caching?
:: https://www.codeproject.com/articles/1158641/windows-continuous-disk-write-plus-webcachev-dat-p
:: %LocalAppData%\Microsoft\Windows\WebCache
:: Take Ownership of the Registry key - https://www.youtube.com/watch?v=M1l5ifYKefg
:: reg delete "HKCR\AppID\{3eb3c877-1f16-487c-9050-104dbcd66683}" /f
:: reg delete "HKCR\CLSID\{0358b920-0ac7-461f-98f4-58e32cd89148}" /v "AppID" /f
:: reg delete "HKCR\Wow6432Node\AppID\{3eb3c877-1f16-487c-9050-104dbcd66683}" /f
:: reg delete "HKCR\Wow6432Node\CLSID\{0358b920-0ac7-461f-98f4-58e32cd89148}" /v "AppID" /f
:: reg delete "HKLM\SOFTWARE\Wow6432Node\Classes\AppID\{3eb3c877-1f16-487c-9050-104dbcd66683}" /f
:: reg delete "HKLM\SOFTWARE\Wow6432Node\Classes\CLSID\{0358b920-0ac7-461f-98f4-58e32cd89148}" /v "AppID" /f
:: schtasks /Change /TN "Microsoft\Windows\Wininet\CacheTask" /Disable
:: Disable WiFi Sense
:: Shares your WiFi network login with other people
reg add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" /v "value" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" /v "value" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Microsoft\WcmSvc\wifinetworkmanager\config" /v "AutoConnectAllowedOEM" /t REG_DWORD /d 0 /f
:: Disable IDN (internationalized domain name)
reg add "HKLM\Software\Policies\Microsoft\Windows NT\DNSClient" /v "DisableIdnEncoding" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows NT\DNSClient" /v "EnableIdnMapping" /t REG_DWORD /d 0 /f
:: Disable Multicast
reg add "HKLM\Software\Policies\Microsoft\Windows NT\DNSClient" /v "EnableMulticast" /t REG_DWORD /d 0 /f
:: Disable NTLMv1
powershell.exe Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol
reg add "HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10" /v "Start" /t REG_DWORD /d 4 /f
:: Disable Powershellv2
powershell.exe Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2
powershell.exe Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root
:: Setup DNS over HTTPS (DoH) 21H1+
:: netsh dns show encryption
:: Auto DoH enforces Cloudflare
:: 21H2+
reg add "HKLM\System\CurrentControlSet\Services\Dnscache\Parameters" /v "EnableAutoDoh" /t REG_DWORD /d 2 /f
:: Setup DNS over HTTPS (DoH) Add Custom Servers
netsh dns add encryption server=1.0.0.1 dohtemplate=https://cloudflare-dns.com/dns-query autoupgrade=yes udpfallback=no
netsh dns add encryption server=1.1.1.1 dohtemplate=https://cloudflare-dns.com/dns-query autoupgrade=yes udpfallback=no
netsh dns add encryption server=9.9.9.9 dohtemplate=https://dns.quad9.net/dns-query autoupgrade=yes udpfallback=no
netsh dns add encryption server=149.112.112.112 dohtemplate=https://dns.quad9.net/dns-query autoupgrade=yes udpfallback=no
netsh dns add encryption server=94.140.14.15 dohtemplate=https://dns-family.adguard.com/dns-query autoupgrade=yes udpfallback=no
netsh dns add encryption server=94.140.15.16 dohtemplate=https://dns-family.adguard.com/dns-query autoupgrade=yes udpfallback=no
netsh dns add encryption server=185.228.168.10 dohtemplate=https://doh.cleanbrowsing.org/doh/adult-filter autoupgrade=yes udpfallback=no
netsh dns add encryption server=185.228.169.11 dohtemplate=https://doh.cleanbrowsing.org/doh/adult-filter autoupgrade=yes udpfallback=no
::
:: Harden Powershellv1 (2 - default)
:: %WINDIR%\System32\WindowsPowerShell\v1.0\powershell.exe "Set-ExecutionPolicy bypass - noprofile"
:: powershell.exe "Set-ExecutionPolicy bypass - noprofile"
:: reg add "HKLM\Software\Microsoft\PowerShell\1\ShellIds\ScriptedDiagnostics" /v "ExecutionPolicy" /t REG_SZ /d "Restricted" /f
:: reg add "HKLM\Software\WOW6432Node\Microsoft\PowerShell\1\ShellIds\ScriptedDiagnostics" /v "ExecutionPolicy" /t REG_SZ /d "Restricted" /f
:: reg add "HKLM\Software\Policies\Microsoft\Windows\PowerShell" /v "EnableScripts" /t REG_DWORD /d 0 /f
::
::##########################################################################################################################
:: Harden lsass to help protect against credential dumping (Mimikatz)
:: Configures lsass.exe as a protected process and disables wdigest
:: Enables delegation of non-exported credentials which enables support for Restricted Admin Mode or Remote Credential Guard
:: https://technet.microsoft.com/en-us/library/dn408187(v=ws.11).aspx
:: https://medium.com/blue-team/preventing-mimikatz-attacks-ed283e7ebdd5
:: ---------------------
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" /v "AuditLevel" /t REG_DWORD /d 8 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "RunAsPPL" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "DisableRestrictedAdmin" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "DisableRestrictedAdminOutboundCreds" /t REG_DWORD /d 1 /f
:: Digest Security Provider is disabled by default, but malware can enable it to recover the plain text passwords from the system’s memory (+CachedLogonsCount/+DisableDomainCreds/+DisableAutomaticRestartSignOn)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v "UseLogonCredential" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v "Negotiate" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" /v "AllowProtectedCreds" /t REG_DWORD /d 1 /f
::
::##########################################################################################################################
:: Disable the ClickOnce trust prompt
:: this only partially mitigates the risk of malicious ClickOnce Appps - the ability to run the manifest is disabled, but hash retrieval is still possible
reg add "HKLM\SOFTWARE\MICROSOFT\.NETFramework\Security\TrustManager\PromptingLevel" /v "MyComputer" /t REG_SZ /d Disabled /f
reg add "HKLM\SOFTWARE\MICROSOFT\.NETFramework\Security\TrustManager\PromptingLevel" /v "LocalIntranet" /t REG_SZ /d Disabled /f
reg add "HKLM\SOFTWARE\MICROSOFT\.NETFramework\Security\TrustManager\PromptingLevel" /v "Internet" /t REG_SZ /d Disabled /f
reg add "HKLM\SOFTWARE\MICROSOFT\.NETFramework\Security\TrustManager\PromptingLevel" /v "TrustedSites" /t REG_SZ /d Disabled /f
reg add "HKLM\SOFTWARE\MICROSOFT\.NETFramework\Security\TrustManager\PromptingLevel" /v "UntrustedSites" /t REG_SZ /d Disabled /f
::
::##########################################################################################################################
:: Windows Logging
:: https://docs.microsoft.com/en-us/windows/win32/etw/configuring-and-starting-an-autologger-session
:: DiagLog is required by Diagnostic Policy Service (Troubleshooting)
:: EventLog-System/EventLog-Application are required by Windows Events Log Service
:: perfmon
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d 0 /f
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DiagLog" /v "Start" /t REG_DWORD /d 0 /f
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\Diagtrack-Listener" /v "Start" /t REG_DWORD /d 0 /f
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\WiFiSession" /v "Start" /t REG_DWORD /d 0 /f
::
::##########################################################################################################################
:: Windows Error Reporting
:: https://docs.microsoft.com/en-us/windows/win32/wer/wer-settings
:: Disable Microsoft Support Diagnostic Tool MSDT
reg add "HKLM\Software\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" /v "DisableQuery::oteServer" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" /v "EnableQuery::oteServer" /t REG_DWORD /d 0 /f
:: Disable System Debugger (Dr. Watson)
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\AeDebug" /v "Auto" /t REG_SZ /d 0 /f
:: 1 - Disable Windows Error Reporting (WER)
reg add "HKLM\Software\Microsoft\PCHealth\ErrorReporting" /v "DoReport" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d 1 /f
:: DefaultConsent / 1 - Always ask (default) / 2 - Parameters only / 3 - Parameters and safe data / 4 - All data
reg add "HKCU\Software\Microsoft\Windows\Windows Error Reporting\Consent" /v "DefaultConsent" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\Windows Error Reporting\Consent" /v "DefaultOverrideBehavior" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting\Consent" /v "DefaultConsent" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting\Consent" /v "DefaultOverrideBehavior" /t REG_DWORD /d 1 /f
:: 1 - Disable WER sending second-level data
reg add "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /v "DontSendAdditionalData" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /v "DontSendAdditionalData" /t REG_DWORD /d 1 /f
:: 1 - Disable WER crash dialogs, popups
reg add "HKLM\Software\Microsoft\PCHealth\ErrorReporting" /v "ShowUI" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /v "DontShowUI" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /v "DontShowUI" /t REG_DWORD /d 1 /f
:: 1 - Disable WER logging
reg add "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /v "LoggingDisabled" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /v "LoggingDisabled" /t REG_DWORD /d 1 /f
::
schtasks /Change /TN "Microsoft\Windows\ErrorDetails\EnableErrorDetailsUpdate" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable
:: Windows Error Reporting Service
sc config WerSvc start= disabled
:: ::ove Windows Errror Reporting exe (to restore run "sfc /scannow")
:: takeown /s %computername% /u %username% /f "%WinDir%\System32\WerFault.exe"
:: icacls "%WinDir%\System32\WerFault.exe" /grant:r %username%:F
:: taskkill /im WerFault.exe /f
:: del "%WinDir%\System32\WerFault.exe" /s /f /q

:: takeown /s %computername% /u %username% /f "%WinDir%\SysWOW64\WerFault.exe"
:: icacls "%WinDir%\SysWOW64\WerFault.exe" /grant:r %username%:F
:: taskkill /im WerFault.exe /f
:: del "%WinDir%\SysWOW64\WerFault.exe" /s /f /q

:: takeown /s %computername% /u %username% /f "%WinDir%\System32\WerFaultSecure.exe"
:: icacls "%WinDir%\System32\WerFaultSecure.exe" /grant:r %username%:F
:: taskkill /im WerFaultSecure.exe /f
:: del "%WinDir%\System32\WerFaultSecure.exe" /s /f /q

:: takeown /s %computername% /u %username% /f "%WinDir%\SysWOW64\WerFaultSecure.exe"
:: icacls "%WinDir%\SysWOW64\WerFaultSecure.exe" /grant:r %username%:F
:: taskkill /im WerFaultSecure.exe /f
:: del "%WinDir%\SysWOW64\WerFaultSecure.exe" /s /f /q

:: takeown /s %computername% /u %username% /f "%WinDir%\System32\wermgr.exe"
:: icacls "%WinDir%\System32\wermgr.exe" /grant:r %username%:F
:: taskkill /im wermgr.exe /f
:: del "%WinDir%\System32\wermgr.exe" /s /f /q

:: takeown /s %computername% /u %username% /f "%WinDir%\SysWOW64\wermgr.exe"
:: icacls "%WinDir%\SysWOW64\wermgr.exe" /grant:r %username%:F
:: taskkill /im wermgr.exe /f
:: del "%WinDir%\SysWOW64\wermgr.exe" /s /f /q
::
::##########################################################################################################################
:: Remove All (Default) Windows Firewall Rules
:: netsh advfirewall firewall delete rule name=all
:: reg delete "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Defaults\FirewallPolicy\FirewallRules" /f
:: reg delete "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /f
:: reg delete "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedInterfaces" /f
:: reg delete "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices" /f
:: Block all inbound network traffic and all outbound except allowed apps
:: netsh advfirewall set DomainProfile firewallpolicy blockinboundalways,blockoutbound
:: netsh advfirewall set PrivateProfile firewallpolicy blockinboundalways,blockoutbound
:: neths advfirewall set PublicProfile firewallpolicy blockinboundalways,blockoutbound
:: Enable Windows Firewall / AllProfiles / CurrentProfile / DomainProfile / PrivateProfile / PublicProfile
:: https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc771920(v=ws.10)?
:: This blocks most lolbins
:: advfirewall set allprofiles state on
netsh advfirewall firewall add rule name="Block appvlp.exe netconns" program="C:\Program Files (x86)\Microsoft Office\root\client\AppVLP.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block calc.exe netconns" program="%systemroot%\system32\calc.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block certutil.exe netconns" program="%systemroot%\system32\certutil.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block cmstp.exe netconns" program="%systemroot%\system32\cmstp.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block cscript.exe netconns" program="%systemroot%\system32\cscript.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block esentutl.exe netconns" program="%systemroot%\system32\esentutl.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block expand.exe netconns" program="%systemroot%\system32\expand.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block extrac32.exe netconns" program="%systemroot%\system32\extrac32.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block findstr.exe netconns" program="%systemroot%\system32\findstr.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block hh.exe netconns" program="%systemroot%\system32\hh.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block makecab.exe netconns" program="%systemroot%\system32\makecab.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block mshta.exe netconns" program="%systemroot%\system32\mshta.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block msiexec.exe netconns" program="%systemroot%\system32\msiexec.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block nltest.exe netconns" program="%systemroot%\system32\nltest.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block Notepad.exe netconns" program="%systemroot%\system32\notepad.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block pcalua.exe netconns" program="%systemroot%\system32\pcalua.exe" protocol=tcp dir=out enable=yes action=block profile=any
:: netsh advfirewall firewall add rule name="Block print.exe netconns" program="%systemroot%\system32\print.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block regsvr32.exe netconns" program="%systemroot%\system32\regsvr32.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block replace.exe netconns" program="%systemroot%\system32\replace.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block rundll32.exe netconns" program="%systemroot%\system32\rundll32.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block runscripthelper.exe netconns" program="%systemroot%\system32\runscripthelper.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block scriptrunner.exe netconns" program="%systemroot%\system32\scriptrunner.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block SyncAppvPublishingServer.exe netconns" program="%systemroot%\system32\SyncAppvPublishingServer.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block wmic.exe netconns" program="%systemroot%\system32\wbem\wmic.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block wscript.exe netconns" program="%systemroot%\system32\wscript.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block regasm.exe netconns" program="%systemroot%\system32\regasm.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block odbcconf.exe netconns" program="%systemroot%\system32\odbcconf.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block regasm.exe netconns" program="%systemroot%\SysWOW64\regasm.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block odbcconf.exe netconns" program="%systemroot%\SysWOW64\odbcconf.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block appvlp.exe netconns" program="C:\Program Files\Microsoft Office\root\client\AppVLP.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block calc.exe netconns" program="%systemroot%\SysWOW64\calc.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block certutil.exe netconns" program="%systemroot%\SysWOW64\certutil.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block cmstp.exe netconns" program="%systemroot%\SysWOW64\cmstp.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block cscript.exe netconns" program="%systemroot%\SysWOW64\cscript.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block esentutl.exe netconns" program="%systemroot%\SysWOW64\esentutl.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block expand.exe netconns" program="%systemroot%\SysWOW64\expand.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block extrac32.exe netconns" program="%systemroot%\SysWOW64\extrac32.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block findstr.exe netconns" program="%systemroot%\SysWOW64\findstr.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block hh.exe netconns" program="%systemroot%\SysWOW64\hh.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block makecab.exe netconns" program="%systemroot%\SysWOW64\makecab.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block mshta.exe netconns" program="%systemroot%\SysWOW64\mshta.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block msiexec.exe netconns" program="%systemroot%\SysWOW64\msiexec.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block nltest.exe netconns" program="%systemroot%\SysWOW64\nltest.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block Notepad.exe netconns" program="%systemroot%\SysWOW64\notepad.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block pcalua.exe netconns" program="%systemroot%\SysWOW64\pcalua.exe" protocol=tcp dir=out enable=yes action=block profile=any
:: netsh advfirewall firewall add rule name="Block print.exe netconns" program="%systemroot%\SysWOW64\print.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block regsvr32.exe netconns" program="%systemroot%\SysWOW64\regsvr32.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block replace.exe netconns" program="%systemroot%\SysWOW64\replace.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block rpcping.exe netconns" program="%systemroot%\SysWOW64\rpcping.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block rundll32.exe netconns" program="%systemroot%\SysWOW64\rundll32.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block runscripthelper.exe netconns" program="%systemroot%\SysWOW64\runscripthelper.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block scriptrunner.exe netconns" program="%systemroot%\SysWOW64\scriptrunner.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block SyncAppvPublishingServer.exe netconns" program="%systemroot%\SysWOW64\SyncAppvPublishingServer.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block wmic.exe netconns" program="%systemroot%\SysWOW64\wbem\wmic.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block wscript.exe netconns" program="%systemroot%\SysWOW64\wscript.exe" protocol=tcp dir=out enable=yes action=block profile=any
::
:: Enable Firewall Logging
:: ---------------------
netsh advfirewall set currentprofile logging filename %systemroot%\system32\LogFiles\Firewall\pfirewall.log
netsh advfirewall set currentprofile logging maxfilesize 4096
netsh advfirewall set currentprofile logging droppedconnections enable
::
:: Block all inbound connections on Public profile
:: ---------------------
netsh advfirewall set publicprofile firewallpolicy blockinboundalways,allowoutbound
::
::Disable 8.3 names (Mitigate Microsoft IIS tilde directory enumeration) and Last Access timestamp for files and folder (Performance)
:: ---------------------
fsutil behavior set disable8dot3 1
::
:: Biometrics
:: ---------------------
:: Enable anti-spoofing for facial recognition
reg add "HKLM\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures" /v "EnhancedAntiSpoofing" /t REG_DWORD /d 1 /f
:: Disable other camera use while screen is locked
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v "NoLockScreenCamera" /t REG_DWORD /d 1 /f
::Disable LockScreen
:: reg add "HKLM\Software\Policies\Microsoft\Windows\Personalization" /v "NoLockScreen" /t REG_DWORD /d 1 /f
:: Disable Sign-in Screen Background Image
:: reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v "DisableLogonBackgroundImage" /t REG_DWORD /d 1 /f
:: Disable Windows spotlight
:: Provides features such as different background images and text on the lock screen, suggested apps
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsSpotlightFeatures" /t REG_DWORD /d 1 /f
:: Prevent Windows app voice activation while locked
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsActivateWithVoiceAboveLock" /t REG_DWORD /d 2 /f
:: Prevent Windows app voice activation entirely (be mindful of those with accesibility needs)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsActivateWithVoice" /t REG_DWORD /d 2 /f
::
:: Disable weak TLS/SSL ciphers and protocols
:: ---------------------
:: https://www.nartac.com/Products/IISCrypto
:: https://docs.microsoft.com/en-us/windows-server/identity/ad-fs/operations/manage-ssl-protocols-in-ad-fs
:: https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn786418(v=ws.11)
:: https://docs.microsoft.com/en-us/windows-server/security/tls/tls-registry-settings
:: Encryption - Ciphers: AES only - IISCrypto (recommended options)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 128/128" /v "Enabled" /t REG_DWORD /d 0xffffffff /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 256/256" /v "Enabled" /t REG_DWORD /d 0xffffffff /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 128/128" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/128" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168" /v "Enabled" /t REG_DWORD /d 0 /f
:: Encryption - Hashes: All allowed - IISCrypto (recommended options)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5" /v "Enabled" /t REG_DWORD /d 0xffffffff /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA" /v "Enabled" /t REG_DWORD /d 0xffffffff /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA256" /v "Enabled" /t REG_DWORD /d 0xffffffff /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA384" /v "Enabled" /t REG_DWORD /d 0xffffffff /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA512" /v "Enabled" /t REG_DWORD /d 0xffffffff /f
:: Encryption - Key Exchanges: All allowed
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman" /v "Enabled" /t REG_DWORD /d 0xffffffff /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman" /v "ServerMinKeyBitLength" /t REG_DWORD /d 0x00001000 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\ECDH" /v "Enabled" /t REG_DWORD /d 0xffffffff /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\PKCS" /v "Enabled" /t REG_DWORD /d 0xffffffff /f
:: Encryption - Protocols: TLS 1.0 and higher - IISCrypto (recommended options)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Client" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Client" /v "DisabledByDefault" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server" /v "DisabledByDefault" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client" /v "DisabledByDefault" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server" /v "DisabledByDefault" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" /v "DisabledByDefault" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" /v "DisabledByDefault" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" /v "DisabledByDefault" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" /v "DisabledByDefault" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" /v "Enabled" /t REG_DWORD /d 0xffffffff /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" /v "DisabledByDefault" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" /v "Enabled" /t REG_DWORD /d 0xffffffff /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" /v "DisabledByDefault" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" /v "Enabled" /t REG_DWORD /d 0xffffffff /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" /v "DisabledByDefault" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" /v "Enabled" /t REG_DWORD /d 0xffffffff /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" /v "DisabledByDefault" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" /v "Enabled" /t REG_DWORD /d 0xffffffff /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" /v "DisabledByDefault" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" /v "Enabled" /t REG_DWORD /d 0xffffffff /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" /v "DisabledByDefault" /t REG_DWORD /d 0 /f
:: Encryption - Cipher Suites (order) - All cipher included to avoid application problems
reg add "HKLM\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" /v "Functions" /t REG_SZ /d "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_CBC_SHA256,TLS_RSA_WITH_AES_128_CBC_SHA256,TLS_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_AES_256_GCM_SHA384,TLS_AES_128_GCM_SHA256,TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_3DES_EDE_CBC_SHA,TLS_RSA_WITH_NULL_SHA256,TLS_RSA_WITH_NULL_SHA,TLS_PSK_WITH_AES_256_GCM_SHA384,TLS_PSK_WITH_AES_128_GCM_SHA256,TLS_PSK_WITH_AES_256_CBC_SHA384,TLS_PSK_WITH_AES_128_CBC_SHA256,TLS_PSK_WITH_NULL_SHA384,TLS_PSK_WITH_NULL_SHA256" /f
:: Prioritize ECC Curves with longer keys - IISCrypto (recommended options)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" /v "EccCurves" /t REG_MULTI_SZ /d NistP384,NistP256 /f
::
:: OCSP stapling - Enabling this registry key has a potential performance impact
:: reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL" /v "EnableOcspStaplingForSni" /t REG_DWORD /d 1 /f
::
:: Enabling Strong Authentication for .NET Framework 3.5
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727" /v "SchUseStrongCrypto" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727" /v "SystemDefaultTlsVersions" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\.NETFramework\v2.0.50727" /v "SchUseStrongCrypto" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\.NETFramework\v2.0.50727" /v "SystemDefaultTlsVersions" /t REG_DWORD /d 1 /f
:: Enabling Strong Authentication for .NET Framework 4.0/4.5.x
reg add "HKLM\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" /v "SchUseStrongCrypto" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" /v "SystemDefaultTlsVersions" /t REG_DWORD /d 1 /f
::
::##########################################################################################################################
:: Enable and Configure MS Edge Internet Browser Settings
::##########################################################################################################################
::
:: Enable/Disable SmartScreen for MS Edge
:: We do not use Edge
reg add "HKCU\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d 0 /f
:: Enable Notifications in IE when a site attempts to install software
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer" /v "SafeForScripting" /t REG_DWORD /d 0 /f
:: Disable Edge password manager to encourage use of proper password manager
reg add "HKCU\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" /v "FormSuggest Passwords" /t REG_SZ /d no /f
:: Prevent MS Edge auto-installation
reg add "HKLM\SOFTWARE\Microsoft\EdgeUpdate" /v "DoNotUpdateToEdgeWithChromium" /t REG_DWORD /d 1 /f
rem Google Cast, Edge trying to connect to 239.255.255.250 via UDP port 1900
:: 0 - Disable
:: https://docs.microsoft.com/en-us/DeployEdge/microsoft-edge-policies
:: https://www.microsoft.com/en-us/download/details.aspx?id=55319
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "EnableMediaRouter" /t REG_DWORD /d 0 /f
:: Disable Microsoft Edge Preloading
:: Removed since 21H1
:: reg add "HKLM\Software\Policies\Microsoft\MicrosoftEdge\Main" /v "AllowPrelaunch" /t REG_DWORD /d 0 /f
::
::##########################################################################################################################
:: Enable and Configure Google Chrome based Internet Browser Settings
::##########################################################################################################################
::
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AdvancedProtectionAllowed" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AllowCrossOriginAuthPrompt" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AlwaysOpenPdfExternally" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AmbientAuthenticationInPrivateModesEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AudioCaptureAllowed" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AudioSandboxEnabled" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "BlockExternalExtensions" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "DnsOverHttpsMode" /t REG_SZ /d on /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "ScreenCaptureAllowed" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "SitePerProcess" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "SSLVersionMin" /t REG_SZ /d tls1 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "TLS13HardeningForLocalAnchorsEnabled" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "VideoCaptureAllowed" /t REG_DWORD /d 1 /f
::
::##########################################################################################################################
:: Windows 10 Privacy Settings (Master Toggles)
::##########################################################################################################################
::
:: Disable Help Experience Improvement Program (HEIP)
reg add "HKCU\Software\Microsoft\Assistance\Client\1.0\Settings" /v "ImplicitFeedback" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Assistance\Client\1.0\Settings" /v "OnlineAssist" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Assistance\Client\1.0\Settings" /v "FirstTimeHelppaneStartup" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Assistance\Client\1.0\Settings" /v "NoActiveHelp" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Assistance\Client\1.0\Settings" /v "NoExplicitFeedback" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Assistance\Client\1.0\Settings" /v "NoImplicitFeedback" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Assistance\Client\1.0\Settings" /v "NoOnlineAssist" /t REG_DWORD /d 1 /f
::
:: Let Microsoft provide more tailored experiences with relevant tips and recommendations by using your diagnostic data
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableTailoredExperiencesWithDiagnosticData" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /t REG_DWORD /d 0 /f
:: Set Windows Analytics to limited enhanced if enhanced is enabled
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "LimitEnhancedDiagnosticDataWindowsAnalytics" /t REG_DWORD /d 1 /f
:: Set Windows Telemetry to security only
:: If you intend to use Enhanced for Windows Analytics then set this to 2 instead
:: Note my understanding is W10 Home edition will do a minimum of "Basic"
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
:: reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience/Program-Telemetry" /v "Enabled" /t REG_DWORD /d 0 /f
:: reg add "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "MaxTelemetryAllowed" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "ShowedToastAtLevel" /t REG_DWORD /d 1 /f
:: Disable location data
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore" /v "Location" /t REG_SZ /d Deny /f
:: Prevent the Start Menu Search from providing internet results and using your location
:: Disable Cortana in Taskbar search
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "CortanaEnabled" /t REG_DWORD /d 0 /f
:: Cortana Button on Taskbar
:: 0 - Hide
:: 1 - Show
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowCortanaButton" /t REG_DWORD /d 0 /f
:: Hide Taskbar search
:: 1 - Show search icon
:: 2 - Show search box
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaConsent" /t REG_DWORD /d 0 /f
:: Disable publishing of Win10 user activity
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "PublishUserActivities" /t REG_DWORD /d 1 /f
:: Disable Win10 settings sync to cloud
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableSettingSync" /t REG_DWORD /d 2 /f
:: Disable the advertising ID
:: Let apps use advertising ID to make ads more interesting to you based on your app usage
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v "DisabledByGroupPolicy" /t REG_DWORD /d 1 /f
::
:: Disable Fullscreen Optimizations for Current User
:: 0 - Enabled
:: 2 - Disabled
:: Does not work this way anymore since 1909+
:: reg add "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehavior" /t REG_DWORD /d 2 /f
:: reg add "HKCU\System\GameConfigStore" /v "GameDVR_HonorUserFSEBehaviorMode" /t REG_DWORD /d 2 /f
::
:: Disable Windows GameDVR (Broadcasting and Recording)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v "AllowGameDVR" /t REG_DWORD /d 0 /f
reg add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d 0 /f
:: Show GameDVR tips when I start a game (ADs)
reg add "HKCU\Software\Microsoft\GameBar" /v "ShowStartupPanel" /t REG_DWORD /d 0 /f
:: Open Game bar using this button on a controller
reg add "HKCU\Software\Microsoft\GameBar" /v "UseNexusForGameBarEnabled" /t REG_DWORD /d 0 /f
:: Record game clips, screenshots, and broadcast using Game bar / Disable the message "Press Win + G to open Game bar"
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d 0 /f
:: Remove Game Bar Presence (to restore run "sfc /scannow")
takeown /s %computername% /u %username% /f "%WinDir%\System32\GameBarPresenceWriter.exe"
icacls "%WinDir%\System32\GameBarPresenceWriter.exe" /grant:r %username%:F
taskkill /im GameBarPresenceWriter.exe /f
del "%WinDir%\System32\GameBarPresenceWriter.exe" /s /f /q
reg add "HKCU\Software\Microsoft\GameBar" /v "UseNexusForGameBarEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AudioCaptureEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "CursorCaptureEnabled" /t REG_DWORD /d 0 /f
:: Disable support for Game Mode
reg add "HKCU\Software\Microsoft\GameBar" /v "AutoGameModeEnabled" /t REG_DWORD /d 0 /f
:: Use Game Mode
reg add "HKCU\Software\Microsoft\GameBar" /v "AllowAutoGameMode" /t REG_DWORD /d 0 /f
::
:: Disable Microsoft consumer experience which prevent notifications of suggested applications to install
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "OemPreInstalledAppsEnabled" /t REG_DWORD /d 0 /f
:: Get fun facts, tips, tricks, and more on your lock screen (ADs) / Windows Spotlight
:: Home/Pro Editions only
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenEnabled" /t REG_DWORD /d 0 /f
:: Rotating Lock Screen
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenOverlayEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "NOC_GLOBAL_SETTING_ALLOW_TOASTS_ABOVE_LOCK" /t REG_DWORD /d 0 /f
:: Disable websites accessing local language list
reg add "HKCU\Control Panel\International\User Profile" /v "HttpAcceptLanguageOptOut" /t REG_DWORD /d 1 /f
:: Prevent toast notifications from appearing on lock screen
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v "NoToastApplicationNotificationOnLockScreen" /t REG_DWORD /d 1 /f
:: Hide News And Interests (depends on search)
:: New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds -Name ShellFeedsTaskbarViewMode -PropertyType DWord -Value 2 -Force
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Feeds" /v "ShellFeedsTaskbarViewMode" /t REG_DWORD /d 2 /f
:: News and Interests Open on hover / 0 - No / 1 - Yes
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Feeds" /v "ShellFeedsTaskbarOpenOnHover" /t REG_DWORD /d 0 /f
:: Hide Task View button
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowTaskViewButton" /t REG_DWORD /d 0 /f
::
::##########################################################################################################################
:: Enable Advanced Windows Logging
::##########################################################################################################################
::
:: Enlarge Windows Event Security Log Size
wevtutil sl Security /ms:1024000
wevtutil sl Application /ms:1024000
wevtutil sl System /ms:1024000
wevtutil sl "Windows Powershell" /ms:1024000
wevtutil sl "Microsoft-Windows-PowerShell/Operational" /ms:1024000
:: Record command line data in process creation events eventid 4688
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v "ProcessCreationIncludeCmdLine_Enabled" /t REG_DWORD /d 1 /f
::
:: Enabled Advanced Settings
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "SCENoApplyLegacyAuditPolicy" /t REG_DWORD /d 1 /f
:: Enable PowerShell Logging
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v "EnableModuleLogging" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v "EnableScriptBlockLogging" /t REG_DWORD /d 1 /f
::
:: Enable Windows Event Detailed Logging
:: This is intentionally meant to be a subset of expected enterprise logging as this script may be used on consumer devices.
:: For more extensive Windows logging, I recommend https://www.malwarearchaeology.com/cheat-sheets
Auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:disable
Auditpol /set /subcategory:"Filtering Platform Policy Change" /success:disable /failure:disable
Auditpol /set /subcategory:"IPsec Driver" /success:enable /failure:enable
Auditpol /set /subcategory:"Logoff" /success:enable /failure:disable
Auditpol /set /subcategory:"Logon" /success:enable /failure:enable
Auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
Auditpol /set /subcategory:"Removable Storage" /success:enable /failure:enable
Auditpol /set /subcategory:"SAM" /success:disable /failure:disable
Auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
Auditpol /set /subcategory:"Security State Change" /success:enable /failure:enable
Auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable
Auditpol /set /subcategory:"System Integrity" /success:enable /failure:enable
::##########################################################################################################################
:: Uninstall dangerous apps with browser extentions (example)
:: ---------------------
:: wmic /interactive:off product where "name like 'Adobe Flash%' and version like'%'" call uninstall
:: wmic /interactive:off product where "name like 'Java%' and version like'%'" call uninstall
::
::##########################################################################################################################
:: Uninstall pups
:: ---------------------
:: wmic /interactive:off product where "name like 'Ask Part%' and version like'%'" call uninstall
:: wmic /interactive:off product where "name like 'searchAssistant%' and version like'%'" call uninstall
:: wmic /interactive:off product where "name like 'Weatherbug%' and version like'%'" call uninstall
::
:: Uninstall common extra apps found on a lot of Win10 installs
:: Obviously do a quick review to ensure it isn't removing any apps you or your user need to use.
:: https://docs.microsoft.com/en-us/windows/application-management/apps-in-windows-10
:: PowerShell command to reinstall all pre-installed apps below
:: Get-AppxPackage -AllUsers| Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
powershell.exe -command "Get-AppxPackage *Microsoft.BingWeather* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.DesktopAppInstaller* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.GetHelp* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.Getstarted* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.Messaging* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.Microsoft3DViewer* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.MicrosoftOfficeHub* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.MicrosoftSolitaireCollection* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.MicrosoftStickyNotes* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.MixedReality.Portal* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.Office.OneNote* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.OneConnect* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.Print3D* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.SkypeApp* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.Wallet* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.WebMediaExtensions* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.WebpImageExtension* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.WindowsAlarms* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.WindowsCamera* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *microsoft.windowscommunicationsapps* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.WindowsFeedbackHub* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.WindowsMaps* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.WindowsSoundRecorder* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.Xbox.TCUI* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.XboxApp* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.XboxGameOverlay* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.XboxGamingOverlay* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.XboxIdentityProvider* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.XboxSpeechToTextOverlay* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.YourPhone* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.ZuneMusic* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.ZuneVideo* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.WindowsFeedback* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Windows.ContactSupport* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *PandoraMedia* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *AdobeSystemIncorporated. AdobePhotoshop* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Duolingo* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.BingNews* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.Office.Sway* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.Advertising.Xaml* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.Services.Store.Engagement* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *ActiproSoftware* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *EclipseManager* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *SpotifyAB.SpotifyMusic* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *king.com.* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.NET.Native.Framework.1.* -AllUsers | Remove-AppxPackage"
:: Removed Provisioned Apps
:: This will prevent these apps from being reinstalled on new user first logon
:: Obviously I manually chose this list. If you truly want to nuke all the provisioned apps, you can use the below commented command in PowerShell
:: Get-AppXProvisionedPackage -Online | Remove-AppxProvisionedPackage -Online
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.BingWeather'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.GetHelp'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.Getstarted'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.MicrosoftOfficeHub'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.MicrosoftSolitaireCollection'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.MicrosoftStickyNotes'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.MixedReality.Portal'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.Office.OneNote'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.SkypeApp'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.WindowsAlarms'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.WindowsCamera'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'microsoft.windowscommunicationsapps'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.WindowsFeedbackHub'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.WindowsMaps'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.WindowsSoundRecorder'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.XboxApp'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.XboxTCUI'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.XboxGameOverlay'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.XboxGamingOverlay'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.XboxIdentityProvider'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.YourPhone'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.ZuneMusic'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.ZuneVideo'} | Remove-AppxProvisionedPackage -Online"
::##########################################################################################################################
:: Remove user account caused by an old Windows Bug (does not affect 1909+)
net user defaultuser0 /delete
net user defaultuser100000 /delete
:: ---------------------
:: Remove random files/folders
:: https://github.com/MoscaDotTo/Winapp2/blob/master/Winapp3/Winapp3.ini
del "%AppData%\Microsoft\Windows\Recent\*" /s /f /q
del "%LocalAppData%\Microsoft\Windows\ActionCenterCache" /s /f /q
del "%SystemDrive%\AMFTrace.log" /s /f /q
del "%WINDIR%\System32\sru\*" /s /f /q
rd "%SystemDrive%\AMD" /s /q
rd "%SystemDrive%\OneDriveTemp" /s /q
rd "%SystemDrive%\PerfLogs" /s /q
rd "%SystemDrive%\Recovery" /s /q
rd "%ProgramData%\Microsoft\Diagnosis" /s /q
rd "%ProgramData%\Microsoft\DiagnosticLogCSP" /s /q
rd "%ProgramData%\Microsoft\Network" /s /q
rd "%ProgramData%\Microsoft\Search" /s /q
rd "%ProgramData%\Microsoft\SmsRouter" /s /q
rd "%AppData%\AMD" /s /q
rd "%AppData%\ArtifexMundi\SparkPromo" /s /q
rd "%LocalAppData%\Microsoft\Internet Explorer" /s /q
rd "%LocalAppData%\Microsoft\Windows\AppCache" /s /q
rd "%LocalAppData%\Microsoft\Windows\History" /s /q
rd "%LocalAppData%\Microsoft\Windows\IECompatCache" /s /q
rd "%LocalAppData%\Microsoft\Windows\IECompatUaCache" /s /q
rd "%LocalAppData%\Microsoft\Windows\INetCache" /s /q
rd "%LocalAppData%\Microsoft\Windows\INetCookies" /s /q
rd "%LocalAppData%\Microsoft\Windows\WebCache" /s /q
rd "%LocalAppData%\Packages\Microsoft.Windows.Cortana_cw5n1h2txyewy\AppData\Indexed DB" /s /q
rd "%LocalAppData%\slobs-client-updater" /s /q
rd "%LocalAppData%\Steam\htmlcache" /s /q
rd "%LocalAppData%\Temp" /s /q
:: ---------------------
:: Remove/Rebuild Font Cache
:: Fixed in 21H1+
:: del "%WinDir%\ServiceProfiles\LocalService\AppData\Local\FontCache\*FontCache*"/s /f /q
:: del "%WinDir%\System32\FNTCACHE.DAT" /s /f /q
:: Remove Startup Folders
:: takeown /s %computername% /u %username% /f "%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup"
:: icacls "%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup" /grant:r %username%:(OI)(CI)F /t /l /q /c
:: del "%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup\*" /s /f /q
:: del "%AppData%\Microsoft\Windows\Start Menu\Programs\Startup\*" /s /f /q
::##########################################################################################################################
:: Secure Explorer defaults
:: ---------------------
::Show known file extensions and hidden files
:: ---------------------
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSuperHidden" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSuperHidden" /t REG_DWORD /d 1 /f
:: Enable Bluetooth ads (workaround)
:: reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Bluetooth" /v "AllowAdvertising" /t REG_DWORD /d 1 /f
:: reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Browser" /v "AllowAddressBarDropdown" /t REG_DWORD /d 1 /f
:: Add "Take Ownership" Option in Files and Folders Context Menu in Windows
reg add "HKCR\*\shell\runas" /ve /t REG_SZ /d "Take ownership" /f
reg add "HKCR\*\shell\runas" /v "HasLUAShield" /t REG_SZ /d "" /f
reg add "HKCR\*\shell\runas" /v "NoWorkingDirectory" /t REG_SZ /d "" /f
reg add "HKCR\*\shell\runas\command" /ve /t REG_SZ /d "cmd.exe /c takeown /f \"%%1\" && icacls \"%%1\" /grant administrators:F" /f
reg add "HKCR\*\shell\runas\command" /v "IsolatedCommand" /t REG_SZ /d "cmd.exe /c takeown /f \"%%1\" && icacls \"%%1\" /grant administrators:F" /f
reg add "HKCR\Directory\shell\runas" /ve /t REG_SZ /d "Take ownership" /f
reg add "HKCR\Directory\shell\runas" /v "HasLUAShield" /t REG_SZ /d "" /f
reg add "HKCR\Directory\shell\runas" /v "NoWorkingDirectory" /t REG_SZ /d "" /f
reg add "HKCR\Directory\shell\runas\command" /ve /t REG_SZ /d "cmd.exe /c takeown /f \"%%1\" /r /d y && icacls \"%%1\" /grant administrators:F /t" /f
reg add "HKCR\Directory\shell\runas\command" /v "IsolatedCommand" /t REG_SZ /d "cmd.exe /c takeown /f \"%%1\" /r /d y && icacls \"%%1\" /grant administrators:F /t" /f
:: Let apps on other devices open apps and message apps on this device, and vice versa / 0 - Disabled
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CDP" /v "EnableRemoteLaunchToast" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v "EnableCdp" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v "EnableMmx" /t REG_DWORD /d 0 /f
:: Save multiple items / 0 - Disable / 1 - Enable
reg add "HKCU\Software\Microsoft\Clipboard" /v "EnableClipboardHistory " /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v "AllowClipboardHistory" /t REG_DWORD /d 0 /f
:: Sync across devices / 0 - Disable / 1 - Enable
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v "AllowCrossDeviceClipboard " /t REG_DWORD /d 0 /f
:: Advanced system settings - Startup and Recovery
:: Disable automatically Restart on System Failure to show the BSOD Code
reg add "HKLM\System\CurrentControlSet\Control\CrashControl" /v "AutoReboot" /t REG_DWORD /d 0 /f
:: Advanced system settings - Startup and Recovery
:: 5 - 5 secs / Time to display list of operating systems
:: bcdedit /timeout 5
:: Advanced system settings - Performance - Advanced - Virtual memory
:: Disable pagefile
:: wmic computersystem where name="%computername%" set AutomaticManagedPagefile=False
:: wmic pagefileset where name="%SystemDrive%\\pagefile.sys" set InitialSize=0,MaximumSize=0
:: wmic pagefileset where name="%SystemDrive%\\pagefile.sys" delete
:: Advanced system settings - Performance - Advanced - Processor Scheduling
:: Obsolete since 1909+
:: 0 - Foreground and background applications equally responsive / 1 - Foreground application more responsive than background / 2 - Best foreground application response time (Default)
:: 38 - Adjust for best performance of Programs / 24 - Adjust for best performance of Background Services
:: reg add "HKLM\System\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation " /t REG_DWORD /d "38" /f
:: Allow/Deny - Videos library access for this device
:: reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary" /v "Value" /t REG_SZ /d "Deny" /f
:: Allow/Deny - Allow Apps to access your videos library
:: reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary" /v "Value" /t REG_SZ /d "Deny" /f
:: Allow/Deny - Allow access to tasks on this device
:: reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks" /v "Value" /t REG_SZ /d "Deny" /f
:: Allow/Deny - Allow Apps to access your tasks
:: reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks" /v "Value" /t REG_SZ /d "Deny" /f
:: Let apps access tasks / 0 - Default / 1 - Enabled / 2 - Disabled
:: reg add
:: Allow/Deny - Allow Apps to take screenshots of various windows or displays on this device
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\graphicsCaptureProgrammatic" /v "Value" /t REG_SZ /d "Deny" /f
:: Allow/Deny - Allow access to screenshot border settings on this device
:: reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\graphicsCaptureWithoutBorder" /v "Value" /t REG_SZ /d "Deny" /f
:: Allow/Deny - Allow access to control radios on this device
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios" /v "Value" /t REG_SZ /d "Deny" /f
:: Let apps control radios / 0 - Default / 1 - Enabled / 2 - Disabled
reg add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessRadios" /t REG_DWORD /d 2 /f
:: Speech, inking and typing
reg add "HKCU\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /v "HasAccepted" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Microsoft\Input" /v "InputServiceEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Microsoft\Input" /v "InputServiceEnabledForCCI" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\InputPersonalization" /v "AllowInputPersonalization" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\HandwritingErrorReports" /v "PreventHandwritingErrorReports" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\TabletPC" /v "PreventHandwritingDataSharing" /t REG_DWORD /d 1 /f
:: Allow/Deny - Pictures library access for this device
:: reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary" /v "Value" /t REG_SZ /d "Deny" /f
:: Allow/Deny - Allow apps to access your pictures library
:: reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary" /v "Value" /t REG_SZ /d "Deny" /f
:: Allow/Deny - Allow phone calls on this device
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCall" /v "Value" /t REG_SZ /d "Deny" /f
:: Allow/Deny - Allow apps to make phone calls
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCall" /v "Value" /t REG_SZ /d "Deny" /f
:: Allow/Deny - Communicate with unpaired devices
:: Security Critical but I need it for ADB debugging
:: reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetooth" /v "Value" /t REG_SZ /d "Deny" /f
:: reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetoothSync" /v "Value" /t REG_SZ /d "Deny" /f
:: Allow/Deny - Use trusted devices
:: reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetoothSync" /v "Value" /t REG_SZ /d "Deny" /f
:: Let apps automatically share and sync info with wireless devices that don't explicitly pair with your PC, tablet, or phone / 0 - Default / 1 - Enabled / 2 - Disabled
:: reg add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsSyncWithDevices" /t REG_DWORD /d 2 /f
:: reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessTrustedDevices" /t REG_DWORD /d 2 /f
:: Allow/Deny - Allow access to user notifications on this device
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener" /v "Value" /t REG_SZ /d "Allow" /f
:: Allow/Deny - Allow apps to access your notifications
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener" /v "Value" /t REG_SZ /d "Allow" /f
:: Let apps access my notifications / 0 - Default / 1 - Enabled / 2 - Disabled
:: reg add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessNotifications" /t REG_DWORD /d 0 /f
:: reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{52079E78-A92B-413F-B213-E8FE35712E72}" /v "Value" /t REG_SZ /d "Deny" /f
:: Allow/Deny - Allow access to screenshot border settings on this device
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\musicLibrary" /v "Value" /t REG_SZ /d "Deny" /f
:: Allow/Deny - Allow access to the microphone on this device
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone" /v "Value" /t REG_SZ /d "Deny" /f
:: Allow/Deny - Allow Apps to access your microphone
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone" /v "Value" /t REG_SZ /d "Deny" /f
:: Let apps use my microphone
:: 0 - Default
:: 1 - Enabled
:: 2 - Disabled
:: reg add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessMicrophone" /t REG_DWORD /d 2 /f
:: Let apps read or send messages (text or MMS) / 0 - Default / 1 - Enabled / 2 - Disabled
reg add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessMessaging" /t REG_DWORD /d 2 /f
:: Location for this device is set to Off
:: reg add "HKLM\Software\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocation" /t REG_DWORD /d 1 /f
:: reg add "HKLM\Software\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocationScripting" /t REG_DWORD /d 1 /f
:: reg add "HKLM\Software\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableSensors" /t REG_DWORD /d 1 /f
:: reg add "HKLM\Software\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableWindowsLocationProvider" /t REG_DWORD /d 1 /f
:: 0 - Default
:: 1 - Enabled
:: 2 - Disabled
reg add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessLocation" /t REG_DWORD /d 0 /f
:: reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "Value" /t REG_SZ /d "Deny" /f
:: Allow/Deny - File system access for this device
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess" /v "Value" /t REG_SZ /d "Deny" /f
:: Allow/Deny - Allow Apps to access your file system
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess" /v "Value" /t REG_SZ /d "Deny" /f
:: Allow/Deny - Allow access to email on this device
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email" /v "Value" /t REG_SZ /d "Deny" /f
:: Allow/Deny - Allow apps to access your email
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email" /v "Value" /t REG_SZ /d "Deny" /f
:: Let apps access and send email / 0 - Default / 1 - Enabled / 2 - Disabled
:: reg add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessEmail" /t REG_DWORD /d 2 /f
:: Allow/Deny - Downloads folders access on this device
:: reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\downloadsFolder" /v "Value" /t REG_SZ /d "Deny" /f
:: Allow/Deny - Allow Apps to access your downloads folder
:: reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\downloadsFolder" /v "Value" /t REG_SZ /d "Deny" /f
:: Allow/Deny - Document libraries access for this device
:: reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary" /v "Value" /t REG_SZ /d "Deny" /f
:: Allow/Deny - Allow Apps to access your documents library
:: reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary" /v "Value" /t REG_SZ /d "Deny" /f
:: Allow/Deny - Allow access to contacts on this device
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts" /v "Value" /t REG_SZ /d "Deny" /f
:: Allow/Deny - Allow Apps to access your contacts
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts" /v "Value" /t REG_SZ /d "Deny" /f
:: Let Windows apps access contacts / 0 - Default / 1 - Enabled / 2 - Disabled
:: reg add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessContacts" /t REG_DWORD /d 2 /f
:: Disallow Cloud Sync (Microsoft's own IM)
:: reg add "HKCU\Software\Microsoft\Messaging" /v "CloudServiceSyncEnabled" /t REG_DWORD /d 0 /f
:: Allow/Deny - Allow access to messaging on this device
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat" /v "Value" /t REG_SZ /d "Deny" /f
:: Allow/Deny - Allow Apps to read or send messages
reg add "HKCU\Software\Microsoft\
:: Allow/Deny - Allow access to cellular data on this device
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\cellularData" /v "Value" /t REG_SZ /d "Deny" /f
:: Allow/Deny - Allow apps to access your cellular data
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\cellularData" /v "Value" /t REG_SZ /d "Deny" /f
:: Allow/Deny - Allow access to camera on this device
:: I use OBS Studio
:: reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" /v "Value" /t REG_SZ /d "Deny" /f
:: Allow/Deny - Allow Apps to access your camera
:: reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" /v "Value" /t REG_SZ /d "Deny" /f
:: Let apps use my camera / 0 - Default / 1 - Enabled / 2 - Disabled
:: reg add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCamera" /t REG_DWORD /d 2 /f
:: reg add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCamera_ForceAllowTheseApps" /t REG_MULTI_SZ /d "" /f
:: reg add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCamera_ForceDenyTheseApps" /t REG_MULTI_SZ /d "" /f
:: reg add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCamera_UserInControlOfTheseApps" /t REG_MULTI_SZ /d "" /f
:: Allow/Deny - Allow access to call history on this device
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory" /v "Value" /t REG_SZ /d "Deny" /f
:: Allow/Deny - Allow apps to access your call history
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory" /v "Value" /t REG_SZ /d "Deny" /f
:: Let apps access my call history / 0 - Default / 1 - Enabled / 2 - Disabled
:: reg add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCallHistory" /t REG_DWORD /d 2 /f
:: Allow/Deny - Allow access to calendars on this device
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments" /v "Value" /t REG_SZ /d "Deny" /f
:: Allow/Deny - Allow apps to access your calendar
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments" /v "Value" /t REG_SZ /d "Deny" /f
:: Let Windows apps access contacts / 0 - Default / 1 - Enabled / 2 - Disabled
:: reg add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCalendar" /t REG_DWORD /d 2 /f
:: Let apps run in the background / 1 - Enabled / 0 - Disabled
:: reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "BackgroundAppGlobalToggle" /t REG_DWORD /d 0 /f
:: Let apps run in the background / 0 - Enabled / 1 - Disabled
:: reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t REG_DWORD /d 1 /f
:: Let apps run in the background / 0 - Default / 1 - Enabled / 2 - Disabled
:: reg add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsRunInBackground" /t REG_DWORD /d 2 /f
:: Let apps access diagnostic information / 0 - Default / 1 - Enabled / 2 - Disabled
:: reg add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsGetDiagnosticInfo" /t REG_DWORD /d 2 /f
:: Allow/Deny - Allow access to account info on this device
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" /v "Value" /t REG_SZ /d "Allow" /f
:: Allow/Deny - Allow apps to access your account info
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" /v "Value" /t REG_SZ /d "Allow" /f
:: Let apps access my name, picture, and other account info / 0 - Default / 1 - Enabled / 2 - Disabled
:: reg add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessAccountInfo" /t REG_DWORD /d 0 /f
:: Let apps access ... / 0 - Default / 1 - Enabled / 2 - Disabled
reg add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessGazeInput" /t REG_DWORD /d 2 /f
:: Let apps access ... / 0 - Default / 1 - Enabled / 2 - Disabled
reg add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessMotion" /t REG_DWORD /d 2
:: Let apps access ... / 0 - Default / 1 - Enabled / 2 - Disabled
:: reg add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessPhone" /t REG_DWORD /d 2 /f
:: When windows detects communications activity
:: 0 - Mute all other sounds
:: 1 - Reduce all other by 80%
:: 2 - Reduce all other by 50%
:: 3 - Do nothing
:: Useless because Discord and other apps can control this internally
reg add "HKCU\Software\Microsoft\Multimedia\Audio" /v "UserDuckingPreference" /t REG_DWORD /d 3 /f
:: Delete Windows Default Sounds (Permanently)
reg delete "HKCU\AppEvents\Schemes\Apps" /f
:: Hide OneDrive
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /t REG_DWORD /d 1 /f
:: Hide Meet Now Tray Icon in Taskbar
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "HideSCAMeetNow" /t REG_DWORD /d 1 /f
:: Hide Volume System Tray Icon in Taskbar
:: reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "HideSCAVolume" /t REG_DWORD /d 1 /f
:: Hide Power System Tray Icon in Taskbar
:: reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "HideSCAPower" /t REG_DWORD /d 0 /f
:: Hide Network System Tray Icon in Taskbar
:: reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "HideSCANetwork" /t REG_DWORD /d 1 /f
:: Hide Action Center System Tray Icon in Taskbar
:: reg add "HKCU\Software\Policies\Microsoft\Windows\Explorer" /v "DisableNotificationCenter" /t REG_DWORD /d 0 /f
:: Turn on Quiet Hours in Action Center / Disable/Hide the message: Turn on Windows Security Center service
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "NOC_GLOBAL_SETTING_TOASTS_ENABLED" /t REG_DWORD /d 0 /f
:: Show People on the taskbar Icon
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" /v "PeopleBand" /t REG_DWORD /d 0 /f
:: Show recently opened items in Jump Lists on Start or the taskbar
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackDocs" /t REG_DWORD /d 0 /f
:: Show suggestions occasionally in Start
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338388Enabled" /t REG_DWORD /d 0 /f
:: Block untrusted fonts and log events
:: 2000000000000 - Do not block untrusted fonts
:: 3000000000000 - Log events without blocking untrusted fonts
reg add "HKLM\Software\Policies\Microsoft\Windows NT\MitigationOptions" /v "MitigationOptions_FontBocking" /t REG_SZ /d "1000000000000" /f
:: All of the components of Windows Explorer run a single process / 1 - All instances of Windows Explorer run in one process and the Desktop and Taskbar run in a separate process
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "DesktopProcess" /t REG_DWORD /d 1 /f
:: Use Inline AutoComplete in File Explorer and Run Dialog / No
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoComplete" /v "Append Completion" /t REG_SZ /d "No" /f
:: Do this for all current items checkbox / 1 - Disabled
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" /v "ConfirmationCheckBoxDoForAll" /t REG_DWORD /d 0 /f
:: Always show more details in copy dialog
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" /v "EnthusiastMode" /t REG_DWORD /d 0 /f
:: Disable Previous Version Tab
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "NoPreviousVersionsPage" /t REG_DWORD /d 1 /f
:: Display confirmation dialog when deleting files
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "ConfirmFileDelete" /t REG_DWORD /d 1 /f
:: Auto arrange icons and Align icons to grid on Desktop 1075839525 / 1075839520 / 1075839521 / 1075839524
reg add "HKCU\Software\Microsoft\Windows\Shell\Bags\1\Desktop" /v "FFlags" /t REG_DWORD /d "1075839525" /f
:: Disable Look for an app in the Store (How do you want to open this file)
:: reg add "HKLM\Software\Policies\Microsoft\Windows\Explorer" /v "NoUseStoreOpenWith" /t REG_DWORD /d 1 /f
:: Disables the retrieval of online tips and help for the Settings app (ADs)
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "AllowOnlineTips" /t REG_DWORD /d 0 /f
:: Disable recent documents history
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoRecentDocsHistory" /t REG_DWORD /d 1 /f
:: Do not add shares from recently opened documents to the My Network Places folder
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Norecentdocsnethood" /t REG_DWORD /d 1 /f
:: Disable Cursor Suppression 0 / 1 - Enable (Default)
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableCursorSuppression" /t REG_DWORD /d 0 /f
:: Disable Program Compatibility Assistant
reg add "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /v "DisablePCA" /t REG_DWORD /d 1 /f
:: Specifies that Windows does not automatically encrypt eDrives
reg add "HKLM\Software\Policies\Microsoft\Windows\EnhancedStorageDevices" /v "TCGSecurityActivationDisabled" /t REG_DWORD /d 1 /f
:: Network Connection Status Indicator (NCSI)
:: HKLM\System\CurrentControlSet\Services\NlaSvc\Parameters\Internet
:: Sends Metdadata via pings to MS
:: Thats how MS knows how many Windows Installs existing
reg add "HKLM\Software\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator" /v "NoActiveProbe" /t REG_DWORD /d 1 /f
reg add "HKLM\System\CurrentControlSet\Services\NlaSvc\Parameters\Internet" /v "EnableActiveProbing" /t REG_DWORD /d 0 /f
:: The system registry is no longer backed up to the RegBack folder starting in Windows 10 version 1803
:: Use a real backup like e.g. Restic or Macrium Backup
:: reg add "HKLM\System\CurrentControlSet\Control\Session Manager\Configuration Manager" /v "EnablePeriodicBackup" /t REG_DWORD /d 1 /f
:: Automatically save my restartable apps when I sign out and restart them after I sign in
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "RestartApps" /t REG_DWORD /d 0 /f
:: Choose where you can get apps from - Anywhere / PreferStore / StoreOnly / Recommendations
:: Sideload apps (critical in terms of security but needed if you install apps from GitHub)
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "AicEnabled" /t REG_SZ /d "Anywhere" /f
:: No advertising banner in Snipping Tool
reg add "HKCU\Software\Microsoft\Windows\TabletPC\Snipping Tool" /v "IsScreenSketchBannerExpanded" /t REG_DWORD /d 0 /f
::##########################################################################################################################
:: Mouse
:: ---------------------
:: Enhance pointer precision to enforce 1/6/10 (Mouse Acceleration)
reg add "HKCU\Control Panel\Mouse" /v "MouseSpeed" /t REG_SZ /d 0 /f
reg add "HKCU\Control Panel\Mouse" /v "MouseThreshold1" /t REG_SZ /d 0 /f
reg add "HKCU\Control Panel\Mouse" /v "MouseThreshold2" /t REG_SZ /d 0 /f
reg add "HKCU\Control Panel\Desktop" /v "SmoothScroll" /t REG_DWORD /d 0 /f
reg add "HKCU\Control Panel\Mouse" /v "MouseTrails" /t REG_SZ /d 0 /f
:: Remove Windows Mouse Acceleration Curve
reg delete "HKCU\Control Panel\Mouse" /v "SmoothMouseXCurve" /f
reg delete "HKCU\Control Panel\Mouse" /v "SmoothMouseYCurve" /f
:: Mouse Hover Time in milliseconds before Pop-up Display
reg add "HKCU\Control Panel\Mouse" /v "MouseHoverTime" /t REG_SZ /d 0 /f
:: How long in milliseconds you want to have for a startup delay time for desktop apps that run at startup to load
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" /v "StartupDelayInMSec" /t REG_DWORD /d 0 /f
::
::##########################################################################################################################
:: File System
:: ---------------------
:: Encrypt the Pagefile
:: Security wise good, performance wise bad because it causes overheap
:: fsutil behavior set EncryptPagingFile 1
:: Enables 8dot3 name creation for all volumes on the system / 1 - Disables 8dot3 name creation for all volumes on the system / 2 - Sets 8dot3 name creation on a per volume basis / 3 - Disables 8dot3 name creation for all volumes except the system volume
:: Disable the Encrypting File System (EFS)
fsutil behavior set disableencryption 1
:: When listing directories, NTFS does not update the last-access timestamp, and it does not record time stamp updates in the NTFS log
:: Most "secure" would be 0
fsutil behavior set disablelastaccess 3
:: 5 secs / Delay Chkdsk startup time at OS Boot
reg add "HKLM\System\CurrentControlSet\Control\Session Manager" /v "AutoChkTimeout" /t REG_DWORD /d 5 /f
:: Establishes a standard size file-system cache of approximately 8 MB / 1 - Establishes a large system cache working set that can expand to physical memory, minus 4 MB, if needed
:: Obsolete since 21H1+
:: reg add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t REG_DWORD /d 1 /f
::##########################################################################################################################
:: Group Policies
:: ---------------------
:: Disable the warning The Publisher could not be verified
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Associations" /v "DefaultFileTypeRisk" /t REG_DWORD /d 1808 /f
:: Disable Security warning to unblock the downloaded file
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "SaveZoneInformation" /t REG_DWORD /d 1 /f
:: Disable Low Disk Space Alerts
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoLowDiskSpaceChecks" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoLowDiskSpaceChecks" /t REG_DWORD /d 1 /f
:: Do not allow storage of passwords and credentials for network authentication in the Credential Manager
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v "DisableDomainCreds" /t REG_DWORD /d 1 /f
::##########################################################################################################################
:: LOLBin Protection
:: ---------------------
:: Don't run specified exe
:: https://lolbas-project.github.io
:: https://blog.talosintelligence.com/2019/11/hunting-for-lolbins.html
:: https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-block-rules
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "DisallowRun" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v 1 /t REG_SZ /d "addinprocess.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v 2 /t REG_SZ /d "addinprocess32.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v 3 /t REG_SZ /d "addinutil.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v 4 /t REG_SZ /d "aspnet_compiler.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v 5 /t REG_SZ /d "bash.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v 6 /t REG_SZ /d "bginfo.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v 7 /t REG_SZ /d "bitsadmin.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v 8 /t REG_SZ /d "cdb.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v 9 /t REG_SZ /d "cipher.exe" /f
:: reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v 10 /t REG_SZ /d "cscript.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v 11 /t REG_SZ /d "csi.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v 12 /t REG_SZ /d "dbghost.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v 13 /t REG_SZ /d "dnx.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v 14 /t REG_SZ /d "dotnet.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v 15 /t REG_SZ /d "fsi.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v 16 /t REG_SZ /d "fsiAnyCpu.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v 17 /t REG_SZ /d "infdefaultinstall.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v 18 /t REG_SZ /d "hh.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v 19 /t REG_SZ /d "kd.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v 20 /t REG_SZ /d "kill.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v 21 /t REG_SZ /d "lxrun.exe" /f
:: reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v 22 /t REG_SZ /d "msbuild.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v 23 /t REG_SZ /d "mshta.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v 24 /t REG_SZ /d "msra.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v 25 /t REG_SZ /d "nc.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v 26 /t REG_SZ /d "nc64.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v 27 /t REG_SZ /d "ntkd.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v 28 /t REG_SZ /d "ntsd.exe" /f
:: reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v 29 /t REG_SZ /d "powershell.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v 30 /t REG_SZ /d "powershell_ise.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v 31 /t REG_SZ /d "powershellcustomhost.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v 32 /t REG_SZ /d "psexec.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v 33 /t REG_SZ /d "rcsi.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v 34 /t REG_SZ /d "regsvr32.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v 35 /t REG_SZ /d "runscripthelper.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v 36 /t REG_SZ /d "scrcons.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v 37 /t REG_SZ /d "texttransform.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v 38 /t REG_SZ /d "visualuiaverifynative.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v 39 /t REG_SZ /d "wbemtest.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v 40 /t REG_SZ /d "wecutil.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v 41 /t REG_SZ /d "werfault.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v 42 /t REG_SZ /d "wfc.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v 43 /t REG_SZ /d "windbg.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v 44 /t REG_SZ /d "winrm.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v 45 /t REG_SZ /d "winrs.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v 46 /t REG_SZ /d "wmic.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v 47 /t REG_SZ /d "wscript.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v 48 /t REG_SZ /d "wsl.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v 49 /t REG_SZ /d "wslconfig.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v 50 /t REG_SZ /d "wslhost.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v 51 /t REG_SZ /d "ftp.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v 52 /t REG_SZ /d "certutil.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v 53 /t REG_SZ /d "regsvr32.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v 54 /t REG_SZ /d "rundll32.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v 55 /t REG_SZ /d "finger.exe" /f
::##########################################################################################################################
:: Internal Debugging
:: ---------------------
:: Check for installed updates
:: DISM /Online /get-packages
:: Allow/Deny - Allow access to app diagnostic info on this device
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\activity" /v "Value" /t REG_SZ /d "Deny" /f
:: reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2297E4E2-5DBE-466D-A12B-0F8286F0D9CA}" /v "Value" /t REG_SZ /d "Deny" /f
:: Allow/Deny - Allow Apps to access diagnostic info about your other apps
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\activity" /v "Value" /t REG_SZ /d "Deny" /f
:: Collect Activity History
:: 0 - Disabled
:: 1 - Enabled
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v "EnableActivityFeed" /t REG_DWORD /d 0 /f
:: Let Windows collect my activities from this PC
:: 0 - Disabled
:: 1 - Enabled
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v "PublishUserActivities" /t REG_DWORD /d 0 /f
:: Let Windows collect my activities from this PC to the cloud
:: 0 - Disabled
:: 1 - Enabled
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v "UploadUserActivities" /t REG_DWORD /d 0 /f
:: Disable PerfTrack (tracking of responsiveness events)
:: reg add "HKLM\Software\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}" /v "ScenarioExecutionEnabled" /t REG_DWORD /d 0 /f
:: Disable Distributed Component Object Model (DCOM) support in Windows / Y - Enable
:: add "HKLM\Software\Microsoft\Ole" /v "EnableDCOM" /t REG_SZ /d "N" /f
:: Disable Microsoft Windows Just-In-Time (JIT) script debugging
:: reg add "HKCU\Software\Microsoft\Windows Script\Settings" /v "JITDebug" /t REG_DWORD /d 0 /f
:: reg add "HKU\.Default\Microsoft\Windows Script\Settings" /v "JITDebug" /t REG_DWORD /d 0 /f
:: When the system detects that the user is downloading an external program that runs as part of the Windows user interface, the system searches for a digital certificate or requests that the user approve the action
:: reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "EnforceShellExtensionSecurity" /t REG_DWORD /d 1 /f
:: Disable Application Impact Telemetry (AIT)
:: reg add "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d 0 /f
:: Disable Inventory Collector
:: reg add "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /v "DisableInventory" /t REG_DWORD /d 1 /f
:: Disable Steps Recorder (Steps Recorder keeps a record of steps taken by the user, the data includes user actions such as keyboard input and mouse input user interface data and screen shots)
:: reg add "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d 1 /f
:: reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience/Steps-Recorder" /v "Enabled" /t REG_DWORD /d 0 /f
:: Enable Shutdown Event Tracker
:: 0 is defaultsince 1809+
:: reg add "HKLM\Software\Policies\Microsoft\Windows NT\Reliability" /v "ShutdownReasonOn" /t REG_DWORD /d 0 /f
:: reg add "HKLM\Software\Policies\Microsoft\Windows NT\Reliability" /v "ShutdownReasonUI" /t REG_DWORD /d 0 /f
:: Enable BluetoothSession AutoLogger
:: reg add "HKLM\SYSTEM\ControlSet001\Control\WMI\Autologger\BluetoothSession" /v Start /t REG_DWORD /d 1 /f >nul 2>&1
:: reg add "HKLM\SYSTEM\ControlSet002\Control\WMI\Autologger\BluetoothSession" /v Start /t REG_DWORD /d 1 /f >nul 2>&1
:: reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\BluetoothSession" /v Start /t REG_DWORD /d 1 /f >nul 2>&1
::##########################################################################################################################
:: User Account Control
:: ---------------------
:: https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/dd835564(v=ws.10)
:: Reason to set UAC to Always Notify - https://docs.microsoft.com/en-us/previous-versions/technet-magazine/dd822916(v=msdn.10)?
:: https://daniels-it-blog.blogspot.com/2020/07/uac-bypass-via-dll-hijacking-and-mock.html
:: https://www.bleepingcomputer.com/news/security/bypassing-windows-10-uac-with-mock-folders-and-dll-hijacking/
:: There are really only two effectively distinct settings for the UAC slider - https://devblogs.microsoft.com/oldnewthing/20160816-00/?p=94105
:: Elevate without prompting
:: 1 - Prompt for credentials on the secure desktop
:: 2 - Prompt for consent on the secure desktop
:: 3 - Prompt for credentials
:: 4 - Prompt for consent
:: 5 (Default) - Prompt for consent for non-Windows binaries
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d 1 /f
:: Automatically deny elevation requests
:: 1 - Prompt for credentials on the secure desktop
:: 3 (Default) - Prompt for credentials
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorUser" /t REG_DWORD /d 0 /f
:: Trust Startup Tasks
:: 2 (Default)
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableFullTrustStartupTasks" /t REG_DWORD /d 0 /f
:: Detect application installations and prompt for elevation
:: 1 - Enabled (default for home)
:: 0 - Disabled (default for enterprise)
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableInstallerDetection" /t REG_DWORD /d 1 /f
:: Run all administrators in Admin Approval Mode
:: 0 - Disabled (UAC)
:: 1 - Enabled (UAC)
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" /t REG_DWORD /d 1 /f
:: Only elevate UIAccess applications that are installed in secure locations
:: 0 - Disabled
:: 1 (Default) - Enabled
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableSecureUIAPaths" /t REG_DWORD /d 1 /f
:: UWP Startup task Check
:: 0 (Default) = Disabled
:: 1 - Enabled
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableUwpStartupTasks" /t REG_DWORD /d 0 /f
:: Allow UIAccess applications to prompt for elevation without using the secure desktop
:: 0 (Default) = Disabled
:: 1 - Enabled
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableUIADesktopToggle" /t REG_DWORD /d 0 /f
:: Virtualization check
:: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/932a34b5-48e7-44c0-b6d2-a57aadef1799
:: 0 - Disabled
:: 1 - Enabled (Default)
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableVirtualization" /t REG_DWORD /d 0 /f
:: Admin Approval Mode for the built-in Administrator account
:: 0 (Default) - Disabled
:: 1 - Enabled
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "FilterAdministratorToken" /t REG_DWORD /d 1 /f
:: Allow UIAccess applications to prompt for elevation without using the secure desktop
:: 0 (Default) - Disabled
:: 1 - Enabled
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "PromptOnSecureDesktop" /t REG_DWORD /d 1 /f
:: Enforce cryptographic signatures on any interactive application that requests elevation of privilege
:: 0 (Default) - Disabled
:: 1 - Enabled
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "ValidateAdminCodeSignatures" /t REG_DWORD /d 1 /f
:: Display highly detailed status messages
:: 0 (Default) - Disabled
:: 1 - Enabled
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "VerboseStatus" /t REG_DWORD /d 1 /f
:: Enable command-line auditing
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v "ProcessCreationIncludeCmdLine_Enabled" /t REG_DWORD /d 1 /f
::##########################################################################################################################
:: Remove some useless tasks
:: It will show some errors chillax and cuddle your cat in that time.
:: ---------------------
:: Disable keyboard input/monitoring in apps like Calc, Edge, Search, Start, Store
schtasks /Change /TN "Microsoft\Windows\TextServicesFramework\MsCtfMonitor" /Disable
:: UAC Bypass via Disk Cleanup (fixed in 2004+)
:: https://enigma0x3.net/2016/07/22/bypassing-uac-on-windows-10-using-disk-cleanup
:: schtasks /Change /TN "Microsoft\Windows\TextServicesFramework\MsCtfMonitor" /Enable
:: schtasks /Run /TN "Microsoft\Windows\TextServicesFramework\MsCtfMonitor"
:: schtasks /Change /TN "Microsoft\Office\OfficeBackgroundTaskHandlerRegistration" /Disable
:: schtasks /End /TN "Microsoft\Office\OfficeBackgroundTaskHandlerRegistration"
:: Disable Background Synchronization (permanently, it can not be disabled)
:: schtasks /DELETE /TN "Microsoft\Windows\SettingSync\BackgroundUploadTask" /f
schtasks /DELETE /TN "AMDInstallLauncher" /f
schtasks /DELETE /TN "AMDLinkUpdate" /f
schtasks /DELETE /TN "AMDRyzenMasterSDKTask" /f
schtasks /DELETE /TN "ModifyLinkUpdate" /f
schtasks /DELETE /TN "SoftMakerUpdater" /f
schtasks /DELETE /TN "StartCN" /f
schtasks /DELETE /TN "StartDVR" /f

:: schtasks /Change /TN "CreateExplorerShellUnelevatedTask" /Enable

schtasks /Change /TN "Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319" /Disable
schtasks /Change /TN "Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 64" /Disable
schtasks /Change /TN "Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 64 Critical" /Disable
schtasks /Change /TN "Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 Critical" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Autochk\Proxy" /Disable
:: schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable
:: schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable
:: schtasks /Change /TN "Microsoft\Windows\Defrag\ScheduledDefrag" /Disable
schtasks /Change /TN "Microsoft\Windows\Device Information\Device" /Disable
schtasks /Change /TN "Microsoft\Windows\Device Information\Device User" /Disable
schtasks /Change /TN "Microsoft\Windows\Diagnosis\RecommendedTroubleshootingScanner" /Disable
schtasks /Change /TN "Microsoft\Windows\Diagnosis\Scheduled" /Disable
:: schtasks /Change /TN "Microsoft\Windows\DiskCleanup\SilentCleanup" /Disable
:: schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable
:: schtasks /Change /TN "Microsoft\Windows\DiskFootprint\Diagnostics" /Disable
:: schtasks /Change /TN "Microsoft\Windows\DiskFootprint\StorageSense" /Disable
schtasks /Change /TN "Microsoft\Windows\DUSM\dusmtask" /Disable
schtasks /Change /TN "Microsoft\Windows\Feedback\Siuf\DmClient" /Disable
schtasks /Change /TN "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" /Disable
schtasks /Change /TN "Microsoft\Windows\FileHistory\File History (maintenance mode)" /Disable
schtasks /Change /TN "Microsoft\Windows\Flighting\FeatureConfig\ReconcileFeatures" /Disable
schtasks /Change /TN "Microsoft\Windows\Flighting\FeatureConfig\UsageDataFlushing" /Disable
schtasks /Change /TN "Microsoft\Windows\Flighting\FeatureConfig\UsageDataReporting" /Disable
schtasks /Change /TN "Microsoft\Windows\Flighting\OneSettings\RefreshCache" /Disable
schtasks /Change /TN "Microsoft\Windows\HelloFace\FODCleanupTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Input\LocalUserSyncDataAvailable" /Disable
schtasks /Change /TN "Microsoft\Windows\Input\MouseSyncDataAvailable" /Disable
schtasks /Change /TN "Microsoft\Windows\Input\PenSyncDataAvailable" /Disable
schtasks /Change /TN "Microsoft\Windows\Input\TouchpadSyncDataAvailable" /Disable
schtasks /Change /TN "Microsoft\Windows\International\Synchronize Language Settings" /Disable
schtasks /Change /TN "Microsoft\Windows\LanguageComponentsInstaller\Installation" /Disable
schtasks /Change /TN "Microsoft\Windows\LanguageComponentsInstaller\ReconcileLanguageResources" /Disable
schtasks /Change /TN "Microsoft\Windows\LanguageComponentsInstaller\Uninstallation" /Disable
schtasks /Change /TN "Microsoft\Windows\License Manager\TempSignedLicenseExchange" /Disable
schtasks /Change /TN "Microsoft\Windows\License Manager\TempSignedLicenseExchange" /Disable
schtasks /Change /TN "Microsoft\Windows\Management\Provisioning\Cellular" /Disable
schtasks /Change /TN "Microsoft\Windows\Management\Provisioning\Logon" /Disable
schtasks /Change /TN "Microsoft\Windows\Maintenance\WinSAT" /Disable
schtasks /Change /TN "Microsoft\Windows\Maps\MapsToastTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Maps\MapsUpdateTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Mobile Broadband Accounts\MNO Metadata Parser" /Disable
schtasks /Change /TN "Microsoft\Windows\MUI\LPRemove" /Disable
schtasks /Change /TN "Microsoft\Windows\Multimedia\SystemSoundsService" /Disable
:: schtasks /Change /TN "Microsoft\Windows\NlaSvc\WiFiTask" /Disable
schtasks /Change /TN "Microsoft\Windows\NetTrace\GatherNetworkInfo" /Disable
schtasks /Change /TN "Microsoft\Windows\PI\Sqm-Tasks" /Disable
schtasks /Change /TN "Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /Disable
schtasks /Change /TN "Microsoft\Windows\Printing\EduPrintProv" /Disable
schtasks /Change /TN "Microsoft\Windows\PushToInstall\Registration" /Disable
schtasks /Change /TN "Microsoft\Windows\Ras\MobilityManager" /Disable
schtasks /Change /TN "Microsoft\Windows\RecoveryEnvironment\VerifyWinRE" /Disable
schtasks /Change /TN "Microsoft\Windows\RemoteAssistance\RemoteAssistanceTask" /Disable
schtasks /Change /TN "Microsoft\Windows\RetailDemo\CleanupOfflineContent" /Disable
schtasks /Change /TN "Microsoft\Windows\Servicing\StartComponentCleanup" /Disable
schtasks /Change /TN "Microsoft\Windows\SettingSync\BackupTask" /Disable
schtasks /Change /TN "Microsoft\Windows\SettingSync\NetworkStateChangeTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Setup\SetupCleanupTask" /Disable
schtasks /Change /TN "Microsoft\Windows\SpacePort\SpaceAgentTask" /Disable
schtasks /Change /TN "Microsoft\Windows\SpacePort\SpaceManagerTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Storage Tiers Management\Storage Tiers Management Initialization" /Disable
schtasks /Change /TN "Microsoft\Windows\Sysmain\ResPriStaticDbSync" /Disable
schtasks /Change /TN "Microsoft\Windows\Sysmain\WsSwapAssessmentTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Task Manager\Interactive" /Disable
schtasks /Change /TN "Microsoft\Windows\Time Synchronization\ForceSynchronizeTime" /Disable
schtasks /Change /TN "Microsoft\Windows\Time Synchronization\SynchronizeTime" /Disable
schtasks /Change /TN "Microsoft\Windows\Time Zone\SynchronizeTimeZone" /Disable
:: schtasks /Change /TN "Microsoft\Windows\TPM\Tpm-HASCertRetr" /Disable
:: schtasks /Change /TN "Microsoft\Windows\TPM\Tpm-Maintenance" /Disable
schtasks /Change /TN "Microsoft\Windows\UPnP\UPnPHostConfig" /Disable
schtasks /Change /TN "Microsoft\Windows\User Profile Service\HiveUploadTask" /Disable
:: schtasks /Change /TN "Microsoft\Windows\WCM\WiFiTask" /Disable
schtasks /Change /TN "Microsoft\Windows\WDI\ResolutionHost" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Filtering Platform\BfeOnServiceStartTypeChange" /Disable
schtasks /Change /TN "Microsoft\Windows\WindowsUpdate\Scheduled Start" /Disable
schtasks /Change /TN "Microsoft\Windows\WlanSvc\CDSSync" /Disable
schtasks /Change /TN "Microsoft\Windows\WOF\WIM-Hash-Management" /Disable
schtasks /Change /TN "Microsoft\Windows\WOF\WIM-Hash-Validation" /Disable
schtasks /Change /TN "Microsoft\Windows\Work Folders\Work Folders Logon Synchronization" /Disable
schtasks /Change /TN "Microsoft\Windows\Work Folders\Work Folders Maintenance Work" /Disable
schtasks /Change /TN "Microsoft\Windows\Workplace Join\Automatic-Device-Join" /Disable
:: schtasks /Change /TN "Microsoft\Windows\WwanSvc\NotificationTask" /Disable
:: schtasks /Change /TN "Microsoft\Windows\WwanSvc\OobeDiscovery" /Disable
::##########################################################################################################################
:: Services.msc
:: https://docs.microsoft.com/en-us/windows/application-management/per-user-services-in-windows
:: https://docs.microsoft.com/en-us/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server
:: ---------------------
:: Network Policy Server Management Service
sc config "NPSMSvc" start= disabled
:: AMD Crash Defender Service
sc config "AMD Crash Defender Service" start= disabled
:: AMD External Events Utility
sc config "AMD External Events Utility" start= disabled
:: AVCTP service (needed for e.g. bluetooth)
:: sc config BthAvctpSvc start= demand
:: reg add "HKLM\SYSTEM\CurrentControlSet\Services\BluetoothUserService" /v "Start" /t REG_DWORD /d 2 /f
:: reg add "HKLM\SYSTEM\CurrentControlSet\Services\bthserv" /v "Start" /t REG_DWORD /d 2 /f
:: XBox Game Saves and services
reg add "HKLM\System\CurrentControlSet\Services\BcastDVRUserService" /v "Start" /t REG_DWORD /d 4 /f
reg add "HKLM\System\CurrentControlSet\Services\xbgm" /v "Start" /t REG_DWORD /d 4 /f
sc config "XblAuthManager" start= disabled
sc config "XblGameSave" start= disabled
sc config "XboxGipSvc" start= disabled
sc config "XboxNetApiSvc" start= disabled
schtasks /Change /TN "Microsoft\XblGameSave\XblGameSaveTask" /Disable
:: Clipboard User Service
sc config "cbdhsvc" start= disabled
:: Connected User Experiences and Telemetry
sc config "DiagTrack" start= disabled
:: Contact Data
reg add "HKLM\System\CurrentControlSet\Services\PimIndexMaintenanceSvc" /v "Start" /t REG_DWORD /d 4 /f
:: Data Usage
sc config "DusmSvc" start= disabled
:: Display Policy Service
sc config "DispBrokerDesktopSvc" start= disabled
:: dLauncherLoopback
sc config "dLauncherLoopback" start= demand
:: Geolocation Service
sc config "lfsvc" start= disabled
:: IKE and AuthIP IPsec Keying Modules
sc config "IKEEXT" start= disabled
:: IP Helper
sc config "iphlpsvc" start= disabled
:: Payments and NFC/SE Manager
sc config "SEMgrSvc" start= disabled
:: Print Spooler
::sc config "Spooler""" start= disabled
:: Radio Management Service
:: sc config "RmSvc" start= disabled
:: Remote Access Connection Manager
sc config "RasMan" start= disabled
:: Remote Desktop Services
sc config "TermService" start= disabled
:: Retail Demo
sc config "RetailDemo" start=disabled
:: Server
sc config "LanmanServer" start= disabled
:: Shell Hardware Detection (needed for BitLocker)
:: sc config "ShellHWDetection" start= disabled
:: SSDP Discovery
sc config "SSDPSRV" start= demand
:: Superfetch
sc config "SysMain" start= demand
:: TCP/IP NetBIOS Helper
sc config "lmhosts" start= disabled
:: Touch Keyboard and Handwriting Panel Service (keeps ctfmon.exe running)
sc config "TabletInputService" start= demand
:: UserDataSvc
reg add "HKLM\System\CurrentControlSet\Services\UserDataSvc" /v "Start" /t REG_DWORD /d 4 /f
:: UnistoreSvc
reg add "HKLM\System\CurrentControlSet\Services\UnistoreSvc" /v "Start" /t REG_DWORD /d 4 /f
:: WebClient
sc config "WebClient" start= disabled
:: Windows Remote Management (WS-Management)
sc config "WinRM" start= disabled
:: Windows Search
:: We use VoidTools Everything
sc config "WSearch" start= disabled
:: Windows Time
:: Changing default povider is sufficent enough.
:: sc config "W32Time" start= disabled
:: WinHTTP Web Proxy Auto-Discovery Service
reg add "HKLM\System\CurrentControlSet\Services\WinHttpAutoProxySvc" /v "Start" /t REG_DWORD /d 4 /f
:: Workstation
sc config "LanmanWorkstation" start= disabled
::##########################################################################################################################
:: Spelling & Typing
::Disabled due to Privacy concerns + metadata concerns
:: ---------------------
:: Typing insights
reg add "HKCU\Software\Microsoft\Input\Settings" /v "InsightsEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\TextInput" /v "AllowLinguisticDataCollection" /t REG_DWORD /d 0 /f
:: Autocorrect misspelled words
reg add "HKCU\Software\Microsoft\TabletTip\1.7" /v "EnableAutocorrection" /t REG_DWORD /d 0 /f
:: Highlight misspelled words
reg add "HKCU\Software\Microsoft\TabletTip\1.7" /v "EnableSpellchecking" /t REG_DWORD /d 0 /f
:: Show text suggestions as I type on the software keyboard
reg add "HKCU\Software\Microsoft\TabletTip\1.7" /v "EnableTextPrediction" /t REG_DWORD /d 0 /f
:: Add a space after I choose a text suggestion
reg add "HKCU\Software\Microsoft\TabletTip\1.7" /v "EnablePredictionSpaceInsertion" /t REG_DWORD /d 0 /f
:: Add a period after I double-tap the Spacebar
reg add "HKCU\Software\Microsoft\TabletTip\1.7" /v "EnableDoubleTapSpace" /t REG_DWORD /d 0 /f
::##########################################################################################################################
:: Sticky Keys and other Media Keys
:: ---------------------
:: Mouse Keys
:: 254 - Disable
:: 255 - Default
reg add "HKCU\Control Panel\Accessibility\MouseKeys" /v "Flags" /t REG_SZ /d 254 /f
:: Sticky Keys
:: 26 - Disable All
:: 511 - Default
reg add "HKCU\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_SZ /d 26 /f
:: Toggle Keys
:: 58 - Disable All
:: 63 - Default
reg add "HKCU\Control Panel\Accessibility\ToggleKeys" /v "Flags" /t REG_SZ /d 58 /f
:: Disable Windows Key Hotkeys
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoWinKeys" /t REG_DWORD /d 1 /f
:: Disable specific Windows Key Hotkeys only e.g. Win+R
:: reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "DisabledHotkeys" /t REG_EXPAND_SZ /d R /f
::
::##########################################################################################################################
:: Cortana Master Toggles
:: ---------------------
:: Disable Cortana
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Cortana" /v "IsAvailable" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "AllowCortana" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "CortanaCapabilities" /t REG_SZ /d "" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "CortanaConsent" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "DeviceHistoryEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "IsAssignedAccess" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "IsWindowsHelloActive" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Windows Search" /v "CortanaConsent" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Microsoft\PolicyManager\default\Experience\AllowCortana" /v "value" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\SearchCompanion" /v "DisableContentFileUpdates" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "AllowCloudSearch" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "AllowCortanaAboveLock" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "AllowIndexingEncryptedStoresOrItems" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchPrivacy" /t REG_DWORD /d 3 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWebOverMeteredConnections" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "DoNotUseWebResults" /t REG_DWORD /d 1 /f
:: Let Cortana respond to "Hey Cortana"
reg add "HKCU\Software\Microsoft\Speech_OneCore\Preferences" /v "VoiceActivationOn" /t REG_DWORD /d 0 /f
:: Let Cortana listen for my commands when I press Windows key + C
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "VoiceShortcut" /t REG_DWORD /d 0 /f
:: Use Cortana even when my device is locked
reg add "HKCU\Software\Microsoft\Speech_OneCore\Preferences" /v "VoiceActivationEnableAboveLockscreen" /t REG_DWORD /d 0 /f
:: Remove Cortana app (News and Interests)
takeown /s %computername% /u %username% /f "%WINDIR%\SystemApps\Microsoft.Windows.Search_cw5n1h2txyewy\SearchApp.exe"
icacls "%WINDIR%\SystemApps\Microsoft.Windows.Search_cw5n1h2txyewy\SearchApp.exe" /inheritance:r /grant:r %username%:F
taskkill /im SearchApp.exe /f
del "%WINDIR%\SystemApps\Microsoft.Windows.Search_cw5n1h2txyewy\SearchApp.exe" /s /f /q
::
:: Remove Your Phone app
:: takeown /s %computername% /u %username% /f "%ProgramFiles%\Microsoft.YourPhone_1.21042.137.0_x64__8wekyb3d8bbwe\YourPhone.exe"
:: icacls "%ProgramFiles%\WindowsApps\Microsoft.YourPhone_1.21042.137.0_x64__8wekyb3d8bbwe\YourPhone.exe" /inheritance:r /grant:r %username%:F
:: taskkill /im YourPhone.exe /f
:: del "%ProgramFiles%\WindowsApps\Microsoft.YourPhone_1.21042.137.0_x64__8wekyb3d8bbwe\YourPhone.exe" /s /f /q
::##########################################################################################################################
:: Notifications
:: ---------------------
:: Get tips, tricks, and suggestions as you use Windows
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338389Enabled" /t REG_DWORD /d 0 /f
:: Get notifications from apps and other senders
reg add "HKCU\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v "NoToastApplicationNotification" /t REG_DWORD /d 0 /f
:: Show me the Windows welcome experience after updates and occasionally when I sign in to highlight what's new and suggested
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-310093Enabled" /t REG_DWORD /d 0 /f
:: Suggest ways I can finish setting up my device to get the most out of Windows
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" /v "ScoobeSystemSettingEnabled" /t REG_DWORD /d 0 /f
:: No Cloud Push Notification
:: Breaks some apps
:: reg add "HKCU\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v "NoCloudApplicationNotification" /t REG_DWORD /d 1 /f
:: reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v "NoCloudApplicationNotification" /t REG_DWORD /d 1 /f
::##########################################################################################################################
:: Storage Sense
:: ---------------------
:: fsutil storagereserve query C:
:: Dism /Online /Set-ReservedStorageState /State:Disabled /Quiet /NoRestart
:: 2/0/0 - Disable Reserved Storage (7GB)
:: 1/1/1 - Enabled
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\MiscPolicyInfo" /v "ShippedWithReserves" /t REG_DWORD /d 2 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\PassedPolicy" /v "ShippedWithReserves" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\ReserveManager" /v "ShippedWithReserves" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\StorageSense" /v "AllowStorageSenseGlobal" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\StorageSense" /v "AllowStorageSenseTemporaryFilesCleanup" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\StorageSense" /v "ConfigStorageSenseCloudContentDehydrationThreshold" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\StorageSense" /v "ConfigStorageSenseRecycleBinCleanupThreshold" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\StorageSense" /v "ConfigStorageSenseDownloadsCleanupThreshold" /t REG_DWORD /d 0 /f
reg delete "HKLM\Software\Policies\Microsoft\Windows\StorageSense" /v "ConfigStorageSenseGlobalCadence" /f
::##########################################################################################################################
:: Time & Language
:: ---------------------
:: Set Location to United Kingdom -> 242
:: Example: UK
:: reg add "HKCU\Control Panel\International\Geo" /v "Nation" /t REG_SZ /d "242" /f
:: Set Time to 24h
:: Week starts Monday
reg add "HKCU\Control Panel\International" /v "iCalendarType" /t REG_SZ /d 1 /f
reg add "HKCU\Control Panel\International" /v "iDate" /t REG_SZ /d 1 /f
reg add "HKCU\Control Panel\International" /v "iFirstDayOfWeek" /t REG_SZ /d 0 /f
reg add "HKCU\Control Panel\International" /v "iFirstWeekOfYear" /t REG_SZ /d 0 /f
reg add "HKCU\Control Panel\International" /v "iTime" /t REG_SZ /d 1 /f
reg add "HKCU\Control Panel\International" /v "iTimePrefix" /t REG_SZ /d 0 /f
reg add "HKCU\Control Panel\International" /v "sDate" /t REG_SZ /d "-" /f
reg add "HKCU\Control Panel\International" /v "sList" /t REG_SZ /d "," /f
reg add "HKCU\Control Panel\International" /v "sLongDate" /t REG_SZ /d "d MMMM, yyyy" /f
reg add "HKCU\Control Panel\International" /v "sMonDecimalSep" /t REG_SZ /d "." /f
reg add "HKCU\Control Panel\International" /v "sMonGrouping" /t REG_SZ /d "3;0" /f
reg add "HKCU\Control Panel\International" /v "sMonThousandSep" /t REG_SZ /d "," /f
reg add "HKCU\Control Panel\International" /v "sShortDate" /t REG_SZ /d "dd-MMM-yy" /f
reg add "HKCU\Control Panel\International" /v "sTime" /t REG_SZ /d ":" /f
reg add "HKCU\Control Panel\International" /v "sTimeFormat" /t REG_SZ /d "HH:mm:ss" /f
reg add "HKCU\Control Panel\International" /v "sShortTime" /t REG_SZ /d "HH:mm" /f
reg add "HKCU\Control Panel\International" /v "sYearMonth" /t REG_SZ /d "MMMM yyyy" /f
:: Set Formats to Metric
:: Auto detected by keyboard layout since 1809+
:: reg add "HKCU\Control Panel\International" /v "iDigits" /t REG_SZ /d 2 /f
:: reg add "HKCU\Control Panel\International" /v "iLZero" /t REG_SZ /d 1 /f
:: reg add "HKCU\Control Panel\International" /v "iMeasure" /t REG_SZ /d 0 /f
:: reg add "HKCU\Control Panel\International" /v "iNegNumber" /t REG_SZ /d 1 /f
:: reg add "HKCU\Control Panel\International" /v "iPaperSize" /t REG_SZ /d 1 /f
:: reg add "HKCU\Control Panel\International" /v "iTLZero" /t REG_SZ /d 1 /f
:: reg add "HKCU\Control Panel\International" /v "sDecimal" /t REG_SZ /d "," /f
:: reg add "HKCU\Control Panel\International" /v "sNativeDigits" /t REG_SZ /d "0123456789" /f
:: reg add "HKCU\Control Panel\International" /v "sNegativeSign" /t REG_SZ /d "-" /f
:: reg add "HKCU\Control Panel\International" /v "sPositiveSign" /t REG_SZ /d "" /f
:: reg add "HKCU\Control Panel\International" /v "NumShape" /t REG_SZ /d 1 /f
:: Language bar options
:: Advanced key settings
:: Change Key Sequence
:: 3 - Not assigned / 2 - CTRL+SHIFT / 1 - Left ALT+SHIFT
:: reg add "HKCU\Keyboard Layout\Toggle" /v "Language Hotkey" /t REG_SZ /d 3 /f
:: reg add "HKCU\Keyboard Layout\Toggle" /v "Hotkey" /t REG_SZ /d 3 /f
:: reg add "HKCU\Keyboard Layout\Toggle" /v "Layout Hotkey" /t REG_SZ /d 3 /f
:: Enable Num Lock on Sign-in Screen / 2147483648 - Disable
:: reg add "HKCU\Control Panel\Keyboard" /v "InitialKeyboardIndicators" /t REG_SZ /d 2 /f
:: reg add "HKU\.DEFAULT\Control Panel\Keyboard" /v "InitialKeyboardIndicators" /t REG_SZ /d 2 /f
::##########################################################################################################################
:: Windows Updates Block
:: ---------------------
:: Block svchost.exe in the firewall (TCP 80) or create a nonexistant symlink
:: rd "%WINDIR%\SoftwareDistribution\Download" /s /q
:: mklink /d "%WINDIR%\SoftwareDistribution\Download" "X:\Download"
::##########################################################################################################################
:: Context Menu Entries
:: ---------------------
:: Remove Pin to Start
reg delete "HKLM\SOFTWARE\Classes\Folder\shellex\ContextMenuHandlers\PintoStartScreen"
:: Remove open in Windows Terminal from context menu
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" /v "{9F156763-7844-4DC4-B2B1-901F640F5155}" /t REG_SZ /d "" /f
:: Remove Send To from context Menu
:: reg delete "HKCR\AllFilesystemObjects\shellex\ContextMenuHandlers\SendTo" /f
:: Remove Share from Context menu
reg delete "HKLM\Software\Classes\*\shellex\ContextMenuHandlers\ModernSharing" /f
reg delete "HKLM\Software\Classes\*\shellex\ContextMenuHandlers\Sharing" /f
reg delete "HKLM\Software\Classes\Drive\shellex\ContextMenuHandlers\Sharing" /f
reg delete "HKLM\Software\Classes\Drive\shellex\PropertySheetHandlers\Sharing" /f
reg delete "HKLM\Software\Classes\Directory\background\shellex\ContextMenuHandlers\Sharing" /f
reg delete "HKLM\Software\Classes\Directory\shellex\ContextMenuHandlers\Sharing" /f
reg delete "HKLM\Software\Classes\Directory\shellex\CopyHookHandlers\Sharing" /f
reg delete "HKLM\Software\Classes\Directory\shellex\PropertySheetHandlers\Sharing" /f
::##########################################################################################################################
:: Restore Missing Default Power Plans
:: https://www.tenforums.com/tutorials/110372-restore-missing-default-power-plans-windows-10-a.html
:: ---------------------
:: Ultimate Performance Plan
:: Only available by default in the Windows 10 Pro for Workstations edition starting with Windows 10 build 17101.
:: https://www.howtogeek.com/368781/how-to-enable-ultimate-performance-power-plan-in-windows-10/
powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61
::
:: Power Saver
powercfg -duplicatescheme a1841308-3541-4fab-bc81-f71556f20b4a
::
:: Balanced
:: powercfg -duplicatescheme 381b4222-f694-41f0-9685-ff5bb260df2e
::
:: High performance
:: powercfg -duplicatescheme 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
::
:: Disable Hibernate Mode
:: https://docs.microsoft.com/en-us/troubleshoot/windows-client/deployment/disable-and-re-enable-hibernation
powercfg -h off
::
::
