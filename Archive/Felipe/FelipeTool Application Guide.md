## FelipeTool Application Guide**

**The first launch it will capture your hardware CD KEY, just paste your clipboard to my discord in DM.**

**Every other launch should be instant. You also only need to give me CD KEY once, or when you reset your BIOS/Change motherboard.**

**OCCT**

OCCT is the most popular all-in-one stability check & stress test tool available. OCCT is great at generating heavy loads on your components ( CPU, GPU, Memory, GPU Memory & Power supply ) , and aims at detecting hardware errors or stability issues faster than anything else.

You can check temperatures and stability here after you overclock.

**HWiNFO**

Hardware Info is a powerful system information utility designed especially for detection of hardware. From a quick overview unfolding into the depth of all hardware components, ir provides all information related to hardware. Also use sensors to detect temperatures

**CPU-Z**

CPU-Z is a freeware system profiling and monitoring application for Microsoft Windows and Android that detects the central processing unit, RAM, motherboard chip-set, and other hardware features

**GPU-Z**

GPU-Z is a lightweight utility designed to provide information about video cards and GPUs. The program displays the specifications of the Graphics Processing Unit and its memory; also displays temperature, core frequency, memory frequency, GPU load and fan speeds.

**MSI Afterburner**

MSI Afterburner is the world's most recognized and widely used graphics card overclocking utility which gives you full control of your graphics cards. It also provides an incredibly detailed overview of your hardware and comes with some additional features. On the program i also added a custom skin, that allows you to Enable/Disable K-boost

**ThermSpyGPU**

ThermSpy is developed by NVIDIA, lets you control Fan and Pstate

**AIDA64**

AIDA64 is a system information, diagnostics, and auditing application. Have a small stress test that is not as much effective as OCCT, but is perfect for checking all parts of hardware

**Command Center Memory Lite**

Command Center was made by MSI, it show all timings of your memory ram

**TestMem5**

It is the fastest and best free ram stability testing tool. On the program I load this with anta config.

**Intel Memory Latency Checker**

Intel® Memory Latency Checker is a tool used to measure memory latencies and b/w, and how they change with increasing load on the system. It also provides several options for more fine-grained investigation where b/w and latencies from a specific set of cores to caches or memory can be measured as well.

**LatencyMon**

LatencyMon checks if a system running Windows is suitable for processing real-time audio and other tasks. LatencyMon analyzes the possible causes of buffer underruns by measuring kernel timer latencies and reporting DPC and ISR execution times as well as hard page faults. It will provide a comprehensible report. Just don't get obsessed at it, you are not supposed to be measuring your system quality by latencymon reports, is not a perfect tool or suitable tool.

Latencymon measures idle, it's a lot worse if u measure two properties of time combined at load, system latency is how long it takes for it to transition from two full states, not only measuring the idle.

**MouseTester**

It is made by a guy named microe in overclock.net, it's a simple mouse testing software that has built-in plotting so you can analyze your polling 

**Snappy Driver Installer Origin**

Is a not sketchy driver updater, you can trust this software

**NvCleanInstall**

Conveniently install the latest NVIDIA graphics card or a previous version that works best with your system using this straightforward app. It also strips unnecessary parts of the driver that make gains into performance!

**NVSlimmer**

The same as NvCleanInstall, it strips the driver, and also packs it

**Geek Uninstaller**

It's a not sketchy application uninstaller, and left-overs remover, you can trust this software

**NVPMManagerUni**

This will apply the registry PowerMizer of your nvidia gpu, which is supposed to control p states. You can use this to force p0 state and minimize throttling

**NvidiaInspectorProfile**

Is a utility to read and edit all NVIDIA GPU configurations

**PowerSettingsExplorer**

Is a utility to read and edit all Powerplan configurations. This dont work in Windows 7

**ThrottleStop**

ThrottleStop is a small application designed to monitor for and correct the three main types of CPU throttling that are being used on many laptop computers

**Autoruns**

This utility, which has the most comprehensive knowledge of auto-starting locations of any startup monitor, shows you what programs are configured to run during system bootup and let you edit

**Registry Workshop**

Registry Workshop is an advanced registry editor. It is a perfect replacement for RegEdit and RegEdt32 which shipped with Windows. In addition to all the standard features, Registry Workshop adds a variety of powerful features that allow you to work faster and more efficiently with registry related tasks

**ServiWin**

ServiWin utility displays the list of installed drivers and services on your system. For some of them, additional useful information is displayed: file description, version, product name, company that created the driver file, and more

**Custom Resolution Utility**

Custom Resolution Utility, free download. Custom resolution software for Windows: Overrides AMD and NVIDIA settings and creates custom resolutions.

**Create Restore Point**

It will create a restore point, for this to be working, your system drive has to be “protected” in System Properties


**Tweak Basics**

This will import many registry keys and few powershell commands that will improve your system, as it is name Basics, I only want to add stuff here that is 100% safe and confirmed to be good

**Tweak Network**

This will edit your network adapter settings, remove all power savings and tweak offloads etc

**Tweak Power Plan**

This will reset all your plans, install and select mine, based on your windows version

It disables all disk/usb/processors power saving, including disabling idle.

Disabling idle states completely causes usage readings to be always 100% in win10 and 8.1 Task Manager, programs that don't use reverse performance method still see 0% usage perfectly fine and measure it correctly, temperature spikes are totally normal since you're disabling all kinds of idling

**Tweak Services**

This will tweak your services based on your windows version, It also reverts to FULLY DEFAULTS clicking twice.

**Use Undocumented GPU**

This will add undocumented reversed engineered registry keys about GPU, trying to disable power savings and bad features and improving it. It also reverts clicking twice.

**Use Undocumented Power and Kernel**

This will add undocumented reversed engineered registry keys about Power and Kernel, trying to disable power savings and bad features and improving it. It also reverts clicking twice.

**Use ThreadPriority**

This tweak will set a priority for a specific device drivers thread. It might improve responsiveness but it's still questionable as the approach of raising priorities everywhere is not smart and should be careful, it might add bad stuff like stuttering. This is optional to users, and clicking twice reverts it.

**Use LargePages**

The main purpose for large page usage is to improve system performance for memory-access-intensive applications that use large amounts of virtual memory. It is an optional cause as seen with people having stuttering as well. You can test yourself, and revert clicking twice.

**Use DataQueueSize**

Specifies the number of events buffered by the mouse and keyboard driver. It also is used in calculating the size of the driver's internal buffer. It is recommendable to use if you don't feel freezes on your devices, but you can revert clicking twice.

**Set StaticIP**

Try to set your IP static, so you can disable unnecessary network services.

**Disable Drivers**

Disables a huge list of drivers, trying to improve systemresponsiveness, it is REALLY not recommended for laptops and wifi, as I didn't have time to make it work for both yet. You can't revert it yet.

**Disable PCW and Replace Taskmgr**

PCW is a performance counter driver that is good to disable and you can disable on windows, problem is that TaskMgr uses it, so i replace TaskMgr with a better software. You can revert clicking twice.

**Backup Current Services**

This backups your current services and saves a file on your desktop.

**Nvidia Config Disallowed FRL**

This will 1-click-Apply all nvidia settings made by me. (Using Disallowed Frame Rate Limiter)

**Nvidia Config Flip**

This will 1-click-Apply all nvidia settings made by me. (Using Flip Frame Rate Limiter)

**Windows10Debloater**

This will run the famous script:  github.com/Sycnex/Windows10Debloater

**Install OpenShell**

This will install OpenShell that is a StartMenu replacement, with my configuration

**Activate Windows**

This will run the famous script: github.com/kkkgo/KMS\_VL\_ALL

**PCIUtil**

This is a WONDERFUL tool made by our friend Bored, to control MSI/Affinity of devices. github.com/BoringBoredom/PCIutil

**MemoryCleaner**

This tool cleans memory and sets timer resolution, made by our friend Danske github.com/danskee/MemoryCleaner


**TimerResolution**

This is the most basic and effective version of setting timer resolution
