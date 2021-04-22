# Calypto&#39;s Windows Latency Guide
*Smoother, more responsive gameplay and input*

Latency is the time between a cause and an effect. An example of latency is input lag, or the time between moving your mouse and the cursor moving on the screen. A good portion of latency comes from the operating system. In this guide, I list methods to decrease input lag. This guide is mostly oriented towards gamers, but would help for any realtime application on Windows. Google is your friend if you&#39;re not sure about something in this guide (avoid forums and Reddit). These tweaks aren&#39;t listed in any particular order, but they are all important, otherwise I wouldn&#39;t bother listing them. Individually, many of these tweaks probably won&#39;t produce a perceivable difference, but if you do every single tweak you will end up with a significantly more responsive system, even if you usually can&#39;t tell.

You&#39;ll have to change the way you use a PC. In terms of programs, you will need a minimalistic approach. Don&#39;t run anything in the background that you don&#39;t absolutely need. Heavy programs such as your web browser (Spotify and Discord are reskinned Google Chrome) will slow down your system and cause stuttering. Close them before gaming and reopen them when you&#39;re done. This goes for other programs. Windows will allocate CPU time to any service or program that is running in the background and will halt all other programs until the designated program gets its CPU time. This is how multitasking works on operating systems. If you&#39;re curious about scheduling and multitasking, read [this](https://www.quora.com/If-there-is-only-one-processor-in-a-computer-and-if-multiple-processes-are-running-on-it-do-we-only-get-an-illusion-that-theyre-running-concurrently), or [this](https://www.tutorialspoint.com/operating_system/os_process_scheduling.htm).

**Measure your latency**

Before doing anything in this guide, measure your latency using [LatencyMon](https://www.resplendence.com/latencymon) then compare after doing everything. Go to &quot;Stats&quot; and record your average interrupt to DPC latency, as that is what we want to decrease. You may have to restart the test a few times to get consistently low averages. The lowest possible average is reproducible, so make a mental average. Anything under .4us is good, under .3us is ideal but difficult to achieve, and impossible to achieve on Ryzen due to its architecture and limitations of Windows. When testing latency, every background program should be closed.

![](RackMultipart20210422-4-5rf0hu_html_70e55a86e6a1c630.png)

The averages are quite low. The averages are what you are looking to improve. Intel will have lower averages than AMD. Different timers (TSC/HPET/PMT etc.) will give different results.

**Measure your polling (smoothness)**

The next thing you want to measure is your mouse polling using [MouseTester](https://www.overclock.net/forum/attachment.php?attachmentid=38838&amp;d=1455148519) originally written by [microe](https://www.overclock.net/forum/375-mice/1535687-mousetester-software.html) and updated to 1.5.3 by [dobragab](https://www.overclock.net/forum/375-mice/1590569-mousetester-software-reloaded.html#post_24873089). Stable mouse polling is extremely difficult to achieve on any multipurpose operating system as it&#39;s not considered a realtime application. For gaming, mouse polling is extremely important and stability is desired. &quot;Stable&quot; polling is very hard to achieve on a system with lots of programs and services running in the background which consequently makes games run not as smoothly, so mouse polling can be used to indirectly measure the smoothness of games. When testing polling, every background program should be closed.

![](RackMultipart20210422-4-5rf0hu_html_7c30ef8ce3d5828f.png)

![](RackMultipart20210422-4-5rf0hu_html_fdca79ed2642d321.gif)

The Tweaks:

**Disable Hyper Threading(Intel) / SMT(AMD)**

Simply put, this feature doubles the number of registers, but there is still only one execution unit (what does the actual calculation). Since you have two sets of registers, the code will have to wait in the second register until the code from the first register finishes executing, which results in roughly 5-40% higher interrupt to DPC latency. SMT gives a performance benefit for highly-threaded applications such as rendering or compiling, but hinders gaming performance as you get worse responsiveness and FPS. If you don&#39;t know, just turn it off (generally it should always be off on a gaming PC, unless you have a quad-core processor, or the game you are playing is highly threaded and you don&#39;t care about mouse response). Disabling HT/SMT will lower the CPU&#39;s energy usage so you can also use a higher frequency at the same voltage.

**Avoid Ryzen CPUs**

AMD used a special interconnect architecture in order to make CPUs with lots of cores for a low price. This is great if you want a workstation PC, not a gaming PC. Ryzens consist of two sets of cores in one die and are connected via the Infinity Fabric. The Infinity Fabric is fast, but not fast enough to not have noticeable performance loss in games as well as general high latency due to driver and OS code being executed on both &quot;sides&quot; of the CPU. Ryzens also have higher memory latency. Expect 1-3ms of extra input lag on a Zen system. Minor performance improvements were made in [Zen 2](https://en.wikichip.org/wiki/amd/microarchitectures/zen_2), but it is still a worse buy than 10th gen. Intel CPUs for latency-sensitive tasks like gaming. Starting with [Zen 3](https://en.wikichip.org/wiki/amd/microarchitectures/zen_3) (Ryzen 5000), each CCD (core complex die) has an 8-core CCX (core complex) which greatly helps reduce intercore latency, and unifies the split L3 cache previous generations had. This brings good performance improvements in games, but unfortunately the memory latency still suffers due to the memory controller being located on the IOD (I/O die). If you happened to buy a Ryzen, you can still mitigate the CCX latency, but not the memory latency by doing this:

- Disable a CCX or CCD ([Downcore Control](https://www.geeks3d.com/20170503/amd-ryzen-downcore-control/))
  - Intercore latencies: [Zen 1](https://3dnews.ru/assets/external/illustrations/2017/08/10/956770/intercore.png) / [Zen+](https://i.imgur.com/zeiugNj.png)/ [Zen 2](https://images.anandtech.com/doci/16214/CC3950X.png) / [Zen 3](https://images.anandtech.com/doci/16214/CC5950X.png)

- Windows 10 1903 has a scheduler update to group threads to CCXs but is not as low latency as disabling a CCX, another drawback is that you have to use Windows 10 1903, the more recent the Windows version the worse it is for latency due to bloat
- If you absolutely need all 8 cores, set affinity to 0-3 or 4-7 in Task Manager to minimize inter-CCX communication, alternate logical CPUs if necessary (0/2/4/6 or 8/10/12/14 odd or even doesn&#39;t matter [for SMT on])

![](RackMultipart20210422-4-5rf0hu_html_d214f89efde1f84f.png)

Disabling a CCX will reduce latency since only local cores are available

![](RackMultipart20210422-4-5rf0hu_html_8660e7b93efc37a2.png)

Setting 4+0 in BIOS on Ryzen dramatically reduces interrupt to DPC latency

![](RackMultipart20210422-4-5rf0hu_html_ed130e73222dca65.png)

Intel vs. AMD average interrupt to DPC latency

**BCDEdit and system timers**

Run Command Prompt as admin and paste these _italicized_ commands (right click and paste only the ones you need):

- To undo a command in BCDEdit, do _ **bcdedit /deletevalue X** _ (where X is useplatformclock, x2apicpolicy, etc.)

_ **bcdedit /set disabledynamictick yes** _ (Windows 8+)

- This command forces the kernel timer to constantly poll for interrupts instead of wait for them; dynamic tick was implemented as a power saving feature for laptops but hurts desktop performance

_ **bcdedit /set useplatformtick yes** _ (Windows 8+)

- Forces the clock to be backed by a platform source, no synthetic timers are allowed
- Potentially better performance, sets timer resolution to .5 instead of .501 or .499 ms

_ **bcdedit /set tscsyncpolicy** _ **[**_ **legacy | default | enhanced** _**]**(Windows 8+)

- Tells Windows which implementation of TSC to use, try all three and see which you prefer

**Disable processor idle states**

By disabling idle, you can force your processor to run at max clocks if you have a locked CPU that doesn&#39;t support overclocking (mostly Intel non-K SKUs). If you have a static all-core overclock then you can skip this step. This will minimize jitter caused by your CPU constantly changing clocks. Disabling idle makes your processor run very warm, so make sure you have adequate cooling. Don&#39;t use this if you have SMT/HT enabled as Windows sleeps the second logical processor of the physical processor for better performance. On Windows 10, CPU usage will show as 100% in Task Manager. Note that disabling idle in Windows does not fully disable CPU C-states.

1. Run CMD as admin:
2. _ **powercfg -attributes SUB\_PROCESSOR 5d76a2ca-e8c0-402f-a133-2158492d58ad -ATTRIB\_HIDE** _
3. Open power management options in Control Panel, set your plan to &quot;Maximum Performance&quot;, open the power plan, go to advanced settings, then set &quot;Processor idle disable&quot; to &quot;Disable idle&quot; under processor power options.

- Power saving has no place on a gaming machine
- I&#39;ve listed the commands below which you can paste into .bat files and run from your desktop if you don&#39;t want your CPU running at 100% all the time:

Enable idle: (less responsive, lowers temperature)

_powercfg -setacvalueindex scheme\_current sub\_processor 5d76a2ca-e8c0-402f-a133-2158492d58ad 0_

_powercfg -setactive scheme\_current_

Disable idle: (more responsive, raises temperature)

_powercfg -setacvalueindex scheme\_current sub\_processor 5d76a2ca-e8c0-402f-a133-2158492d58ad 1_

_powercfg -setactive scheme\_current_

**SetTimerResolutionService.exe** ([by mbk1969](https://forums.guru3d.com/threads/windows-timer-resolution-tool-in-form-of-system-service.376458/))

[http://www.mediafire.com/file/d8vt6ehzooah2so/SetTimerResolutionService.zip/file](http://www.mediafire.com/file/d8vt6ehzooah2so/SetTimerResolutionService.zip/file)

Download and follow the instructions in the readme. Then, open services.msc (win+r) and set &quot;Set Timer Resolution&quot; service to Automatic.

- This service increases the resolution of the Windows kernel timer, which will significantly lower latency
  - Don&#39;t use this if you disabled HPET in BIOS as it results in [higher memory latency](https://i.imgur.com/XHt2saU.png)
- Alternatively you can manually run a [program](https://cms.lucashale.com/timer-resolution/) in the background whenever you need it in case you can&#39;t install the above
- [Install Visual C++](https://github.com/abbodi1406/vcredist/releases) if you get an error

**Device Manager**

Open Device Manager (_devmgmt.msc_) and disable anything you&#39;re not using. Be careful not to disable something you use. Uninstalling a driver via Device Manager will most likely result in it reinstalling after reboot. In order to completely disable a driver, you must disable it instead of uninstalling. When you disable something in Device Manager, the driver is unloaded. Drivers interrupt the CPU, halting everything until the driver gets CPU time (some drivers are poorly programmed and can cause the system to halt for a very long time [stuttering]). What to disable:

Display adapters:

- Intel graphics (if you don&#39;t use it, ideally should be disabled in the BIOS)

Network adapters:

- All WAN miniports
- Microsoft ISATAP Adapter

System devices:

- Intel Management Engine / AMD PSP (AMD CPUs)
- Intel SMBus
- Intel SPI (flash) Controller
- Microsoft GS Wavetable Synth
- Microsoft Virtual Drive Enumerator (if not using virtual drives)
- NDIS Virtual Network Adapter Enumerator
- Remote Desktop Device Redirector Bus
- System speaker
- Terminal Server Mouse/Keyboard drivers
- UMBus Root Bus Enumerator

- In the &quot;Properties&quot; window, be sure to disable &quot;[Power Management](https://i.imgur.com/hMWA9Xv.png)&quot; for devices such as USB root hubs, network controllers, etc.

Now click on View→Devices by connection

1. Expand PCI bus, then expand all the PCI Express Root Ports
2. Locate PCI Express standard Upstream Switch Port and disable every single one with nothing connected to it (if you have it)
3. Locate Standard AHCI 1.0 Serial ATA Controller, disable any channel with nothing connected to it
4. Disable the High Definition Audio Controller that&#39;s on the same PCIe port as your video card, also the USB controller
5. Disable any USB controllers or hubs with nothing connected to them
6. Disable any PCI Express Root Port with nothing connected to it

- Here is an example of someone&#39;s device manager to give you a better idea: [https://i.imgur.com/9sdzhbl.png](https://i.imgur.com/9sdzhbl.png)

**Disable unnecessary services**

Most gaming computers will never be connected to a printer, yet the printer service is always enabled wasting CPU cycles. The same goes for other services.

The easiest way to disable services is through _services.msc_. Services can also be disabled via the registry if you run into a permissions issue using _services.msc_. In _regedit_, navigate to:

_HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Services\_

From there, you can change the start type:

0 = Boot

1 = System

2 = Automatic

3 = Manual

4 = Disabled

Another way to disable services via the registry is simply with a .reg file. Use the &quot;Properties&quot; box in _services.msc_ to get the name of the service, then create a .reg file with entries such as:

Windows Registry Editor Version 5.00

[HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Services\BluetoothUserService]

&quot;Start&quot;=dword:00000004

[HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Services\Spooler]

&quot;Start&quot;=dword:00000004

If you get an error when trying to run the .reg, use [PowerRun](https://www.sordum.org/downloads/?power-run).

Here is my config for Windows 7: [https://i.imgur.com/3BV9qnJ.png](https://i.imgur.com/3BV9qnJ.png) Windows 10 1709: [https://i.imgur.com/VsX7AtP.png](https://i.imgur.com/VsX7AtP.png)

- [BlackViper](http://www.blackviper.com/service-configurations/) (function reference for services)

**Disable your antivirus**

Antivirus causes stuttering and unnecessary CPU usage. Instead, scan files before running them and do frequent system scans. Don&#39;t visit shady websites, and don&#39;t browse the Web without an ad or script blocker ([uBlock](https://github.com/gorhill/uBlock), [uMatrix](https://github.com/gorhill/uMatrix), [ηMatrix](https://addons.palemoon.org/addon/ematrix/) [Pale Moon only]).

**Disable optional features**

By default, Windows comes with many optional features that you may never use. Disable everything that you don&#39;t need.

- Press &quot;Windows key+R&quot; → type &quot;optionalfeatures&quot; and press enter
- Windows 7 example image: [https://i.imgur.com/96DKRJD.png](https://i.imgur.com/96DKRJD.png)

**Startup**

Prevent useless bloat such as Discord/Realtek/Steam/RGB/mouse/keyboard software etc. from starting up with Windows. Your PC will start up faster, and once started will run fewer unnecessary programs.

1. Press &quot;Windows key+R&quot; → type &quot;msconfig&quot; → go to the &quot;Startup&quot; tab
2. Uncheck everything unless you absolutely need it. Launch it manually instead.

**Disable DWM** (Windows 7 or lower)

This disables desktop composition which is quite irritating if you want better responsiveness outside of games, or are playing games not in exclusive fullscreen.

1. Right click on the desktop
2. Personalize
3. Select &quot;Windows Classic&quot;
4. Disable the &quot;Desktop Window Manager&quot; and &quot;Themes&quot; services

**Windows 10 Debloat**

Run this script, clean everything else that the script doesn&#39;t (check in Task Manager and Services)

- [https://github.com/Sycnex/Windows10Debloater](https://github.com/Sycnex/Windows10Debloater)

**Disable power saving features**

There are numerous CPU-level bugs that can&#39;t quite be fixed with microcode related to power-saving features. To ensure maximum stability, disable any power-saving features in the BIOS. Keep in mind your CPU will be using more energy due to no power saving which means more heat. Disable these:

- Any P states besides P0
- C states
- AMD Cool&amp;Quiet / Intel SpeedStep (manually overclock your processor instead)

**Power Plan**

By default, Windows uses the &quot;Balanced&quot; power plan which attempts to save energy when possible. Instead, set the plan to &quot;High Performance&quot; in Control Panel→Power Options or even make a custom power plan using [PowerSettingsExplorer](https://forums.guru3d.com/threads/windows-power-plan-settings-explorer-utility.416058/). The default &quot;High Performance&quot; plan still has many energy-saving features enabled which is why it is better to create a custom plan. On W10 1803+ you may enable the &quot;Ultimate Performance&quot; power plan which is a slight step above the regular &quot;High Performance&quot; plan by pasting this command into CMD as admin:

_powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61_

You can also use my power plan for Windows 7 which was made using the tool listed above.

1. [Download this](https://drive.google.com/open?id=1Tj2VYeUp7Icp9fwf9NLrThog08GmRuDS) and put it on your desktop
2. Open CMD as admin and paste this: powercfg /import &quot;%HOMEPATH%\Desktop\CalyptoPowerPlan.pow&quot;
3. Select the power plan in the &quot;Power Options&quot; Control Panel window

- If it fails to import you&#39;ll have to manually get the directory the power plan file is placed in
- &quot;Processor idle&quot; is disabled by default, enable it manually if issues arise

**Disable Spectre and Meltdown protection / microcode mitigations** (Windows 10 or updated 7/8)

- [https://www.grc.com/inspectre.htm](https://www.grc.com/inspectre.htm)
  - [Example image](https://i.imgur.com/zR1Gz7M.png) of what it should look like when you disable mitigations
- In C:\Windows\System32, Rename &quot;mcupdate\_GenuineIntel.dll&quot; to &quot;mcupdate\_GenuineIntel.dll.old&quot; (change file permissions in Properties→Security)
  - Rename &quot;mcupdate\_AuthenticAMD.dll&quot; to &quot;mcupdate\_AuthenticAMD.dll.old&quot; if using an AMD CPU

**Process scheduling**

&quot;Quantum&quot; is the amount of time the Windows process scheduler allocates to a program. Short quantum will improve responsiveness at the expense of more context switching, or switching between tasks, which is computationally expensive. Think of context switching as downtime between work. Long quantum will improve performance of programs at the expense of lower responsiveness. Why would you want long quantum, then? Well, it minimizes context switching and will make the game run smoother, resulting in better consistency when aiming. However, short quantum could potentially decrease input lag which would improve consistency as well.

The table below lists the possible configurations that you can tell the scheduler to use. You may select Short or Long quantum, Fixed or Variable; and if you select Variable, how much boost (no boost, 2x boost, and 3x boost) to give the foreground program (probably a game). The higher the boost, the better the FPS and smoothness will be, but you may experience degraded input response with high boost. Generally, long quantum results in better smoothness but slightly degraded mouse response, whereas the opposite is true for short quantum. If you use variable quantum then the boost will significantly improve smoothness and FPS at the expense of mouse response.

Open regedit and go to:

[HKEY\_LOCAL\_MACHINE\SYSTEM\ControlSet001\Control\PriorityControl]

- Add together the decimal values you want and enter that as a decimal to the Win32PrioritySeparation key. Example: 32+4+2. (You cannot use the third column unless you use variable quantum. If you are using fixed quantum, ignore the third column.)
- Decimal 40 theoretically would provide the most responsive input at the expense of smoothness and FPS (short, fixed, no boost). Decimal 22 should provide the smoothest gameplay. Dec 37 is a mix between 40 and 38. There is no set answer here, so feel free to try out lots of options. There is no restart required so you can leave regedit open and keep trying different values while having your game open.
- Possible options: decimal 21, 22, 24, 37, 38, 40

![](RackMultipart20210422-4-5rf0hu_html_81b04d83080457ec.png)

[http://recoverymonkey.org/2007/08/17/processor-scheduling-and-quanta-in-windows-and-a-bit-about-unixlinux/](http://recoverymonkey.org/2007/08/17/processor-scheduling-and-quanta-in-windows-and-a-bit-about-unixlinux/)

**Disable the Steam browser**

Add &quot;-no-browser&quot; without quotes to your Steam shortcut to prevent steamwebhelper from opening.

- Example: [https://pbs.twimg.com/media/D6Kp2QrWwAUnLw2.png](https://pbs.twimg.com/media/D6Kp2QrWwAUnLw2.png)
- Add &quot;+open steam://open/minigameslist&quot; to open a small window with a list of your games when you launch Steam
  - You can also launch games with a desktop shortcut or by right-clicking the tray icon

**Enable MSI mode for drivers**

Some drivers default to using legacy pin-triggered interrupts, which are now emulated and are slower than using MSI (message-signaled interrupts). Enabling MSI for a driver that does not support it might break your Windows. If something goes wrong, you can recover with last known settings (f8) or by [editing the registry offline](http://smallvoid.com/article/winnt-offline-registry-edit.html). On Windows 10 systems the MSI utility should show whether a driver supports MSI or not.

- To enable MSI mode for drivers, [download MSI\_util\_v2](https://forums.guru3d.com/threads/windows-line-based-vs-message-signaled-based-interrupts.378044/), **run as admin** , then select your graphics card, audio controllers, PCIe ports. Do not enable it for USB2, SATA controller driver, or anything you&#39;re not sure of. Here is what mine looks like:
- You can check the Device Instance Path (the address listed on the bottom) in Device Manager by right-clicking a device, going to Properties, Details, Device Instance Path
- Priorities usually hurt more than helps
- Every time you update a driver you have to redo the steps for the updated driver
- Only devices with IRQs will benefit, seen under Device Manager → View → Resources by Connection

![](RackMultipart20210422-4-5rf0hu_html_dd945e9ced4fa798.png)

**Alleviate IRQ sharing**

If devices are sharing IRQs (interrupt request lines), they will interfere with each other and increase interrupt latency. To prevent IRQ sharing, enable MSI (see above section) for each driver that supports it and double check that you don&#39;t have interrupt sharing. If you still have devices sharing an IRQ, consider disabling them, moving them to a different PCIe slot, or entirely disabling them.

- Device Manager → View → Resources by connection → expand &quot;Interrupt request (IRQ)&quot;

![](RackMultipart20210422-4-5rf0hu_html_58dade8c5717c0c.png)

Example of IRQ sharing - four devices share IRQ 16 which will cause interrupts from these devices to compete with each other

**How to properly install NVIDIA drivers**

The Nvidia driver executable installs a lot of bloat. Use NVSlimmer to select what you need (enable NvContainer [Nvidia control panel]). Click apply before installing.

[https://forums.guru3d.com/threads/nvidia-driver-slimming-utility.423072/](https://forums.guru3d.com/threads/nvidia-driver-slimming-utility.423072/)

The 441.41 driver has relatively minimal DPC latency spikes compared to other Nvidia drivers. Use NVSlimmer to remove bloat. You can download the 441.41 driver here by scrolling down the list after searching: [https://www.geforce.com/drivers](https://www.geforce.com/drivers)

![](RackMultipart20210422-4-5rf0hu_html_506291ba527ea257.png)

**Nvidia 3D settings** (low latency)

![](RackMultipart20210422-4-5rf0hu_html_b579135cf8b7aeab.png)

- [Low Latency Mode](https://i.imgur.com/tmTJDAQ.png) should be set to &quot;Off&quot; or &quot;On&quot; if you experience low smoothness or stuttering
- Add this [.reg](https://drive.google.com/open?id=1HVBlTfgYy2jsVlgwoVV2_cbuvwkuZfvU) to unhide the &quot;SILK smoothness&quot; option, courtesy of [Guzz from Guru3D](https://forums.guru3d.com/threads/silk-smooth-parameter-in-nvidia-drivers.424886/#post-5630034)

**Lock GPU clocks** (Nvidia only, see the section below for Radeon cards)

**KBoost** (900 series Nvidia GPUs and older)

This tweak forces the GPU to always run at max clock speed. This prevents the GPU from constantly switching back and forth between different clocks which can impact smoothness and performance. Ensure you have adequate load temperatures (\&lt;70°C) or you will shorten the lifespan of your card. This doesn&#39;t work with Pascal or Turing cards. Use Ctrl+L in the voltage curve editor instead for 1000 and 2000 series cards.

1. [Download MSI Afterburner](http://download.msi.com/uti_exe/vga/MSIAfterburnerSetup.zip)
2. Download and add [this skin](https://drive.google.com/open?id=18-s7JEeLFfKeQJyQzYSOK-BG35wXw5PG) to C:\Program Files (x86)\MSI Afterburner\Skins (courtesy of user [BerserkForces](https://www.reddit.com/r/blackdesertonline/comments/5oh4xu/guide_making_sure_your_gpu_runs_at_its_highest/dckcjyf/))
3. Open the settings and select the &quot;User Interface&quot; tab, then select &quot;Default EVGA PrecisionX 16 Skin&quot;
4. Click OK and press &quot;KBOOST&quot; on the right side of the window, then restart your PC

**Voltage/Frequency Curve** (1000, 2000, 3000 series)

Starting with Pascal, you cannot lock P-states. The card will downclock automatically based on power and thermal limits. This is an issue because in some games the driver will not boost to its max game clock, which will increase render time. Although it is nearly impossible to prevent downclocking, you can still set a &quot;target&quot; frequency based on the voltage curve in Afterburner.

- See Cancerogeno&#39;s guide &quot;[_A slightly better way to overclock and tweak your Nvidia GPU_](https://docs.google.com/document/d/14ma-_Os3rNzio85yBemD-YSpF_1z75mZJz1UdzmW8GE/)&quot; that explains how to properly lock clocks on modern Nvidia GPUs

**Radeon Settings**

- Remove Radeon-related bloatware:
  - Disable AMDInstallLauncher / AMDLinkUpdate / ModifyLinkUpdate / StartCN (Radeon Software) / StartDVR in Task Scheduler
  - Disable AMD Crash Defender / AMD Special Tools Driver (required to flash BIOS) / High Definition Audio Controller (the one from your GPU) in Device Manager
  - Disable AMD Crash Defender / AMD External Events Utility in Services
- Radeon Software settings:
  - Anti-Lag: On
  - Radeon Chill: Off
  - Radeon Boost: Off
  - Radeon Enhanced Sync: Off
  - Wait for Vertical Refresh: Off
  - FreeSync: [Off is almost always better](https://i.imgur.com/LjwiYI8.png)
  - HDCP Support: Off
  - Change power limit to max in Performance→Tuning
  - Raise VRAM clock to something stable
  - Everything else: Off / Lowest

For The next steps, use [GPU-Z](https://www.techpowerup.com/download/techpowerup-gpu-z/) to dump your current VBIOS. Create a backup of your original VBIOS and save it somewhere in case you want to return to stock settings.

- [MorePowerTool](https://www.igorslab.de/en/red-bios-editor-and-morepowertool-adjust-and-optimize-your-vbios-and-even-more-stable-overclocking-navi-unlimited/) (helps with stuttering / downclocking / other hardware-related things - centered around 5000-series cards)
  - Use the VBIOS you dumped from GPU-Z to load the Power Play Tables to edit the settings below
  - [Features](https://i.imgur.com/qkgoBR5.png)
  - [PPTable Features](https://i.imgur.com/McTcj6v.png)
  - [Frequency](https://i.imgur.com/nQLLU23.png): Set reasonable limits for GFX Minimum / SoC Minimum. Start with something like 1900MHz GFX and 1100MHz SoC and then raise later if your thermals and stability permit. Setting these values too high (GFX 1950MHz+) may cause instability manifesting as crashing, stuttering, or microstuttering. You can try raising voltage if you experience these issues, but thermals will suffer.
  - Fan: Disable &quot;Zero RPM Enable&quot;
  - Once finished, click &quot;Write SPPT&quot; and restart the driver or reboot

  - I recommend BIOS flashing the MPT file this program creates since the driver might ignore some settings; however, BIOS flashing is not recommended if you don&#39;t have an integrated GPU or another GPU to recover a bad VBIOS
    - Use Red Bios Editor to load the saved .mpt file, then save the VBIOS and flash it using AMDVbFlash (follow the directions from Igor&#39;s Lab)
    - Use common sense when flashing - close every background program and have a backup VBIOS saved and another (i)GPU ready in case something goes wrong

- [RadeonMod](https://forums.guru3d.com/threads/radeonmod-tweak-utility.403389/)
  - FlipQueueSize=0x3000
  - Main3D\_DEF=0
  - Main3D=0x3000
  - Comb through the settings yourself and disable unnecessary features, read what everything does before changing
- If using MSI AfterBurner, disable custom fan curve to prevent screen flashing

**Interrupt affinity**

Using Microsoft&#39;s [Interrupt-Affinity Policy Tool](http://download.microsoft.com/download/9/2/0/9200a84d-6c21-4226-9922-57ef1dae939e/interrupt_affinity_policy_tool.msi)([backup link](https://drive.google.com/open?id=1_XHjXsWJOIoC5nu07bYQ-5padFQ5CQWI)), one can set affinity for a driver&#39;s interrupts. Don&#39;t go overboard. You may actually make the system perform worse if you randomly start setting affinities or set too many devices onto a single core.

- **Do not change the NVME driver or SATA driver. You will have to boot in safe mode to fix the registry entry**. On Windows 7 you can change the SATA driver, but I&#39;m not sure about NVME.
- Default install dir: C:\Program Files (x86)\Microsoft Corporation\Interrupt Affinity Policy Tool (use the x64 executable)

1. **Run as admin**
2. Select a driver and &quot;Set Mask&quot; (this is for IrqPolicySpecifiedProcessors)
  1. Select the cores you want the driver to be executed on
  2. If you have HT or SMT, select every other CPU to ensure one core doesn&#39;t get two interrupts at once, there is more nuance to this but generally you don&#39;t want to share execution units
  3. If you have a Ryzen CPU, try to keep the drivers pinned to one CCX only (CPUs 0-3 and 4-7 on an eight-core, 0-2 and 3-5 on a six core)
  4. Press the &quot;Advanced…&quot; button for other choices if you wish (not really useful on single-socket systems)
  5. Do not restart any drivers for storage devices or PCIe controllers with storage devices attached, restart your PC instead to prevent risk of data loss
3. Open Device Manager and click View→Devices by connection then expand all devices, you will need this to see which devices are under certain PCIe controllers

- These devices are fine to set, as they are most responsible for input/performance:
  - GPU
    - Set the PCIe controller that the GPU is connected to onto the same core
    - Setting the graphics card onto a single core gives the best performance, however setting it to a busy core will result in worse performance. You will have to find out which core performs best by benchmarking, such as using menu FPS or something very consistent with high FPS (300+) that you can reproduce easily
    - Keep a mental list of cores that are the most performant
  - USB controllers (also works best on a single core, test polling using MouseTester)
  - PCIe Controllers (you should set the PCIe controller onto the same cores that you set its devices as, i.e. if you set the GPU to core 0, you should set the PCIe controller as core 0 as well)

- This tool can also show hidden devices in MSI util if you change the setting at least once using this program
- Every time you update a driver such as the Nvidia driver you will have to change the affinity

![](RackMultipart20210422-4-5rf0hu_html_61957b625ebf3303.png)

- To check the device ID, open Device Manager, click View and select &quot;Devices by connection,&quot; right click on a device, Properties, Details, Physical Device Object Name

![](RackMultipart20210422-4-5rf0hu_html_60e9a6c91cbaa65e.png)

**Benchmarking affinities or driver latency**

- Use [MouseTester](https://drive.google.com/file/d/1BiePKOwZLgItGsxKYSCyEf_lJ_fO4Z6a/view?usp=sharing) for benchmarking xHCI/EHCI controller affinities

- Use [liblava-demo](https://github.com/liblava/liblava/releases/) to benchmark GPU affinities, or anything else with extremely high FPS
  - Use [CapFrameX](https://www.capframex.com/) or something similar to benchmark average FPS, 1% and .1% lows
- Use [xperf](https://docs.microsoft.com/en-us/windows-hardware/get-started/adk-install) to benchmark execution latencies for each driver. A script will make using it very easy
  - My simple [batch script](https://github.com/Calypto/xperf-dpcisr-script/blob/master/README.md) which includes a Windows 7 download link without having to install all of ADK
  - [Timecard&#39;s script](https://github.com/djdallmann/GamingPCSetup/blob/master/CONTENT/SCRIPTS/xperfdpcisr.ps1) which uses PowerShell if you prefer that instead

**Automatically setting process affinities and priorities**

If you don&#39;t use SMT/HT, you can skip this step. If you have SMT/HT enabled, Process Lasso is a useful program to set CPU affinities to every other logical processor automatically for better performance in games. You don&#39;t have to use this software; anything else that manages affinities persistently will work.

- Download and install: [https://bitsum.com/get-lasso-pro/](https://bitsum.com/get-lasso-pro/)
- Launch your game, right click on the .exe, press &quot;CPU Affinity,&quot; &quot;Always,&quot; then select every other CPU ([example here](https://i.imgur.com/40QTOgF.png)).
  - For games with an anti-cheat that prevent setting affinities, you will have to set the launcher&#39;s affinity and the game will automatically inherit the affinity. Example: set Epic Games Launcher&#39;s affinity, then Fortnite will automatically receive the affinity from the launcher

Other options for Process Lasso:

1. Press the Options menu, go to General Settings, Reconfigure the way Process Lasso starts. For the first box select &quot;Do not start at login&quot;, the second box select &quot;Start at login for ALL users,&quot; press Next, &quot;Manage ALL processes Process Lasso has access to&quot;, click finish. This will ensure only ProcessGovernor.exe (the service) runs at login, which will set the priorities of processes automatically.
2. Press the Options menu, go to General Settings, Refresh interval (governor), select 10s. This will minimize CPU usage. The &quot;Other&quot; option doesn&#39;t seem to work.
3. We want to change the priorities of all programs to lowest priority. Highlight all programs (ctrl+a), right click, Priority class always on Idle.
4. Avoid ProBalance, IdleSaver, or SmartTrim since they do more than you
5. Under Options, CPU, More, Configure foreground boost, enable both settings.
6. Feel free to explore the other options. You don&#39;t want the user interface (ProcessLasso.exe) running all the time, only ProcessGovernor.exe.

**Low Latency Hardware** (centered around gaming, not professional tasks such as low latency audio)

CPUs:

For optimal smoothness in gaming, an 8-core CPU is now the minimum. A 6-core CPU will be pushing it and won&#39;t be as future-proof. If money is tight, consider saving for a 9700K/10700K. Ryzen is excluded for latency reasons.

i7-3770K (4C/8T)

- Outdated for modern games; however, the L2 hit latency is 10ns lower than current Skylake-based CPUs (~10ns vs. ~20ns)

i7-9700K/F, i9-9900K/F (8C/16T)

- 9th generation Intel with 8-core dies. Worse memory overclocking and motherboards than 10th gen, but intercore latency will be marginally better. 10th gen. CPUs also have thinner dies which allow them to run cooler than 9th gen.

i7-10700K (8C/16T)

- lower-[binned](https://www.tomshardware.com/reviews/glossary-binning-definition,5892.html) 10900K with two cores disabled. Because 10th gen. is a 10-core die, there will be a marginal latency penalty when the hopping over the disabled cores on the ring

i9-10850K (10C/20T)

- Failed 10900K, significantly lower OC potential than a 10900K or 10700K, only buy it if you are fine with ~4.8GHz
- [https://siliconlottery.com/pages/statistics](https://siliconlottery.com/pages/statistics)

i9-10900K (10C/20T)

- The &quot;best&quot; for gaming. The two extra cores will provide additional smoothness over eight cores

Wait for 11th gen. Intel.

Motherboards:

Motherboards with 2 DIMM slots such as mini-ITX can OC RAM much better than boards with 4 DIMM slots due to better topology. 2 DIMM ATX boards will cost a lot of money compared to mini-ITX boards, but have much stronger VRMs. The ASUS ROG Maximus XI and EVGA Z390 Dark are two of the best boards in the Z390 form factor, both with 2 DIMM slots, but are very expensive. Consider Windows 7 support (PS/2 ports help in case the USB 3 drivers are not loaded).

Z390:

MSI Z390i: $165

- Best cheap board for RAM OC. More RAM frequency-oriented compared to the Phantom Gaming ITX. Does not have a PS/2 port, so keep this in mind if using Windows 7 and recovery is needed

ASRock Z390 PHANTOM GAMING-ITX: $180

- One of the best VRMs in ITX form factor. More RAM timing-oriented compared to the MSI Z390i. Overall a better board than the MSI Z390i

Asus Z390 Apex XI

- Enthusiast board for Z390, very powerful VRMs and ample BIOS options; second-best option to the EVGA Z390 Dark

EVGA Z390 Dark

- Windows XP ACPI support, more efficient VRM than Apex, iGPU support, more expensive than Apex XI
- 10 layer PCB (all else being equal, better signal compared to 6 or 8 layers)
- Forced spread spectrum clocking which results in high jitter (bad)

Z490:

MSI Z490i Unify: $250

- Requires firmware updates for CR1 support

Asus Z490 XII Apex: $420

EVGA Z490 Dark: $550

- Windows XP support
- 10 layer PCB (all else equal, better signal compared to 6 or 8 layers)
- Forced spread spectrum clocking which results in high jitter

MSI MEG Godlike: $700

- For dual-rank with four single-rank DIMMs or quad-rank with four dual-rank DIMMs

Gigabyte Aorus Xtreme: $750

- For dual-rank with four single-rank DIMMs or quad-rank with four dual-rank DIMMs

- [Z490/Z590 Motherboard Spreadsheet](https://docs.google.com/spreadsheets/d/16YJm4L1-ohpL8s-4rLDDDCBZvi97ZYwkc44s7LS5-2Q/)
  - Contains detailed information such as PCB layer count, Vcore / Vccgt / Vccsa / Vccio VRM specs, among other things
- [Z590 VRM List](https://docs.google.com/spreadsheets/d/1_ZGSXi1deJEXhHZNcm3bGvP-r8KkNKKPdTuBoFPctH4/edit#gid=0)
  - Contains basic VRM and IO information

RAM:

Avoid RGB RAM if possible due to the wasted trace space and power draw which interferes with RAM operation. Anything under 1.5-1.6V is fine for daily use, after that you may experience stability issues due to memory chips preferring lower temperatures. However, staying under 2V is fine if you have a fan over the memory and understand the stability implications. You can limit the maximum amount of memory used by the OS to 2000M if using high voltages for additional stability. The metallic covers on DIMMs (dual in-line memory modules) can be removed for better thermals since they use low quality thermal tape (or just glue) and cover the [back of the PCB with foam](https://i.imgur.com/7KvbxTv.jpg) which makes the RAM run hotter than if the &quot;heatsinks&quot; weren&#39;t there in the first place.

The &quot;best&quot; consumer RAM chip in most cases is Samsung 8Gb B-die, as it scales well with voltage allowing for lower timings. Beware of A0 PCB kits which are usually older (2017-2018). This older PCB layout is less ideal due to the chips being farther away from the DIMM&#39;s pins. The A2 layout is generally better, and is found in recently released kits. Listed below are typical B-die timings. Use these as base timings; lower is better but usually more expensive and not always a better bin:

- [3200 14-14-14-XX 1.35v](https://pcpartpicker.com/products/memory/#Z=16384002&amp;L=30,140&amp;B=1200000000,1350000000&amp;s=403200&amp;sort=price)
- Avoid 3600 as it&#39;s usually not always B-die i.e. 3600 16-19-19 = not B-die, 3600 16-16-16 = overpriced
- [4000 18-20-20-XX 1.35v](https://pcpartpicker.com/products/memory/#Z=16384002&amp;L=30,180&amp;B=1200000000,1350000000&amp;sort=price&amp;s=404000) (or better)
- [4133+](https://pcpartpicker.com/products/memory/#Z=16384002&amp;L=30,190&amp;sort=price&amp;s=404133,404200,404266,404300,404333,404400,404500,404600,404700,404800,404866,405000)
- [https://pcpartpicker.com/list/FGzLp2](https://pcpartpicker.com/list/FGzLp2) (non-exhaustive B-die list)
  - XTREEM / Viper Steel lack temperature sensors

- [Image comparison](https://i.imgur.com/rFRDe0M.jpg) of A0/A1/A2/A3 PCBs ([Source](https://www.facebook.com/photo.php?fbid=1517832921732388&amp;set=pb.100005170833640.-2207520000..&amp;type=3))

All else equal, dual-rank RAM performs better than single-rank RAM. However, more ranks require more voltage for the same timings and require a high quality motherboard for better signal integrity. Keep in mind many of the kits in this list have RGB which is detrimental to performance.

- [https://pcpartpicker.com/list/bTmqYH](https://pcpartpicker.com/list/VMxkLP) (non-exhaustive dual rank B-die list [2x16])

GPUs:

At low settings, the CPU and RAM are more important than the GPU for high refresh rate gaming. You want a stable foundation (CPU and RAM) before buying a GPU, so a 5 GHz 9700K is the minimum for driving high refresh rates. Avoid buying blower cards (one fan), avoid overly cheap cards, and be wary of problems brought up in reviews. AMD video cards offer lots of tweaking headroom but may lack optimizations in certain games. Nvidia cards are regarded as more stable and have better optimization from game developers (especially Unreal Engine), but lack the modding and tuning opportunities that the AMD offerings have. AMD&#39;s video encoder is very far behind Nvidia&#39;s; both quality and stability-wise, so keep this in mind (streaming/recording). Linux driver support is typically better for AMD.

RTX 3060 Ti - Roughly 2080 Super performance, does not use GDDR6X unlike the 3080/90

RTX 3070 - Roughly 2080 Ti performance for much cheaper, also no G6X

RTX 3080 - Solid performance, ASUS models have I2C support which allows for interfacing with tools such as the [EVC2S](https://www.elmorlabs.com/index.php/product/evc2s/) for external voltage control

RTX 3090 - Flagship Nvidia offering, very high premium over 3080

- Avoid Ampere reference (Nvidia) models due to poor thermals
- Power consumption of Ampere is higher than previous generations which requires a good power supply
- Ampere NVENC untouched from Turing

RX 6800 / 6800 XT / 6900 XT

- Better rasterization performance than competing Nvidia models, similar or better 1080p performance, lack of G6X is apparent at higher resolutions such as 4K where performance starts to lag behind Nvidia models due to memory bottlenecking
- Very high overclocks are possible (2.5+ GHz)

- Beware of driver issues for Radeon cards
  - Windows 7 drivers are especially buggy on 5000-series
- AMD has no equivalent of [Nvidia&#39;s Reflex](https://www.nvidia.com/en-us/geforce/news/reflex-low-latency-platform/#reducing-system-latency-with-nvidia-reflex) which you may want to consider when purchasing a GPU

Monitors:

Monitors have many sources of latency, starting from the GPU&#39;s output to the display itself. CRTs have very low latency because lower signal processing is required and the nature of CRT technology (once the signal is converted to analog, a CRT&#39;s latency is basically the refresh rate), [whereas LCDs have multiple components](http://monitorinsider.com/monitor_anatomy/) (such as the scalar, timing controller, source drivers, TFT) and each have their own delays.

I will only cover 240Hz+ monitors since CRTs are no longer in production. The latency can be split into two categories: _processing_ and _pixel response time_. Processing is the delay of the monitor processing the signal, whereas response time is how quickly the pixel can change states (manifests as motion blur). An example below shows the separation of the processing and response time latencies. Note that this selection of monitors is very limited, so don&#39;t base your monitor purchase off a single source. Typically IPS monitors such as the VG279QM will have lower processing latency than TN monitors, but will suffer from worse response times. Avoid monitors with [PWM (pulse-width modulation)](https://www.notebookcheck.net/Why-Pulse-Width-Modulation-PWM-is-such-a-headache.270240.0.html) at all costs, even if high frequency.

![](RackMultipart20210422-4-5rf0hu_html_65f8cc6a7cca5b91.png)

Source: [https://www.tftcentral.co.uk/reviews/asus\_rog\_swift\_360hz\_pg259qn.htm#lag](https://www.tftcentral.co.uk/reviews/asus_rog_swift_360hz_pg259qn.htm#lag)

Avoid first generation (~2017-2018) 240Hz monitors as they have higher signal and response time latencies than second generation (~2019-2020) monitors. Examples of common 1st generation monitors:

- Acer XF250Q
- Dell AW2518Hf
- ASUS XG248/258Q
- ASUS PG248/[258Q](https://www.tftcentral.co.uk/reviews/asus_rog_swift_pg258q.htm)
- BenQ [XL2540](https://www.rtings.com/monitor/reviews/benq/zowie-xl2540)/2546
- ViewSonic XG2530

2nd generation monitors are usually the same price so there&#39;s little point in buying 1st generation monitors. Some examples of gen. 2 monitors:

- Acer XF252Q ([RTINGS](https://www.rtings.com/monitor/reviews/acer/nitro-xf252q))
- Omen X 25f ([RTINGS](https://www.rtings.com/monitor/reviews/hp/omen-x-25f))
- Asus VG259QM ([RTINGS](https://www.rtings.com/monitor/reviews/asus/tuf-gaming-vg259qm))
- Asus VG279QM ([RTINGS](https://www.rtings.com/monitor/reviews/asus/vg279qm)) ([TFTCentral](https://www.tftcentral.co.uk/reviews/asus_tuf_gaming_vg279qm.htm))

If you can afford them, consider the 360Hz monitors for their lower signal and response times compared to 240Hz monitors:

- Asus PG259QN ([RTINGS](https://www.rtings.com/monitor/reviews/dell/alienware-aw2521h)) ([TFTCentral](https://www.tftcentral.co.uk/reviews/asus_rog_swift_360hz_pg259qn.htm))
- Dell AW2521H ([RTINGS](https://www.rtings.com/monitor/reviews/asus/rog-swift-360hz-pg259qn))

Monitor review sites with latency measurements (do not compare latency measurements from different sources due to differing test methods)

[https://www.tftcentral.co.uk/reviews.htm](https://www.tftcentral.co.uk/reviews.htm)

[https://www.rtings.com/monitor/reviews](https://www.rtings.com/monitor/reviews)

[https://pcmonitors.info/reviews/archive/](https://pcmonitors.info/reviews/archive/)

![](RackMultipart20210422-4-5rf0hu_html_35fecfa332938c25.jpg)

**Miscellaneous links**

Windows ISOs

[https://digitalrivermirror.com/](https://digitalrivermirror.com/) (Windows 7)

[https://the-eye.eu/public/MSDN/](https://the-eye.eu/public/MSDN/) (Windows XP, Vista, 7, 8, 8.1, 10 1511/1607)

[https://tb.rg-adguard.net/public.php](https://tb.rg-adguard.net/public.php) (Windows 8.1 - Windows 10 2009)

[https://docs.google.com/spreadsheets/d/14-D4tIlFp9APP0OOvQBRXvfLOYC447UygywenX5LXfo/](https://docs.google.com/spreadsheets/d/14-D4tIlFp9APP0OOvQBRXvfLOYC447UygywenX5LXfo/edit#gid=960687212) (Windows XP - Windows 10 1809, Windows 8.0 missing, many dead links)

[https://docs.google.com/spreadsheets/d/1zTF5uRJKfZ3ziLxAZHh47kF85ja34\_OFB5C5bVSPumk/](https://docs.google.com/spreadsheets/d/1zTF5uRJKfZ3ziLxAZHh47kF85ja34_OFB5C5bVSPumk/) (Windows XP - Windows 10 1909)

Hash checks: [1](https://files.rg-adguard.net/version/f0bd8307-d897-ef77-dbd6-216fefbe94c5)[2](https://www.heidoc.net/php/myvsdump.php)

Windows 7 driver integration (Win7 lacks USB 3 and NVMe drivers which will prevent you from installing if using these devices. Use these resources to get around the limitations)

[How to use NTLite to integrate drivers](https://www.win-raid.com/t750f25-Guide-Integration-of-drivers-into-a-Win-image.html)

- [Generic Win7/Vista USB3 drivers](https://forums.mydigitallife.net/threads/usb-3-xhci-driver-stack-for-windows-7-vista.81934/) - supports 8KHz polling natively
- [Z370 USB+NVMe iso integration tool](http://download.gigabyte.eu/FileList/Utility/mb_utility_windowsimagetool_B18.0213.1.zip)
- [Z390 USB drivers](https://drive.google.com/file/d/1akxmt_B382SJ8JwRoMataazTmOfzRt6d/view?usp=sharing) - from [canonkong](https://www.win-raid.com/t4883f52-Solution-Win-drivers-for-USB-Controllers-of-new-Intel-chipset-systems.html) - requires [IMOD change](https://djdallmann.github.io/GamingPCSetup/CONTENT/RESEARCH/PERIPHERALS/) for 2KHz+
- [Z490 USB drivers](https://drive.google.com/file/d/120f1o_kxV-wF0Ax13yJxkUzsyBsDNU6D/view?usp=sharing) - from m0nkrus, uploaded by [NewcomerAl](https://www.win-raid.com/t4883f52-Solution-Win-drivers-for-USB-Controllers-of-new-Intel-chipset-systems-18.html#msg111959) - requires [IMOD change](https://djdallmann.github.io/GamingPCSetup/CONTENT/RESEARCH/PERIPHERALS/) for 2KHz+
- [Intel UHD 630 driver](https://www.biostar.com.tw/app/en/event/H310_windowstool/win7_8th_i3_i5_Driver_2.0.rar)
- [Intel I219-V driver](https://downloadmirror.intel.com/18713/eng/PROWinx64Legacy.exe)

- [Intel I225-V driver](https://drive.google.com/file/d/1HaDiZzJkU6SRiSQI4F1KLwPTfkPlycTN/view?usp=sharing) - from [canonkong and daniel\_k](https://www.win-raid.com/t7402f42-Installing-i-v-ethernet-drivers-W-drivers-on-windows.html)

- [Realtek 2.5G driver](https://www.realtek.com/en/component/zoo/category/network-interface-controllers-10-100-1000m-gigabit-ethernet-pci-express-software)

- [Microsoft generic NVMe driver](https://drive.google.com/file/d/1NMTu8aZXXVdOAHOu7U6_q--Id9_-pmZl/view?usp=sharing) ([KB2990941](https://support.microsoft.com/en-us/kb/2990941)[KB3087873](http://download.windowsupdate.com/d/msdownload/update/software/htfx/2015/09/windows6.1-kb3087873-v2-x64_098e3dc3e7133ba8a37b2e47260cd8cba960deb8.msu))
  - Other [Storage drivers](https://www.win-raid.com/t29f25-Recommended-AHCI-RAID-and-NVMe-Drivers.html) (NVMe, SATA AHCI/RAID)
- Full UEFI installation: [https://github.com/manatails/uefiseven](https://github.com/manatails/uefiseven)

Stress testing software for overclocking

RAM:

- Karhu: [https://www.karhusoftware.com/ramtest/](https://www.karhusoftware.com/ramtest/)
- TM5: [https://testmem.tz.ru/testmem5.htm](https://testmem.tz.ru/testmem5.htm)[extreme@anta777 config](https://drive.google.com/file/d/1uegPn9ZuUoWxOssCP4PjMjGW9eC_1VJA/edit)
- HCI: [https://hcidesign.com/memtest/](https://hcidesign.com/memtest/)[MemTestHelper](https://github.com/integralfx/MemTestHelper)
- Prime95 Large FFTs: [https://www.mersenne.org/download/](https://www.mersenne.org/download/)
- MemTest86 (preliminary test before booting into Windows): [https://www.memtest86.com/](https://www.memtest86.com/)

CPU:

- Linpack Xtreme: [https://www.techpowerup.com/download/linpack-xtreme/](https://www.techpowerup.com/download/linpack-xtreme/)
- Prime95 Small FFTs: [https://www.mersenne.org/download/](https://www.mersenne.org/download/)

Why latency matters

[https://www.youtube.com/watch?v=vOvQCPLkPt4](https://www.youtube.com/watch?v=vOvQCPLkPt4) - &quot;Applied Sciences Group: High Performance Touch&quot;

Cancerogeno&#39;s Nvidia overclocking guide

[https://docs.google.com/document/d/14ma-\_Os3rNzio85yBemD-YSpF\_1z75mZJz1UdzmW8GE/edit](https://docs.google.com/document/d/14ma-_Os3rNzio85yBemD-YSpF_1z75mZJz1UdzmW8GE/edit)

Collection of various resources devoted to performance and input lag optimization

[https://github.com/BoringBoredom/PC-Optimization-Hub](https://github.com/BoringBoredom/PC-Optimization-Hub)

r0ach&#39;s BIOS optimization guide

[https://www.overclock.net/forum/6-intel-motherboards/1433882-gaming-mouse-response-bios-optimization-guide-modern-pc-hardware.html](https://www.overclock.net/forum/6-intel-motherboards/1433882-gaming-mouse-response-bios-optimization-guide-modern-pc-hardware.html)

How LCD Response Times are Measured, and Why 10% to 90% GtG Measurements are Moderately Deceptive

[https://www.youtube.com/watch?v=MbZUgKpzTA0](https://www.youtube.com/watch?v=MbZUgKpzTA0)

Optimizing Computer Applications for Latency: Part 1: Configuring the Hardware

[https://software.intel.com/en-us/articles/optimizing-computer-applications-for-latency-part-1-configuring-the-hardware](https://software.intel.com/en-us/articles/optimizing-computer-applications-for-latency-part-1-configuring-the-hardware)

Fujitsu Primergy Server BIOS Settings for Performance, Low-Latency and Energy Efficiency

[https://sp.ts.fujitsu.com/dmsp/Publications/public/wp-bios-settings-primergy-ww-en.pdf](https://sp.ts.fujitsu.com/dmsp/Publications/public/wp-bios-settings-primergy-ww-en.pdf)

Better HyperThreading/SMT explanation

[www.cs.virginia.edu/~mc2zk/cs451/vol6iss1\_art01.pdf](http://www.cs.virginia.edu/~mc2zk/cs451/vol6iss1_art01.pdf)

Latency and Gaming Discord

[https://discord.com/invite/QvPubRq](https://discord.com/invite/QvPubRq)

Follow me on Twitter

[https://twitter.com/CaIypto](https://twitter.com/CaIypto)

![](RackMultipart20210422-4-5rf0hu_html_d096ea2f14f81e77.png)

The fruit of my labor. One of the hardest scenarios in Kovaak&#39;s Aim Trainer (now outdated but still a decent score)
