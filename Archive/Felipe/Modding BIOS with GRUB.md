## Modding BIOS with GRUB
Credits to NRK, Bored, Made by Felipe

GRUB can mod your motherboard and change hidden or locked settings/value in BIOS.
Before modding your motherboards BIOS I wanna remind you this was not intended by the motherboards manufacturer. This can result in bricking your motherboard or making it perform worse if done wrong. If you follow along to this part of the guide correctly you should be fine. The most common example of doing it wrong is not using the correct varStore in the command while in grub.

Okay, now first you wanna download your BIOS version from the manufacturers website, please download the right version that is being used by your motherboard, please check the version beforehand. The file you want is something like MAXIMUS-VII-HERO-ASUS-3503.CAP, as the motherboard is a MAXIMUS VII HERO and the bios version is 3503. After finding the correct file for your BIOS version you will want to download this file to open your BIOS file. [https](https://cdn.discordapp.com/attachments/766680501284241460/772333101594312744/UEFITool_0.28.0_win32.zip)[://](https://cdn.discordapp.com/attachments/766680501284241460/772333101594312744/UEFITool_0.28.0_win32.zip)[cdn](https://cdn.discordapp.com/attachments/766680501284241460/772333101594312744/UEFITool_0.28.0_win32.zip)[.](https://cdn.discordapp.com/attachments/766680501284241460/772333101594312744/UEFITool_0.28.0_win32.zip)[discordapp](https://cdn.discordapp.com/attachments/766680501284241460/772333101594312744/UEFITool_0.28.0_win32.zip)[.](https://cdn.discordapp.com/attachments/766680501284241460/772333101594312744/UEFITool_0.28.0_win32.zip)[com](https://cdn.discordapp.com/attachments/766680501284241460/772333101594312744/UEFITool_0.28.0_win32.zip)[/](https://cdn.discordapp.com/attachments/766680501284241460/772333101594312744/UEFITool_0.28.0_win32.zip)[attachments](https://cdn.discordapp.com/attachments/766680501284241460/772333101594312744/UEFITool_0.28.0_win32.zip)[/766680501284241460/772333101594312744/](https://cdn.discordapp.com/attachments/766680501284241460/772333101594312744/UEFITool_0.28.0_win32.zip)[UEFITool](https://cdn.discordapp.com/attachments/766680501284241460/772333101594312744/UEFITool_0.28.0_win32.zip)[_0.28.0_](https://cdn.discordapp.com/attachments/766680501284241460/772333101594312744/UEFITool_0.28.0_win32.zip)[win](https://cdn.discordapp.com/attachments/766680501284241460/772333101594312744/UEFITool_0.28.0_win32.zip)[32.](https://cdn.discordapp.com/attachments/766680501284241460/772333101594312744/UEFITool_0.28.0_win32.zip)[zip](https://cdn.discordapp.com/attachments/766680501284241460/772333101594312744/UEFITool_0.28.0_win32.zip)

After opening the BIOS file you will use the search function to enter ‘’High Precision’’ or on Asrock boards ‘’Acpi HPET Table’’, this should show your main bios with multiple hidden settings. You will want to extract the files you found ‘’Extract as is...’’

After extracting the file you will load it and extract it again with this program. [https](https://cdn.discordapp.com/attachments/766680501284241460/772333216844480512/IRFExtractor_0.3.6_win.zip)[://](https://cdn.discordapp.com/attachments/766680501284241460/772333216844480512/IRFExtractor_0.3.6_win.zip)[cdn](https://cdn.discordapp.com/attachments/766680501284241460/772333216844480512/IRFExtractor_0.3.6_win.zip)[.](https://cdn.discordapp.com/attachments/766680501284241460/772333216844480512/IRFExtractor_0.3.6_win.zip)[discordapp](https://cdn.discordapp.com/attachments/766680501284241460/772333216844480512/IRFExtractor_0.3.6_win.zip)[.](https://cdn.discordapp.com/attachments/766680501284241460/772333216844480512/IRFExtractor_0.3.6_win.zip)[com](https://cdn.discordapp.com/attachments/766680501284241460/772333216844480512/IRFExtractor_0.3.6_win.zip)[/](https://cdn.discordapp.com/attachments/766680501284241460/772333216844480512/IRFExtractor_0.3.6_win.zip)[attachments](https://cdn.discordapp.com/attachments/766680501284241460/772333216844480512/IRFExtractor_0.3.6_win.zip)[/766680501284241460/772333216844480512/](https://cdn.discordapp.com/attachments/766680501284241460/772333216844480512/IRFExtractor_0.3.6_win.zip)[IRFExtractor](https://cdn.discordapp.com/attachments/766680501284241460/772333216844480512/IRFExtractor_0.3.6_win.zip)[_0.3.6_](https://cdn.discordapp.com/attachments/766680501284241460/772333216844480512/IRFExtractor_0.3.6_win.zip)[win](https://cdn.discordapp.com/attachments/766680501284241460/772333216844480512/IRFExtractor_0.3.6_win.zip)[.](https://cdn.discordapp.com/attachments/766680501284241460/772333216844480512/IRFExtractor_0.3.6_win.zip)[zip](https://cdn.discordapp.com/attachments/766680501284241460/772333216844480512/IRFExtractor_0.3.6_win.zip)

After extracting the file to a .txt file you will rename it to a.txt and extract it with Bored’s tool [https](https://github.com/BoringBoredom/extractsettings)[://](https://github.com/BoringBoredom/extractsettings)[github](https://github.com/BoringBoredom/extractsettings)[.](https://github.com/BoringBoredom/extractsettings)[com](https://github.com/BoringBoredom/extractsettings)[/](https://github.com/BoringBoredom/extractsettings)[BoringBoredom](https://github.com/BoringBoredom/extractsettings)[/](https://github.com/BoringBoredom/extractsettings)[extractsettings](https://github.com/BoringBoredom/extractsettings)

Bored’s tool will sort and format the file so it's easy to read and use.

After sorting it you will open the b.txt file and find the settings that are hidden/that you couldn’t find in your BIOS originally like power saving features, global c states, C1E, power gating, power down, gear down, basically you will have to look thro your own bios settings and decide what you want to change. My list is just to have an idea on what to change. When finding settings note them down in a notepad or on your phone as you will need to know the values when changing the settings.

Now make a bootable flash drive on FAT32
Add all the files from this to the bootable drive. 

https://ftp.gnu.org/gnu/grub/grub-2.04-for-windows.zip

Set bios to UEFI, disable secure boot and boot to the bootable drive (If booting from USB doesn’t work, boot to EFI Shell from Bios)
The EFI shell will open. Select your flash drive). You will see from the list which one  it is.

Type CD BOOT\EFI

Type bootx64.efi

GRUB will open.

Here you can edit any setting that you noted down from the text files.

To change you use this template:

setup\_var offset [value] [variable name]

variable name is the VarStore





For example:

Chipset Power Saving Features | VarOffset: 0xB7, VarStore: Setup (0x1)

`      	`Disabled: 0x0

`      	`Enabled: 0x1 (default)

“Setup\_var  0xB7 0x0 Setup” this will disable Chipset Power Saving Features

“Setup\_var  0xB7 0x0 Setup” this will enable Chipset Power Saving Features

“Setup\_var  0xB7 Read Setup” this will show what setting it has it set to.

After this is done you restart pc, and you should be done!

EXAMPLE : My current Grub List of Maximus VII Hero z97 motherboard

Enable Hibernation | VarOffset: 0x17, Varstore: Setup (0x1) Disabled: 0x0

PS/2 Keyboard and Mouse Support | VarOffset: 0x21, VarStore: Setup (0x1) Disabled: 0x2

ACPI Sleep State | VarOffset: 0x14, VarStore: Setup (0x1) Suspend Disabled: 0x0

CPU C-States | VarOffset: 0x4F, VarStore: Setup (0x1) Disabled: 0x0 

Enhanced C1 State | VarOffset: 0x56, VarStore: Setup (0x1) Disabled: 0x0

CPU C-States | VarOffset: 0x4F, VarStore: Setup (0x1) Disabled: 0x0

CPU C3 Report | VarOffset: 0x50, VarStore: Setup (0x1) Disabled: 0x0 

CPU C6 Report | VarOffset: 0x51, VarStore: Setup (0x1) Disabled: 0x0 

CPU C7 Report | VarOffset: 0x52, VarStore: Setup (0x1) Disabled: 0x0

CPU C8 report | VarOffset: 0x63, VarStore: Setup (0x1) Disabled: 0x0 

CPU C9 report | VarOffset: 0x64, VarStore: Setup (0x1) Disabled: 0x0 

CPU C10 report | VarOffset: 0x65, VarStore: Setup (0x1) Disabled: 0x0 

C state Pre-Wake | VarOffset: 0x5F, VarStore: Setup (0x1) Disabled: 0x0 

Package C-States Support | VarOffset: 0x69, VarStore: Setup (0x1) C0/C1: 0x0

PCIE LTR | VarOffset: 0x117, VarStore: Setup (0x1) Disabled: 0x0 

PCIE LTR Lock | VarOffset: 0x11F, VarStore: Setup (0x1) Disabled: 0x0 

PCIE LTR | VarOffset: 0x118, VarStore: Setup (0x1) Disabled: 0x0 

PCIE LTR Lock | VarOffset: 0x120, VarStore: Setup (0x1) Disabled: 0x0 

PCIE LTR | VarOffset: 0x119, VarStore: Setup (0x1) Disabled: 0x0 

PCIE LTR Lock | VarOffset: 0x121, VarStore: Setup (0x1) Disabled: 0x0 

PCIE LTR | VarOffset: 0x11A, VarStore: Setup (0x1) Disabled: 0x0 

PCIE LTR Lock | VarOffset: 0x122, VarStore: Setup (0x1) Disabled: 0x0 

PCIE LTR | VarOffset: 0x11B, VarStore: Setup (0x1) Disabled: 0x0 

PCIE LTR Lock | VarOffset: 0x123, VarStore: Setup (0x1) Disabled: 0x0 

PCIE LTR | VarOffset: 0x11C, VarStore: Setup (0x1) Disabled: 0x0 

PCIE LTR Lock | VarOffset: 0x124, VarStore: Setup (0x1) Disabled: 0x0 

PCIE LTR | VarOffset: 0x11D, VarStore: Setup (0x1) Disabled: 0x0 

PCIE LTR Lock | VarOffset: 0x125, VarStore: Setup (0x1) Disabled: 0x0 

PCIE LTR | VarOffset: 0x11E, VarStore: Setup (0x1) Disabled: 0x0 

PCIE LTR Lock | VarOffset: 0x126, VarStore: Setup (0x1) Disabled: 0x0 

Power Down Mode | VarOffset: 0x374, VarStore: Setup (0x1) No Power Down: 0x0

Power Down Mode | VarOffset: 0x375, VarStore: Setup (0x1) No Power Down: 0x0

DDR PowerDown and idle counter | VarOffset: 0x376, VarStore: Setup (0x1) PCODE: 0x0

PowerDown Energy Ch0Dimm0 | VarOffset: 0x3B4, VarStore: Setup (0x1) Max: 0x3F or Min:0x0

PowerDown Energy Ch0Dimm1 | VarOffset: 0x3B3, VarStore: Setup (0x1) Max: 0x3F or Min:0x0

PowerDown Energy Ch1Dimm0 | VarOffset: 0x3BE, VarStore: Setup (0x1) Max: 0x3F or Min:0x0

PowerDown Energy Ch1Dimm1 | VarOffset: 0x3BD, VarStore: Setup (0x1) Max: 0x3F or Min:0x0

SelfRefresh Enable | VarOffset: 0x3C5, VarStore: Setup (0x1) Disabled: 0x0 

Enable Hibernation | VarOffset: 0x17, Varstore: Setup (0x1) Disabled: 0x0 



Also theres a link about Zoyata GRUB ideas, just dont change if you dont know what to do.

[https](https://imgur.com/a/wupJmpx)[://](https://imgur.com/a/wupJmpx)[imgur](https://imgur.com/a/wupJmpx)[.](https://imgur.com/a/wupJmpx)[com](https://imgur.com/a/wupJmpx)[/](https://imgur.com/a/wupJmpx)[a](https://imgur.com/a/wupJmpx)[/](https://imgur.com/a/wupJmpx)[wupJmpx](https://imgur.com/a/wupJmpx)
