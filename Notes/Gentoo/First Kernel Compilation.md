Installing the kenel source can be done with:

`emerge --ask sys-kernel/`

Before configuring, you may want to emerge:

`emerge --ask sys-apps/pciutils`

To get some information before confuring.

First list the available kernels, you may only see one.

`eselect kernel list`

Then set the kernel you want.

`eselect kernel set 1`

CD into the kernel directory:

`cd /usr/src/linux`
Then run make menuconfig
`make menuconfig`

From here you will see different symbols, heres what they mean

| [\*], [ ] | These options can either be deactivated or activated, simple. |
| < >, <\*>, <M> | These options can be activated, deactivated or activated as a module. [What's the difference?](https://wiki.gentoo.org/wiki/Kernel_Modules) |
| {\*}, {M} | These can be activated or as a module but not deactivated because there it is a dependency of something else. |
| -\*-, -M- | You have no option, you will definitely see these as the required gentoo [options]()|


**TIP:** You can search the options with the `/` key.

## Required Options

Gentoo Linux --->
  Generic Driver Options --->
    [\*] Gentoo Linux support
    [\*]   Linux dynamic and persistent device naming (userspace devfs) support
    [\*]   Select options required by Portage features
        Support for init systems, system and service managers  --->
          [\*] systemd
          
### Enabling devtmpfs support
Device Drivers --->
  Generic Driver Options --->
    [\*] Maintain a devtmpfs filesystem to mount at /dev
    [\*]   Automount devtmpfs at /dev, after the kernel mounted the rootfs
### Enabling SCSI Disk support
Device Drivers --->
   SCSI device support  --->
      <\*> SCSI disk support
### Enabling filesystems
This depends on your disk configuration and preference, the pseudo filesystems are required.
File systems --->
  <\*> The Extended 4 (ext4) filesystem
  <\*> Btrfs filesystem support

Pseudo Filesystems --->
    [\*] /proc file system support
    [\*] Tmpfs virtual memory file system support (former shm fs)
    
If you have multiple cores/threads, enable SMP.
Processor type and features  --->
  [\*] Symmetric multi-processing support
    
Enabling certain USB support via:
Device Drivers --->
  HID support  --->
    -\*- HID bus support
    <\*>   Generic HID driver
    [\*]   Battery level reporting for HID devices
      USB HID support  --->
        <*> USB HID transport layer
  [\*] USB support  --->
    <\*>     xHCI HCD (USB 3.0) support
    <\*>     EHCI HCD (USB 2.0) support
    <\*>     OHCI HCD (USB 1.1) support
    


It may be helpful to read [this](https://wiki.gentoo.org/wiki/Kernel/Gentoo_Kernel_Configuration_Guide)
