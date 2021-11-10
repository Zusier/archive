||Created by imribiy#7966 / You can try my 1803 based XOS for free on: https://dsc.gg/xos|
| - | - |
||Contact me if you want to contribute.|||||
||**TPM State** | Security related, safe to disable|||||
|Tweaked|Disabled: 0x0|||||||
|Default|Enabled: 0x1 (default)|||||||
||||||||||
||**AMD fTPM switch** |Security related, safe to disable||||
|Default|AMD CPU fTPM: 0x0 (default)||||||
|Tweaked|AMD CPU fTPM Disabled: 0x1||||||
||||||||||
||**HPET** | Some people get better latency when they close it, some don't.||
|Tweaked|Disabled: 0x0|||||||
|Default|Enabled: 0x1 (default)|||||||
||||||||||
||**Global C-state Control** | Power saving feature, must close.|||
|Tweaked|Disabled: 0x0|||||||
||Enabled: 0x1|||||||
|Default|Auto: 0x3 (default)|||||||
||||||||||
||**Chipset Power Saving Features** | Power saving feature, must close.|||
|Tweaked|Disabled: 0x0|||||||
|Default|Enabled: 0x1 (default)|||||||
||||||||||
||**Remote Display Feature** | Safe to disable.|||||
|Tweaked|Disabled: 0x0|||||||
||Enabled: 0x1|||||||
|Default|Auto: 0xFF (default)|||||||
||||||||||
||**PS2 Devices Support** | Safe to close if you don't use PS2 port.|||
|Tweaked|Disabled: 0x0|||||||
|Default|Enabled: 0x1 (default MFG)||||||
||||||||||
||**Network Stack Driver Support** | Safe to disable.||||
|Tweaked|Disabled: 0x0|||||||
|Default|Enabled: 0x1 (default MFG)||||||
||||||||||
|It's already set disabled on default, just check.| **Security Device Support** Security related, safe to disable.|||
||Disable: 0x0 (default)|||||||
||Enable: 0x1|||||||
||||||||||
||**Ipv6 PXE Support** | Safe to close if you don't use ipv6||||
|Tweaked|Disabled: 0x0|||||||
|Default|Enabled: 0x1 (default)|||||||
||||||||||
||**IPv6 HTTP Support** | Safe to close if you don't use ip6||||
|Tweaked|Disabled: 0x0|||||||
|Default|Enabled: 0x1|||||||
||||||||||
||**PSS Support** | Microsoft Product Support Service, safe to close.|||
|Tweaked|Disabled: 0x0|||||||
||Enabled: 0x1|||||||
|Default|Auto: 0x2 (default)|||||||
| - | - | - | - | - | - | - | - |
||||||||||
||**AB Clock Gating** | About power saving, safe to close.||||
|Tweaked|Disabled: 0x0|||||||
||Enabled: 0x1|||||||
|Default|Auto: 0xFF (default)|||||||
||||||||||
||**PCIB Clock Run** | About power saving, safe to close.||||
|Tweaked|Disabled: 0x0|||||||
||Enabled: 0x1|||||||
|Default|Auto: 0xFF (default)|||||||
||||||||||
||**UMA Mode** | About internal graphics, disable if you don't use.|||
|Tweaked|None: 0x0||||||||
||UMA\_SPECIFIED: 0x1||||||
||UMA\_AUTO: 0x2|||||||
|Default|Auto: 0xFF (default)|||||||
||||||||||
||**SR-IOV Support** | About virtualization, safe to close.||||
|Tweaked|Disabled: 0x0|||||||
|Default|Enabled: 0x1|||||||
||||||||||
||**BME DMA Mitigation** | About security, safe to close.||||
|Tweaked|Disabled: 0x0|||||||
|Default|Enabled: 0x1|||||||
||||||||||
||**GPIO Devices Support** | It probably won't change anything but set it Auto||
|Default|Enabled: 0x1 (default)|||||||
|Tweaked|Auto: 0xFF||||||||
||||||||||
||**Integrated Graphics** | Disable it if you don't use||||
|Default|Auto: 0x0 (default)|||||||
|Tweaked|Disabled: 0x1|||||||
||Force: 0x2||||||||
||||||||||
||**Opcache Control** | Power saving feature, disable it.||||
|Tweaked|Disabled: 0x1|||||||
||Enabled: 0x0|||||||
|Default|Auto: 0xFF (default)|||||||
