# **Windows Timers Explained**
Credit Felipe, based on opinion

## Timers

Many people made complex over the past years. I will be short and simple. The best scenario is with system defaults=TSC+HPET. There is still another option, unusual but some people like, that is ACPI PMT, which makes the values of “meme” LatencyMon raise by a lot but gives smoothness to the games at a cost of some performance. PMT usually feels best on older windows as well.

I used to also recommend TSC+ACPI PMT, but on games that need “sync” it is a really inferior option. Noone can really prove if X or Y will feel better on your pc, you should test/try. Just please don't be obsessive because it went crazy the past years and the answer was the default..

- Windows 10 1809+ has a fixed 10MHz TSC QPC frequency and a 24MHz HPET QPC frequency
- If you don't have the HPET option in BIOS, then it’s enabled by default
- If you want disable HPET without having it on BIOS, you use GRUB

TSC + HPET (2-4MHz)

- **bcdedit /deletevalue useplatformclock**
- Enable HPET in BIOS

ACPI PMT (3.57MHz-3.58MHz)

- **bcdedit /set useplatformclock yes**
- Disable HPET in BIOS

TSC + ACPI PMT (2-4MHz)

- **bcdedit /set useplatformclock no**
- Disable HPET in BIOS

HPET

- **bcdedit /set useplatformclock yes**
- Enable HPET in BIOS

Timer Resolution

Another “tweak” that people used without really knowing what it is, is forcing the lowest resolution to the system. Most applications/games already drop the system default resolution, but most only close to 1.0. You can improve your input, latency and FPS using a tool to force the timer, I recommend this one who uses 1 thread ([TimerResolution](https://cms.lucashale.com/timer-resolution/)[.](https://cms.lucashale.com/timer-resolution/)[exe](https://cms.lucashale.com/timer-resolution/)).

**Only do this if you use HPET in BIOS ENABLED, otherwise you will fuck your smoothness and ram latency.**
