It may appear to the normal user as if it is either on or off, but there are many different classes of power states that are used to lower the power used when there are minimal need for it to be at full power.

## P-States
P-States, also known as Power Performance States scale the current frequency and voltage. The number of available P-States depends on the processor. The higher number the P-State is, the lower the frequency, voltage and power consumption will be.

### Forcing P0 on Nvidia GPUs (credit: Chrometastic)
Locking your GPU allows you to never downclock, which may cause heating issues. Do this at your own risk.

**If you have any games open, close them.**

Open command prompt as Admin (required)
then cd into the NVSMI directory:

`cd "C:\Program Files\NVIDIA Corporation\NVSMI\"`

then run this to check your current P-State:

`nvidia-smi -q -d performance`
Usually it will show P8, you want it to say P0. If it says P0, you don't have to do this.

... To be finshed at a later point in time.



## C-States
C-States lower power usage by powering down subsystems, here is the list of C-States:

### Main C-States
- C0: Active, if also at P0, operating at maximum performance.
- C1: Halted, can resume instantaneously. P0 and up only matter at C0
  - Core Clock: Off
- C2: Stop-Clock, same as C1, but taking longer to resume.
  - Core Clock: Off
  - Temporary State before transitioning to C3
- C3: Sleep, C2 but taking a noticably longer time to resume.
  - Core Clock: Off
  - [PLL](https://en.wikipedia.org/wiki/Phase-locked_loop): Off
  - L1/L2 Cache: Flushed

### Modern C-States
In modern CPUs, there are more than just package (CPU) states and there are Core and Thread states.
Modern CPUs have more C-States, here is a list:
- C1E: C1, but running at the lowest frequency and voltage.
- C4E/C5: Reduces voltage even more and turns off the memory cache
- C6: Save states before shutdown, shutdown.
- C7: C6 but LLC (Low level cache) may be flushed.
- C8: C7 but LLC must be flushed.

## S-States
S-States, or sleep states are OS controlled states. You may recognize it as Sleep or Hibernate. S1-S3 are known as sleep and S4 is known as Hibernate.
- S0: Similar to C0, this is when it is running at max performance.
- S1: Low latency wake state (Sleep)
  - Power is still provided to CPU and RAM
  - Instructions halted
  - System will need to compatible with ACPI to comply with these feautures
- S2: Similar to S1 (Sleep)
  - CPU and System cache flushed
  - Power to processor is shutdown
- S3: Traditional Sleep/Legacy Standby (Sleep)
  - All other contexts than RAM are cleared
  - System state is loaded into RAM
- S4: Hibernation
  - Power is cut off to all devices, including hard drives
  - System state is loaded to file on system hard drive before shutdown, known as hiberfil.sys
  - No power is used while in hibernation

### How can I check what S-States my system supports?

By running the following command in command prompt, you will find all the states that your system supports.

`powercfg /a`

For ideal performance and latency, you want it to appear similar to this:

<img src="images/Support S-States.png">




## References
- [A Minimum Complete Tutorial of CPU Power Management](https://metebalci.com/blog/a-minimum-complete-tutorial-of-cpu-power-management-c-states-and-p-states)
- [Processor P-States and C-States](https://www.thomas-krenn.com/en/wiki/Processor_P-states_and_C-states)
- [C-States, P-States, and S-States](https://www.technikaffe.de/anleitung-32-c_states_p_states_s_states__energieverwaltung_erklaert)
- [Power Management States](https://www.techjunkie.com/power-management-states-s-state-p-state)
- [ACPI - Wikipedia](https://en.wikipedia.org/wiki/Advanced_Configuration_and_Power_Interface)
- [C-States](https://gist.github.com/wmealing/2dd2b543c4d3cff6cab7)
