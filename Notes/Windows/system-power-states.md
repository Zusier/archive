It may appear to the normal user as if it is either on or off, but there are many different classes of power states that are used to lower the power used when there are minimal need for it to be at full power.

## P-States
P-States, also known as Power Performance States scale the current frequency and voltage. The number of available P-States depends on the processor. The higher number the P-State is, the lower the frequency, voltage and power consumption will be.

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
S-States, or sleep states are OS controlled states mostly on Windows. You may recognize it as Sleep or Hibernate.
- S0: Similar to C0, this is when it is running at max performance.
- S1: Low latency wake state
  - Power is still provided to CPU and RAM
  - Instructions halted
  - System will need to compatible with ACPI to comply with these feautures
- S2: Similar to S1
  - CPU and System cache flushed
  - Power to processor is shutdown
- S3: Known as Sleep
  - All other contexts than RAM are cleared
  - System state is loaded into RAM
- S4: Known as hibernate
  - Power is cut off to all devices, including hard drives
  - System state is loaded to file on system hard drive before shutdown, known as hiberfil.sys
  - No power is used while in hibernation


## References
- [A Minimum Complete Tutorial of CPU Power Management](https://metebalci.com/blog/a-minimum-complete-tutorial-of-cpu-power-management-c-states-and-p-states)
- [Processor P-States and C-States](https://www.thomas-krenn.com/en/wiki/Processor_P-states_and_C-states)
- [C-States, P-States, and S-States](https://www.technikaffe.de/anleitung-32-c_states_p_states_s_states__energieverwaltung_erklaert)
- [Power Management States](https://www.techjunkie.com/power-management-states-s-state-p-state)
- [ACPI - Wikipedia](https://en.wikipedia.org/wiki/Advanced_Configuration_and_Power_Interface)
- [C-States](https://gist.github.com/wmealing/2dd2b543c4d3cff6cab7)
