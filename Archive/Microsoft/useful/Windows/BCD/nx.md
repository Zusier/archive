# Boot Option: NX (DEP)
The nx boot option specifies the policy for Data Execution Prevention. ([What is DEP?](#data-execution-prevention))

## Syntax
To set a policy for nx, type:
```bcdedit /set nx value```

## Behavior
The nx option governs how Windows defends against attempts to execute data. It depends on a relatively recent CPU feature which Intel names Execute Disable and Microsoft calls Data Execution Prevention (DEP). Support for DEP is established by executing the [cpuid](https://www.geoffchappell.com/studies/windows/km/cpu/cpuid/index.htm) instruction with 0x80000001 in eax and testing for the Execute Disable bit (0x00100000) in the feature flags that are returned in edx.

DEP requires the use of 64-bit page table entries as supported by the Physical Address Extension (PAE) feature. Support for PAE is established by executing the [cpuid instruction with 1 in eax](https://www.geoffchappell.com/studies/windows/km/cpu/cpuid/00000001h/index.htm) and testing for the PAE bit (0x40) in the [feature flags](https://www.geoffchappell.com/studies/windows/km/cpu/cpuid/00000001h/edx.htm) that are returned in edx. If PAE and DEP are both supported, then the loader may enable PAE in order to enable DEP, even if this means overriding the [pae](https://www.geoffchappell.com/notes/windows/boot/bcd/osloader/pae.htm) option.

The nx option can be changed at the Edit Boot Options Menu except in one case. If DEP is supported but disabled (by setting nx to AlwaysOff), then the loader may have disabled PAE, depending mostly on the pae option. If so, changing nx at the Edit Boot Options Menu is too late to enable PAE and is therefore also too late to enable DEP.

The nx option passes to the kernel as the corresponding command-line switch. Its treatment in the kernel is presently beyond the scope of this note.

# Data Execution Prevention
DEP is a memory protection that was introduced in Windows XP. In simple terms, it prevents malicous code from running in certain segments of memory known as pages.
