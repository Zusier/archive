@echo off

bcdedit /set nx AlwaysOff
powershell set-ProcessMitigation -System -Disablw DEP
powershell set-ProcessMitigation -System -Disable EmulateAtlThunks

echo DEP has been forcefully disabled. Please reboot your system.
pause
