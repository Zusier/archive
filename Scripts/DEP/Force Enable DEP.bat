@echo off

bcdedit /set nx AlwaysOn
powershell set-ProcessMitigation -System -Enable DEP
powershell set-ProcessMitigation -System -Enable EmulateAtlThunks

echo DEP has been forcefully enabled. Please reboot your system.
pause
