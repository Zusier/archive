@echo off

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "NoDataExecutionPrevention" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "DisableHHDEP" /t REG_DWORD /d 0 /f
bcdedit /set nx AlwaysOn
powershell set-ProcessMitigation -System -Enable DEP
powershell set-ProcessMitigation -System -Enable EmulateAtlThunks

echo DEP has been forcefully enabled. Please reboot your system.
pause
