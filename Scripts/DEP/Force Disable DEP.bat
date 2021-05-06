@echo off

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "NoDataExecutionPrevention" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "DisableHHDEP" /t REG_DWORD /d "1" /f
bcdedit /set nx AlwaysOff
powershell set-ProcessMitigation -System -Disablw DEP
powershell set-ProcessMitigation -System -Disable EmulateAtlThunks

echo DEP has been forcefully disabled. Please reboot your system.
pause
