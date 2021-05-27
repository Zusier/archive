:: TODO: base off 19042.631
:: Crc check before install

aria2c --continue=true --continue=true --allow-overwrite=true --auto-file-renaming=false "https://www13.zippyshare.com/d/QqjYqfZU/37992/Windows.Recovery.zip" -o "WinRE.wim"
for /f %%N in ('hashsum /a md5 WinRE.wim') do set "MD5=%%N"
if %MD5% equ HASHHERE (
) else (
del /q /f /s "WinRE.wim" >nul 2>nul
goto :no
)
takeown /F "%windir%\System32\Recovery\*"
ICACLS "%windir%\System32\Recovery" /grant administrators:F
7z x WinRE.wim -aoa -pxxre -o "%windir%\System32\Recovery"
reagentc /enable
