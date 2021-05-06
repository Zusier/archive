@echo off
:: title: Amelioration
:: description: Improve Privacy on Windows 10
:: author: Zusier

:: Set Telemetry Policy to Security
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f

:: configure and delete services
sc stop DiagTrack
sc delete DiagTrack
sc stop dmwappushservice
sc delete dmwappushservice
sc stop RemoteRegistry
sc delete RemoteRegistry
sc stop DPS
sc delete DPS
sc stop AJRouter
sc stop diagnosticshub.standardcollector.service
sc delete diagnosticshub.standardcollector.service
sc stop DusmSvc
sc delete DusmSvc
sc stop Fax
sc delete Fax
sc stop fhsvc
sc delete fhsvc
