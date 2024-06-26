@REM Insert all system related commands in this file
@REM Note that this script runs during the specialize section of OOBE
@REM This means that it runs on machine level, before any user is created

@REM make sure we don't have hibernate enabled
powercfg /H off

@REM Disable sleep
powercfg /X -standby-timeout-ac 0
powercfg /X -monitor-timeout-ac 0

@REM Disable UAC for post install user scripts
reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 0 /f 