## Place post-install scripts here. This is useful for calling webhook or doing other
## automation that is not critical to be placed in the post-install script. This is 
## also a good place to reboot/shutdown for completing post-install script.

Write-Host "Post-install complete." >> "$env:ProgramData\appinstall.log"

# Enable UAC in the next reboot
& reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 1 /f

# Reboot system
shutdown /r /t 0
