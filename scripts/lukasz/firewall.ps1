#Setup firewall rules


# Backup current firewall rules
$backupFile = "C:\fw-backup.wfw"
netsh advfirewall export $backupFile
Write-Host "Current firewall configuration backed up to $backupFile"

#Deny All
netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound


#Allow RDP
netsh advfirewall firewall add rule name="Allow RDP" protocol=TCP dir=in localport=3389 action=allow
#Allow HTTP
netsh advfirewall firewall add rule name="Allow HTTP" protocol=TCP dir=in localport=80 action=allow
#Allow HTTPS
netsh advfirewall firewall add rule name="Allow HTTPS" protocol=TCP dir=in localport=443 action=allow
#Allow DNS
netsh advfirewall firewall add rule name="Allow DNS" protocol=UDP dir=in localport=53 action=allow



Write-Host "New firewall rules applied."

# Confirmation logic
$confirmed = $false
$endTime = (Get-Date).AddSeconds(10)

Write-Host "Type 'yes' within 10 seconds to keep these rules..."

while ((Get-Date) -lt $endTime) {
    if ($Host.UI.RawUI.KeyAvailable) {
        $input = Read-Host
        if ($input -eq "yes") {
            $confirmed = $true
        }
        break
    }
    Start-Sleep -Milliseconds 200
}