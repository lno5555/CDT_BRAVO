# ============================================================
# Firewall Configuration Script - Domain Controller
# - Backs up current rules
# - Blocks all inbound, allows outbound
# - Allows all necessary DC ports
# - Option to flush/reset rules
# - Rolls back if not confirmed within 10 seconds
# ============================================================


# ---- Define Backup Path ----
$backupFile = "C:\fw-backup.wfw"


# ---- Flush / Reset Option ----
Write-Host "========================================"
Write-Host "  Firewall Management Menu"
Write-Host "========================================"
Write-Host "  [1] Apply DC firewall rules"
Write-Host "  [2] Flush all firewall rules and reset to default"
Write-Host "  [3] Restore from last backup"
Write-Host "========================================"
$menuChoice = Read-Host "Select an option (1/2/3)"

if ($menuChoice -eq "2") {
    Write-Host "Flushing all firewall rules and resetting to default..."
    netsh advfirewall reset
    Write-Host "Firewall reset to Windows defaults."
    exit
}

if ($menuChoice -eq "3") {
    if (Test-Path $backupFile) {
        netsh advfirewall import $backupFile
        Write-Host "Firewall restored from: $backupFile"
    } else {
        Write-Host "No backup file found at $backupFile"
    }
    exit
}


# ---- Backup Current Firewall Rules ----
netsh advfirewall export $backupFile
Write-Host "Firewall configuration backed up to: $backupFile"


# ---- Block All Inbound, Allow Outbound ----
netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound
Write-Host "Default policy set: block inbound, allow outbound"


# ---- Allow Inbound Rules ----

# RDP
netsh advfirewall firewall add rule name="Allow RDP" protocol=TCP dir=in localport=3389 action=allow
Write-Host "Rule added: Allow RDP (TCP 3389)"

# HTTP/HTTPS
netsh advfirewall firewall add rule name="Allow HTTP" protocol=TCP dir=in localport=80 action=allow
Write-Host "Rule added: Allow HTTP (TCP 80)"

netsh advfirewall firewall add rule name="Allow HTTPS" protocol=TCP dir=in localport=443 action=allow
Write-Host "Rule added: Allow HTTPS (TCP 443)"

# DNS
netsh advfirewall firewall add rule name="Allow DNS UDP" protocol=UDP dir=in localport=53 action=allow
Write-Host "Rule added: Allow DNS (UDP 53)"

netsh advfirewall firewall add rule name="Allow DNS TCP" protocol=TCP dir=in localport=53 action=allow
Write-Host "Rule added: Allow DNS (TCP 53)"

# LDAP / LDAPS
netsh advfirewall firewall add rule name="Allow LDAP" protocol=TCP dir=in localport=389 action=allow
Write-Host "Rule added: Allow LDAP (TCP 389)"

netsh advfirewall firewall add rule name="Allow LDAP UDP" protocol=UDP dir=in localport=389 action=allow
Write-Host "Rule added: Allow LDAP (UDP 389)"

netsh advfirewall firewall add rule name="Allow LDAPS" protocol=TCP dir=in localport=636 action=allow
Write-Host "Rule added: Allow LDAPS (TCP 636)"

# Kerberos
netsh advfirewall firewall add rule name="Allow Kerberos TCP" protocol=TCP dir=in localport=88 action=allow
Write-Host "Rule added: Allow Kerberos (TCP 88)"

netsh advfirewall firewall add rule name="Allow Kerberos UDP" protocol=UDP dir=in localport=88 action=allow
Write-Host "Rule added: Allow Kerberos (UDP 88)"

# SMB
netsh advfirewall firewall add rule name="Allow SMB" protocol=TCP dir=in localport=445 action=allow
Write-Host "Rule added: Allow SMB (TCP 445)"

# NetBIOS
netsh advfirewall firewall add rule name="Allow NetBIOS Name Service" protocol=UDP dir=in localport=137 action=allow
Write-Host "Rule added: Allow NetBIOS Name Service (UDP 137)"

netsh advfirewall firewall add rule name="Allow NetBIOS Datagram" protocol=UDP dir=in localport=138 action=allow
Write-Host "Rule added: Allow NetBIOS Datagram (UDP 138)"

netsh advfirewall firewall add rule name="Allow NetBIOS Session" protocol=TCP dir=in localport=139 action=allow
Write-Host "Rule added: Allow NetBIOS Session (TCP 139)"

# RPC
netsh advfirewall firewall add rule name="Allow RPC Endpoint Mapper" protocol=TCP dir=in localport=135 action=allow
Write-Host "Rule added: Allow RPC Endpoint Mapper (TCP 135)"

netsh advfirewall firewall add rule name="Allow RPC Dynamic Ports" protocol=TCP dir=in localport="49152-65535" action=allow
Write-Host "Rule added: Allow RPC Dynamic Ports (TCP 49152-65535)"

# NTP
netsh advfirewall firewall add rule name="Allow NTP" protocol=UDP dir=in localport=123 action=allow
Write-Host "Rule added: Allow NTP (UDP 123)"

# Global Catalog
netsh advfirewall firewall add rule name="Allow Global Catalog" protocol=TCP dir=in localport=3268 action=allow
Write-Host "Rule added: Allow Global Catalog (TCP 3268)"

netsh advfirewall firewall add rule name="Allow Global Catalog SSL" protocol=TCP dir=in localport=3269 action=allow
Write-Host "Rule added: Allow Global Catalog SSL (TCP 3269)"

# DFSR - Replication
netsh advfirewall firewall add rule name="Allow DFSR" protocol=TCP dir=in localport=5722 action=allow
Write-Host "Rule added: Allow DFSR Replication (TCP 5722)"

# ICMP - Ping
netsh advfirewall firewall add rule name="Allow ICMP" protocol=icmpv4 dir=in action=allow
Write-Host "Rule added: Allow ICMP (Ping)"

Write-Host "`nAll DC firewall rules applied."


# ---- Confirmation / Rollback Logic ----
$confirmed = $false
$endTime = (Get-Date).AddSeconds(10)

Write-Host "`nType 'yes' within 10 seconds to keep these rules, otherwise they will be rolled back..."

while ((Get-Date) -lt $endTime) {
    if ($Host.UI.RawUI.KeyAvailable) {
        $response = Read-Host
        if ($response -eq "yes") {
            $confirmed = $true
        }
        break
    }
    Start-Sleep -Milliseconds 200
}

if ($confirmed) {
    Write-Host "Rules confirmed and kept."
} else {
    Write-Host "Not confirmed — rolling back to backup..."
    netsh advfirewall import $backupFile
    Write-Host "Firewall restored from: $backupFile"
}