#Make backups of DNS configuration and user accounts

# Backup DNS configuration
$dnsBackupFile = "C:\dns-backup.txt"
Get-DnsServerZone | ForEach-Object {
    $zoneName = $_.ZoneName
    Get-DnsServerResourceRecord -ZoneName $zoneName | Export-Csv -Path "C:\dns-backup-$zoneName.csv" -NoTypeInformation
}
Write-Host "DNS configuration backed up to C:\dns-backup.txt and individual zone files."

# Backup user accounts
$userBackupFile = "C:\user-backup.csv"
Get-LocalUser | Export-Csv -Path $userBackupFile -NoTypeInformation
Write-Host "User accounts backed up to $userBackupFile"
