#This script will disable users not listed in the packet, create new users, and change passwords for all accounts listed in the packet


#List of users
$users = @("zhukov", "gusev", "makarov", "festisov", "kasatonov", "krutov", "lebedev", "vasiliev", "tikhonov", "kulagin", "brezhnev", "tretiak", "larionov")
$new_users = ("kaspirov", "gagarin", "korolev", "tupolev", "sukhoi", "yakovlev", "mig", "su", "tu", "il")

#Create new users
ForEach-Object {
    foreach ($user in $new_users) {
        if (-not (Get-LocalUser -Name $user -ErrorAction SilentlyContinue)) {
            New-LocalUser -Name $user -Password (ConvertTo-SecureString "SuperSecure12345!" -AsPlainText -Force) -FullName $user -Description "Created by script"
            Write-Host "Created user $user"
        } else {
            Write-Host "User $user already exists"
        }
    }
}


#Change passwords
$NewPassword = ConvertTo-SecureString "SuperSecure12345!" -AsPlainText -Force

Get-LocalUser | ForEach-Object {
    if ($_.Enabled -and $_.Name -in $users -or $_.Name -in $new_users) {
        
        Set-LocalUser -Name $_.Name -Password $NewPassword
        
        Write-Host "Updated password for $($_.Name)"
    }
}


#Disable users not in the list
Get-LocalUser | ForEach-Object {
    if ($_.Name -notin @("zhukov", "gusev", "makarov", "festisov", "kasatonov", "krutov", "lebedev", "vasiliev", "tikhonov", "kulagin", "brezhnev", "tretiak", "larionov", "kaspirov", "gagarin", "korolev", "tupolev", "sukhoi", "yakovlev", "mig", "su", "tu", "il", "grayteam", "greyteam")) {
        Disable-LocalUser -Name $_.Name
        Write-Host "Disabled user $($_.Name)"
    }
}