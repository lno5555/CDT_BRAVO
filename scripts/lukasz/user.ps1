# ============================================================
# User Management & Password Rotation Script
# - Disables users not in the approved list
# - Creates new users
# - Changes passwords for all listed accounts
# - Rotates passwords every 10 minutes
# ============================================================

# ---- Self-Register as Scheduled Task ----
$taskName = "UserRotationService"
$scriptPath = $MyInvocation.MyCommand.Path

if (-not (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue)) {
    $action  = New-ScheduledTaskAction -Execute "powershell.exe" `
                   -Argument "-NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`""

    $trigger = New-ScheduledTaskTrigger -AtStartup

    $settings = New-ScheduledTaskSettingsSet `
                   -ExecutionTimeLimit ([TimeSpan]::Zero) `
                   -RestartCount 3 `
                   -RestartInterval (New-TimeSpan -Minutes 1)

    Register-ScheduledTask -TaskName $taskName `
        -Action $action `
        -Trigger $trigger `
        -RunLevel Highest `
        -Settings $settings `
        -User "SYSTEM"

    Write-Host "Registered as scheduled task: $taskName"
} else {
    Write-Host "Scheduled task already exists: $taskName"
}



# ---- User Lists ----
$users     = @("zhukov", "gusev", "makarov", "festisov", "kasatonov", "krutov",
               "lebedev", "vasiliev", "tikhonov", "kulagin", "brezhnev", "tretiak", "larionov")
$new_users = @("kaspirov", "gagarin", "korolev", "tupolev", "sukhoi",
               "yakovlev", "mig", "su", "tu", "il")
$allUsers  = $users + $new_users
$exemptUsers = $allUsers + @("grayteam", "greyteam", "Administrator", "scoring")


# ---- Password Rotation List ----
$passwordList = @(
    "Volkov@Thunder91",
    "Bering#Frost47",
    "Kremlin!Watch33",
    "Sputnik@Delta82",
    "Taiga#Storm56",
    "Polar!Vortex19",
    "Siberia@Hawk74",
    "Tundra#Blaze38",
    "Arctic!Wolf65",
    "Kazakh@Eagle21"
)
$passwordIndex = 0


# ---- Create New Users ----
$initialPassword = ConvertTo-SecureString $passwordList[0] -AsPlainText -Force

foreach ($user in $new_users) {
    if (-not (Get-LocalUser -Name $user -ErrorAction SilentlyContinue)) {
        New-LocalUser -Name $user -Password $initialPassword -FullName $user -Description "Created by script"
        Write-Host "Created user: $user"
    } else {
        Write-Host "User already exists: $user"
    }
}


# ---- Disable Unlisted Users ----
Get-LocalUser | ForEach-Object {
    if ($_.Name -notin $exemptUsers) {
        Disable-LocalUser -Name $_.Name
        Write-Host "Disabled user: $($_.Name)"
    }
}


# ---- Set Initial Passwords ----
Get-LocalUser | ForEach-Object {
    if ($_.Enabled -and ($_.Name -in $allUsers)) {
        Set-LocalUser -Name $_.Name -Password $initialPassword
        Write-Host "Set initial password for: $($_.Name)"
    }
}


# ---- Password Rotation Loop (every 10 minutes) ----
Write-Host "Starting password rotation loop..."

while ($true) {
    Start-Sleep -Seconds 600

    $passwordIndex = ($passwordIndex + 1) % $passwordList.Count
    $currentPassword = ConvertTo-SecureString $passwordList[$passwordIndex] -AsPlainText -Force

    Write-Host "`n[$(Get-Date)] Rotating to password index $passwordIndex"

    Get-LocalUser | ForEach-Object {
        if ($_.Enabled -and ($_.Name -in $allUsers)) {
            Set-LocalUser -Name $_.Name -Password $currentPassword
            Write-Host "  Rotated password for: $($_.Name)"
        }
    }
}