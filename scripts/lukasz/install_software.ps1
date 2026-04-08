#Install Sysinternals Suite
$sysinternalsUrl = "https://download.sysinternals.com/files/SysinternalsSuite.zip"
$sysinternalsZipPath = "$env:TEMP\SysinternalsSuite.zip"
Invoke-WebRequest -Uri $sysinternalsUrl -OutFile $sysinternalsZipPath
$sysinternalsExtractPath = "$env:ProgramFiles\SysinternalsSuite"
Expand-Archive -Path $sysinternalsZipPath -DestinationPath $sysinternalsExtractPath

#Install Nessus
# $nessusUrl = "https://www.tenable.com/downloads/api/v1/public/pages/nessus/downloads/13224/download?i_agree_to_tenable_license_agreement=true"
# $nessusInstallerPath = "$env:TEMP\nessus_installer.exe"
# Invoke-WebRequest -Uri $nessusUrl -OutFile $nessusInstallerPath
# Start-Process -FilePath $nessusInstallerPath -ArgumentList "/S" -Wait


