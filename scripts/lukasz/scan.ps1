#Scan connections
$connections = Get-NetTCPConnection -State Established
$connections | ForEach-Object {
    $remoteAddress = $_.RemoteAddress
    $remotePort = $_.RemotePort
    $localAddress = $_.LocalAddress
    $localPort = $_.LocalPort
    $processId = $_.OwningProcess

    # Get process name
    $processName = (Get-Process -Id $processId -ErrorAction SilentlyContinue).Name

    Write-Host "Connection from $remoteAddress:$remotePort to $localAddress:$localPort (Process: $processName)"
}

