$connections = Get-NetTCPConnection | Select-Object -ExpandProperty RemoteAddress
$uniqueIPs = $connections | Where-Object { $_ -match "\d+\.\d+\.\d+\.\d+" } | Sort-Object -Unique
$uniqueIPs | ForEach-Object { Write-Output $_ }
