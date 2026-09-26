# Install SQL Server 2019 (default instance MSSQLSERVER) on a GitHub-hosted
# Windows runner for the integrated-auth tests: TCP on 1433, named pipes, and
# SQL Browser (for the named-instance tests), with the runner's Administrators
# group as sysadmin so `IntegratedSecurity=true` logs in.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

choco feature disable --name="'exitOnRebootDetected'"
choco install sql-server-2019 -y --no-progress `
  --params="'/IgnorePendingReboot /INSTANCENAME=MSSQLSERVER /TCPENABLED=1 /NPENABLED=1 /SQLSYSADMINACCOUNTS=BUILTIN\Administrators /BROWSERSVCSTARTUPTYPE=Manual'"
if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 3010) {
  throw "choco install sql-server-2019 failed with exit code $LASTEXITCODE"
}

# Belt and braces: make sure TCP (static 1433) and named pipes are enabled even
# if setup ignored the protocol switches.
$inst = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL').MSSQLSERVER
$net = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$inst\MSSQLServer\SuperSocketNetLib"
Set-ItemProperty -Path "$net\Tcp" -Name Enabled -Value 1
Set-ItemProperty -Path "$net\Tcp\IPAll" -Name TcpPort -Value '1433'
Set-ItemProperty -Path "$net\Tcp\IPAll" -Name TcpDynamicPorts -Value ''
Set-ItemProperty -Path "$net\Np" -Name Enabled -Value 1

# `(local)` alias over TCP, as the previous CI did.
New-Item -Path 'HKLM:\SOFTWARE\Microsoft\MSSQLServer\Client' -Name ConnectTo -Force | Out-Null
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\MSSQLServer\Client\ConnectTo' `
  -Name '(local)' -Value "DBMSSOCN,$env:COMPUTERNAME\MSSQLSERVER"

Set-Service SQLBrowser -StartupType Manual
Start-Service SQLBrowser
Restart-Service MSSQLSERVER -Force

# Readiness: an authenticated (integrated) `SELECT 1` over TCP.
$cs = 'Server=tcp:127.0.0.1,1433;Integrated Security=SSPI;TrustServerCertificate=True;Connect Timeout=5'
for ($i = 0; $i -lt 60; $i++) {
  try {
    $conn = New-Object System.Data.SqlClient.SqlConnection $cs
    $conn.Open()
    $cmd = $conn.CreateCommand()
    $cmd.CommandText = 'SELECT @@VERSION'
    Write-Host "SQL Server ready: $($cmd.ExecuteScalar())"
    $conn.Close()
    exit 0
  } catch {
    Start-Sleep -Seconds 3
  }
}
throw 'SQL Server did not accept an integrated-auth login in time'
