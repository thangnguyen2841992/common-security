[CmdletBinding()]
param([ValidateSet('oauth2','staff','nihongo-user')][string[]]$Services = @('oauth2','staff','nihongo-user'))
$ErrorActionPreference = 'Stop'
$runtimeRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '../..')).Path
$runtimeLogs = Join-Path $runtimeRoot '.local/startup-check'
[System.IO.Directory]::CreateDirectory($runtimeLogs) | Out-Null
$javaExecutable = Join-Path $env:ProgramFiles 'Java/jdk-17/bin/java.exe'
if (!(Test-Path -LiteralPath $javaExecutable)) { $javaExecutable = (Get-Command java -ErrorAction Stop).Source }
$runtimeDefinitions = @{
  'oauth2' = @{ Jar = 'user-0.0.1-SNAPSHOT.jar'; Port = 8081 }
  'staff' = @{ Jar = 'staff-0.0.1-SNAPSHOT.jar'; Port = 8085 }
  'nihongo-user' = @{ Jar = 'nihongo-user-0.0.1-SNAPSHOT.jar'; Port = 8086 }
}
Add-Type -AssemblyName System.IO.Compression.FileSystem
$launchedServices = @()
foreach ($runtimeService in $Services) {
  $definition = $runtimeDefinitions[$runtimeService]
  $tcp = [System.Net.Sockets.TcpClient]::new()
  $occupied = $false
  try { $tcp.Connect('127.0.0.1', $definition.Port); $occupied = $true } catch { } finally { $tcp.Dispose() }
  if ($occupied) { Write-Output "$runtimeService : port $($definition.Port) already listening; no duplicate process started."; continue }
  $jarFile = Join-Path $runtimeRoot ($runtimeService + '/target/' + $definition.Jar)
  if (!(Test-Path -LiteralPath $jarFile)) { throw "Build $runtimeService before starting it." }
  $archive = [System.IO.Compression.ZipFile]::OpenRead($jarFile)
  try {
    if (!($archive.Entries | Where-Object { $_.FullName -match '^BOOT-INF/lib/mariadb-java-client-[^/]+\.jar$' })) { throw "MariaDB driver is absent from $runtimeService JAR. Rebuild it first." }
  } finally { $archive.Dispose() }
  # Verify the existing schema during this recovery run; do not apply automatic database changes.
  $runtimeProcess = Start-Process -FilePath $javaExecutable -ArgumentList @('-jar', ('"' + $jarFile + '"'), '--spring.jpa.hibernate.ddl-auto=validate') -WorkingDirectory $runtimeRoot -WindowStyle Hidden -RedirectStandardOutput (Join-Path $runtimeLogs ($runtimeService + '-jar-runtime.log')) -RedirectStandardError (Join-Path $runtimeLogs ($runtimeService + '-jar-runtime-errors.log')) -PassThru
  $launchedServices += [pscustomobject]@{ service = $runtimeService; pid = $runtimeProcess.Id; port = $definition.Port; jar = $jarFile }
  Write-Output "$runtimeService : started PID $($runtimeProcess.Id), port $($definition.Port)."
}
if ($launchedServices.Count) { $launchedServices | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $runtimeLogs 'jar-runtime-services.json') -Encoding utf8 }
