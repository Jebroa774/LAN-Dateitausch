[CmdletBinding()]
param(
  [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$')]
  [string]$Repository = 'Jebroa774/LAN-Dateitausch',
  [string]$ArchivePath = ''
)
$ErrorActionPreference = 'Stop'

function Assert-LanPlainPath([string]$Path) {
  $item = Get-Item -LiteralPath $Path -Force
  while ($null -ne $item) {
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'GH_REPARSE: Verknuepfungen und Junctions werden nicht verfolgt.' }
    if ($item -is [IO.DirectoryInfo]) { $item = $item.Parent } else { $item = $item.Directory }
  }
}

function Copy-LanBoundedStream($Source, $Destination, [long]$ExpectedLength = -1, [long]$MaximumLength = 134217728) {
  $buffer = New-Object byte[] 65536
  $hash = [Security.Cryptography.SHA256]::Create()
  [long]$total = 0
  try {
    while ($true) {
      $limit = [int][Math]::Min($buffer.Length, $MaximumLength - $total + 1)
      $read = $Source.Read($buffer, 0, $limit)
      if ($read -eq 0) { break }
      $total += $read
      if ($total -gt $MaximumLength -or ($ExpectedLength -ge 0 -and $total -gt $ExpectedLength)) { throw 'GH_SIZE: Das Paket ueberschreitet die erlaubte Dateigroesse.' }
      [void]$hash.TransformBlock($buffer, 0, $read, $buffer, 0)
      if ($null -ne $Destination) { $Destination.Write($buffer, 0, $read) }
    }
    if ($ExpectedLength -ge 0 -and $total -ne $ExpectedLength) { throw 'GH_SIZE: Eine Paketdatei ist unvollstaendig.' }
    [void]$hash.TransformFinalBlock((New-Object byte[] 0), 0, 0)
    return [BitConverter]::ToString($hash.Hash).Replace('-', '').ToLowerInvariant()
  } finally { $hash.Dispose() }
}

function Test-LanPayloadName([string]$Name, [bool]$Directory = $false) {
  if (-not $Name -or $Name.Length -gt 240 -or $Name -match '[\\:\x00-\x1f\x7f<>"|?*]' -or $Name.StartsWith('/')) { return $false }
  $segments = $Name.Split('/')
  foreach ($segment in $segments) {
    if (-not $segment -or $segment -in @('.', '..') -or $segment -match '[. ]$' -or $segment -match '^(?i:CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|COM[1-9¹²³]|LPT[1-9¹²³])(?:\.|$)') { return $false }
  }
  if ($Directory) { return $Name -match '^(?:runtime|app(?:/(?:modules|static)(?:/[A-Za-z0-9_.-]+)*)?)$' }
  return $Name -match '^(?:LAN-Dateitausch\.(?:exe|ico)|desktop-launch\.mjs|Installieren\.ps1|Deinstallieren\.ps1|README\.txt|payload-manifest\.json|runtime/(?:node\.exe|node-LICENSE\.txt)|app/(?:server\.mjs|package\.json|modules/[A-Za-z0-9_./-]+\.(?:mjs|json)|static/[A-Za-z0-9_./-]+\.(?:html|js|css|svg|png|ico|woff2)))$'
}

# Kept as a function so tests can verify local dummy archives by dot-sourcing
# this file. The production entrypoint supplies the immutable release hash.
function Expand-VerifiedLanRelease([string]$ArchivePath, [string]$Destination, [string]$ExpectedSha256, [string]$ExpectedVersion = '1.2.0') {
  Add-Type -AssemblyName System.IO.Compression
  if ($ExpectedSha256 -cnotmatch '^[a-f0-9]{64}$') { throw 'GH_HASH: Ungueltige erwartete Pruefsumme.' }
  $ArchivePath = [IO.Path]::GetFullPath($ArchivePath)
  $Destination = [IO.Path]::GetFullPath($Destination).TrimEnd('\')
  Assert-LanPlainPath $ArchivePath
  $item = Get-Item -LiteralPath $ArchivePath -Force
  if ($item.PSIsContainer -or $item.Length -le 0 -or $item.Length -gt 134217728) { throw 'GH_SIZE: Das ZIP-Paket hat eine unzulaessige Groesse.' }
  if (Test-Path -LiteralPath $Destination) { throw 'GH_DESTINATION: Entpacken ist nur in einen neuen Ordner erlaubt.' }
  Assert-LanPlainPath ([IO.Path]::GetDirectoryName($Destination))
  $stream = $null; $zip = $null
  try {
    # FileShare.Read keeps another process from modifying or replacing this ZIP
    # between hash verification, inspection, and extraction on Windows.
    $stream = [IO.File]::Open($ArchivePath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    $actualHash = Copy-LanBoundedStream $stream $null $item.Length 134217728
    if ($actualHash -cne $ExpectedSha256) { throw 'GH_HASH: Die SHA256-Pruefsumme des Downloads stimmt nicht. Es wird nichts installiert.' }
    $stream.Position = 0
    $zip = New-Object IO.Compression.ZipArchive($stream, [IO.Compression.ZipArchiveMode]::Read, $true)
    if ($zip.Entries.Count -lt 1 -or $zip.Entries.Count -gt 1024) { throw 'GH_ENTRIES: Das ZIP enthaelt zu viele oder keine Eintraege.' }
    $names = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $files = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::OrdinalIgnoreCase)
    [long]$total = 0
    foreach ($entry in $zip.Entries) {
      $directory = $entry.FullName.EndsWith('/')
      $name = $(if ($directory) { $entry.FullName.Substring(0, $entry.FullName.Length - 1) } else { $entry.FullName })
      if (-not (Test-LanPayloadName $name $directory) -or -not $names.Add($name)) { throw 'GH_PATH: Ein ZIP-Pfad ist unzulaessig oder doppelt.' }
      [long]$attributes = $entry.ExternalAttributes
      $type = ($attributes -shr 16) -band 61440
      if (($attributes -band 1024) -ne 0 -or $type -notin @($(if ($directory) { 16384 } else { 32768 }), 0) -or (-not $directory -and ($attributes -band 16) -ne 0)) { throw 'GH_REPARSE: ZIP-Verknuepfungen oder besondere Dateitypen sind nicht erlaubt.' }
      if ($entry.Length -lt 0 -or $entry.Length -gt 134217728 -or ($directory -and $entry.Length -ne 0)) { throw 'GH_SIZE: Eine ZIP-Datei ist zu gross oder ungueltig.' }
      $total += $entry.Length
      if ($total -gt 536870912) { throw 'GH_SIZE: Das entpackte Paket ist zu gross.' }
      if (-not $directory) { $files.Add($name, $entry) }
    }
    if (-not $files.ContainsKey('payload-manifest.json') -or $files['payload-manifest.json'].Length -gt 131072) { throw 'GH_MANIFEST: Das Paketmanifest fehlt oder ist zu gross.' }
    $manifestBytes = New-Object IO.MemoryStream
    $archiveInputStream = $files['payload-manifest.json'].Open()
    try { $null = Copy-LanBoundedStream $archiveInputStream $manifestBytes $files['payload-manifest.json'].Length 131072; $manifest = (New-Object Text.UTF8Encoding($false, $true)).GetString($manifestBytes.ToArray()) | ConvertFrom-Json }
    finally { $archiveInputStream.Dispose(); $manifestBytes.Dispose() }
    if ($manifest.app_id -cne 'pc-assistent' -or $manifest.schema_version -ne 1 -or $manifest.version -isnot [string] -or $manifest.version -cne $ExpectedVersion -or $manifest.personal_data_included -isnot [bool] -or $manifest.personal_data_included -ne $false -or $manifest.apps -isnot [Array] -or $manifest.apps.Count -ne 1 -or $manifest.apps[0] -cne 'transfer' -or $manifest.files -isnot [Array] -or $manifest.files.Count -lt 1 -or $manifest.files.Count -gt 500) { throw 'GH_MANIFEST: Das Manifest beschreibt kein passendes eigenstaendiges LAN-Dateitausch-Paket.' }
    if ($manifest.components -and ($manifest.components.shared_runtime -ne $true -or @($manifest.components.launchers).Count -ne 1 -or $manifest.components.launchers[0] -cne 'transfer')) { throw 'GH_MANIFEST: Die Paketkomponenten passen nicht zur App.' }
    $listed = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($file in $manifest.files) {
      if ($file.path -isnot [string] -or -not (Test-LanPayloadName $file.path) -or $file.path -ieq 'payload-manifest.json' -or $listed.ContainsKey($file.path) -or -not $files.ContainsKey($file.path) -or ($file.bytes -isnot [int] -and $file.bytes -isnot [long]) -or $file.bytes -lt 0 -or $file.bytes -ne $files[$file.path].Length -or $file.sha256 -isnot [string] -or $file.sha256 -cnotmatch '^[a-f0-9]{64}$') { throw 'GH_MANIFEST: Eine Paketdatei ist nicht eindeutig oder ungueltig beschrieben.' }
      $archiveInputStream = $files[$file.path].Open()
      try { $hash = Copy-LanBoundedStream $archiveInputStream $null $file.bytes 134217728 } finally { $archiveInputStream.Dispose() }
      if ($hash -cne $file.sha256) { throw 'GH_PAYLOAD_HASH: Eine Paketdatei stimmt nicht mit ihrem SHA256-Manifest ueberein.' }
      $listed.Add($file.path, $file)
    }
    if ($files.Count -ne $listed.Count + 1) { throw 'GH_UNLISTED: Das ZIP enthaelt Dateien ausserhalb des Manifests.' }
    foreach ($required in @('LAN-Dateitausch.exe', 'LAN-Dateitausch.ico', 'desktop-launch.mjs', 'Installieren.ps1', 'Deinstallieren.ps1', 'README.txt', 'runtime/node.exe', 'runtime/node-LICENSE.txt', 'app/package.json', 'app/server.mjs', 'app/static/index.html', 'app/static/app.js', 'app/static/styles.css', 'app/modules/secure-transfer.mjs', 'app/modules/transfer-identity.mjs', 'app/modules/transfer-discovery.mjs', 'app/modules/transfer.mjs', 'app/modules/network.mjs', 'app/modules/network-vendors.json', 'app/modules/files.mjs', 'app/modules/windows-files.mjs')) {
      if (-not $listed.ContainsKey($required)) { throw 'GH_REQUIRED: Eine erforderliche Paketdatei fehlt.' }
    }
    # No output has been extracted before every payload hash has passed.
    New-Item -ItemType Directory -Path $Destination -ErrorAction Stop | Out-Null
    foreach ($entry in $zip.Entries) {
      $target = [IO.Path]::GetFullPath((Join-Path $Destination $entry.FullName))
      if (-not $target.StartsWith($Destination + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'GH_PATH: Ein ZIP-Pfad verlaesst den Paketordner.' }
      if ($entry.FullName.EndsWith('/')) { [void][IO.Directory]::CreateDirectory($target); continue }
      [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($target))
      Assert-LanPlainPath ([IO.Path]::GetDirectoryName($target))
      $archiveInputStream = $null; $archiveOutputStream = $null
      try {
        $archiveInputStream = $entry.Open(); $archiveOutputStream = [IO.File]::Open($target, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        $hash = Copy-LanBoundedStream $archiveInputStream $archiveOutputStream $entry.Length 134217728
        if ($entry.FullName -ine 'payload-manifest.json' -and $hash -cne $listed[$entry.FullName].sha256) { throw 'GH_PAYLOAD_HASH: Eine entpackte Datei ist nicht unveraendert.' }
      } finally { if ($archiveInputStream) { $archiveInputStream.Dispose() }; if ($archiveOutputStream) { $archiveOutputStream.Dispose() } }
    }
    return [pscustomobject]@{version=$ExpectedVersion;files=$listed.Count;bytes=$total}
  } finally { if ($zip) { $zip.Dispose() }; if ($stream) { $stream.Dispose() } }
}

function Get-LanGithubArchive([Uri]$Uri, [string]$Destination) {
  if ($Uri.Scheme -cne 'https' -or $Uri.Host -cne 'github.com' -or $Uri.UserInfo -or $Uri.Query -or $Uri.Fragment -or $Uri.AbsolutePath -notmatch '^/[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/releases/download/v1\.2\.0/LAN-Dateitausch-1\.2\.0-Windows\.zip$') { throw 'GH_URL: Nur die feste GitHub-Release-Adresse ist erlaubt.' }
  [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
  $current = $Uri
  for ($redirects = 0; $redirects -le 5; $redirects++) {
    if ($current.Scheme -cne 'https' -or $current.Port -ne 443 -or $current.UserInfo -or $current.Host -notin @('github.com', 'release-assets.githubusercontent.com', 'objects.githubusercontent.com', 'github-releases.githubusercontent.com')) { throw 'GH_URL: Eine unerwartete Downloadweiterleitung wurde abgewiesen.' }
    $request = [Net.HttpWebRequest]::Create($current)
    $request.AllowAutoRedirect = $false; $request.Timeout = 30000; $request.ReadWriteTimeout = 30000; $request.UserAgent = 'LAN-Dateitausch-Installer/1.2.0'
    $response = $null
    try {
      $response = $request.GetResponse()
      if ([int]$response.StatusCode -in @(301, 302, 303, 307, 308)) { $current = [Uri]::new($current, [string]$response.Headers['Location']); continue }
      if ([int]$response.StatusCode -ne 200 -or $response.ContentLength -gt 134217728) { throw 'GH_DOWNLOAD: Der Download ist nicht verfuegbar oder zu gross.' }
      $archiveInputStream = $response.GetResponseStream(); $archiveOutputStream = $null
      try { $archiveOutputStream = [IO.File]::Open($Destination, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None); $null = Copy-LanBoundedStream $archiveInputStream $archiveOutputStream $response.ContentLength 134217728 }
      finally { $archiveInputStream.Dispose(); if ($archiveOutputStream) { $archiveOutputStream.Dispose() } }
      return
    } finally { if ($response) { $response.Dispose() } }
  }
  throw 'GH_DOWNLOAD: Zu viele Downloadweiterleitungen.'
}

function Remove-LanInstallWorkspace([string]$Directory, [string]$Parent, [string]$Nonce) {
  $Directory = [IO.Path]::GetFullPath($Directory).TrimEnd('\'); $Parent = [IO.Path]::GetFullPath($Parent).TrimEnd('\')
  if ($Nonce -cnotmatch '^[a-f0-9]{32}$' -or -not ([IO.Path]::GetDirectoryName($Directory)).Equals($Parent, [StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($Directory) -cne ('lan-dateitausch-install-' + $Nonce)) { throw 'GH_CLEANUP: Der Tempordner konnte nicht als eigener Arbeitsordner bestaetigt werden.' }
  Assert-LanPlainPath $Directory
  $marker = Join-Path $Directory '.bootstrap-owner'
  Assert-LanPlainPath $marker
  if ([IO.File]::ReadAllText($marker) -cne $Nonce) { throw 'GH_CLEANUP: Die Tempordnerkennung stimmt nicht.' }
  $pendingDirectories = New-Object 'System.Collections.Generic.Stack[string]'
  $pendingDirectories.Push($Directory)
  while ($pendingDirectories.Count) {
    foreach ($item in Get-ChildItem -LiteralPath $pendingDirectories.Pop() -Force) {
      if (-not $item.FullName.StartsWith($Directory + '\', [StringComparison]::OrdinalIgnoreCase) -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'GH_CLEANUP: Der Tempordner enthaelt unerwartete Umleitungen.' }
      if ($item.PSIsContainer) { $pendingDirectories.Push($item.FullName) }
    }
  }
  # Only this freshly generated, marker-verified GUID workspace is recursive.
  Remove-Item -LiteralPath $Directory -Recurse -Force
}

function Install-LanGithubRelease([string]$Repository, [string]$ArchivePath = '') {
  if ($Repository -notmatch '^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$') { throw 'GH_URL: Ungueltiger GitHub-Repositoryname.' }
  $version = '1.2.0'
  $sha256 = '04757a56401dc51bf82ec0be8a71df28bfbd649a3307061b3bdae2954c3d976c'
  $asset = 'LAN-Dateitausch-1.2.0-Windows.zip'
  $tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
  Assert-LanPlainPath $tempRoot
  $nonce = [Guid]::NewGuid().ToString('N'); $workspace = Join-Path $tempRoot ('lan-dateitausch-install-' + $nonce)
  New-Item -ItemType Directory -Path $workspace -ErrorAction Stop | Out-Null
  [IO.File]::WriteAllText((Join-Path $workspace '.bootstrap-owner'), $nonce)
  try {
    $zipPath = Join-Path $workspace $asset
    if ($ArchivePath) {
      Assert-LanPlainPath $ArchivePath
      $local = Get-Item -LiteralPath $ArchivePath -Force
      if ($local.PSIsContainer -or $local.Length -gt 134217728) { throw 'GH_SIZE: Das lokale ZIP-Paket ist zu gross.' }
      [IO.File]::Copy($local.FullName, $zipPath, $false)
    } else {
      Write-Host 'LAN-Dateitausch 1.2.0 wird von GitHub heruntergeladen ...'
      Get-LanGithubArchive ([Uri]('https://github.com/' + $Repository + '/releases/download/v' + $version + '/' + $asset)) $zipPath
    }
    $payload = Join-Path $workspace 'payload'
    $null = Expand-VerifiedLanRelease $zipPath $payload $sha256 $version
    Write-Host 'Paket und alle Dateien sind geprueft. Installation fuer den aktuellen Benutzer ...'
    $powershell = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $installer = Join-Path $payload 'Installieren.ps1'
    $process = Start-Process -FilePath $powershell -ArgumentList @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', ('"' + $installer + '"'), '-SourceRoot', ('"' + $payload + '"'), '-LaunchApp', 'transfer') -WindowStyle Hidden -PassThru
    try { $process.WaitForExit(); $process.Refresh(); if ($process.ExitCode -ne 0) { throw 'GH_INSTALL: Installation nicht abgeschlossen. Aktive Dateiuebertragungen oder Dateivorgaenge zuerst beenden und erneut versuchen.' } }
    finally { $process.Dispose() }
    Write-Host 'LAN-Dateitausch 1.2.0 ist installiert. Der Appstart wurde angefordert.'
  } finally {
    try { Remove-LanInstallWorkspace $workspace $tempRoot $nonce } catch { Write-Warning 'Der eigene Installations-Tempordner konnte nicht sicher aufgeraeumt werden und wurde beibehalten.' }
  }
}

# Dot-sourcing loads verification helpers only; it never downloads or installs.
if ($MyInvocation.InvocationName -ne '.') { Install-LanGithubRelease $Repository $ArchivePath }
