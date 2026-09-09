[CmdletBinding()]
param([switch]$Apply)
$ErrorActionPreference = 'Stop'
$dockerParent = [IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA 'Docker'))
$runtimePath = [IO.Path]::GetFullPath((Join-Path $dockerParent 'run'))
$backupPath = [IO.Path]::GetFullPath((Join-Path $dockerParent ('run.evidscope-backup-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))))
$expectedPrefix = $dockerParent + [IO.Path]::DirectorySeparatorChar
if (-not $runtimePath.StartsWith($expectedPrefix, [StringComparison]::OrdinalIgnoreCase) -or -not $backupPath.StartsWith($expectedPrefix, [StringComparison]::OrdinalIgnoreCase)) { throw 'Resolved runtime paths must remain within the explicitly named Docker parent.' }
$source = Get-Item -LiteralPath $runtimePath -Force
if (-not $source.PSIsContainer -or ($source.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Runtime must be an ordinary directory, never a directory reparse point.' }
$children = @(Get-ChildItem -LiteralPath $runtimePath -Force)
$expected = @('dockerInference', 'dockerEthernetVfkit', 'userAnalyticsOtlpHttp.sock')
foreach ($child in $children) {
    if ($child.PSIsContainer -or $child.Length -ne 0 -or $child.Name -notin $expected -or -not ($child.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Runtime contents changed or include non-socket data; stop and review.' }
}
$processes = @(Get-Process -Name 'Docker Desktop','com.docker.backend' -ErrorAction SilentlyContinue)
if ($processes.Count -ne 0) { throw 'Docker is running; this script does not stop it.' }
$plan = [ordered]@{ source = $runtimePath; backup = $backupPath; socketNames = @($children.Name); action = 'rename runtime directory, preserve backup, start installed Docker Desktop hidden'; applied = $false }
if (-not $Apply) { $plan | ConvertTo-Json -Depth 4; exit 0 }
if (Test-Path -LiteralPath $backupPath) { throw 'Backup already exists; do not overwrite.' }
$desktopExe = Join-Path $env:ProgramFiles 'Docker\Docker\Docker Desktop.exe'
if (-not (Test-Path -LiteralPath $desktopExe -PathType Leaf)) { throw 'Expected installed Docker Desktop executable is unavailable.' }
# Paths were resolved and checked above. This same-shell rename preserves every entry.
Move-Item -LiteralPath $runtimePath -Destination $backupPath
Start-Process -FilePath $desktopExe -WindowStyle Hidden
$plan.applied = $true
$plan | ConvertTo-Json -Depth 4
Write-Output 'Check docker version separately. The previous runtime directory is retained; no VM, volume, container or context was deleted.'
