param(
  [Parameter(Mandatory=$true)][string]$RepoRoot,
  [switch]$Apply,
  [switch]$Force
)
$ErrorActionPreference = 'Stop'
$source = Split-Path -Parent $MyInvocation.MyCommand.Path
$repo = [System.IO.Path]::GetFullPath($RepoRoot)
if (-not (Test-Path -LiteralPath (Join-Path $repo '.git'))) { throw 'RepoRoot must be a Git worktree root.' }
$copies = @(
  @{ From = (Join-Path $source 'codex\config.toml'); To = (Join-Path $repo '.codex\config.toml') },
  @{ From = (Join-Path $source 'codex\agents'); To = (Join-Path $repo '.codex\agents') },
  @{ From = (Join-Path $source 'claude\agents'); To = (Join-Path $repo '.claude\agents') }
)
foreach ($copy in $copies) {
  Write-Host "$($copy.From) -> $($copy.To)"
  if (-not $Apply) { continue }
  if ((Test-Path -LiteralPath $copy.To) -and -not $Force) { throw "Target exists; inspect it and rerun with -Force only if replacement is intended: $($copy.To)" }
  if (Test-Path -LiteralPath $copy.From -PathType Container) {
    New-Item -ItemType Directory -Force -Path $copy.To | Out-Null
    Get-ChildItem -LiteralPath $copy.From -File | ForEach-Object { Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $copy.To $_.Name) -Force:$Force }
  } else {
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $copy.To) | Out-Null
    Copy-Item -LiteralPath $copy.From -Destination $copy.To -Force:$Force
  }
}
if (-not $Apply) { Write-Host 'Dry run only. Add -Apply after reviewing the exact repository-local targets.' }
