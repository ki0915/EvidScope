$ErrorActionPreference = 'Stop'

# Keep the automatic governance probe and its policy unchanged. This receipt is
# explicitly for one user-requested, bounded public-QA training run.
$qaHost = (& (Join-Path $PSScriptRoot 'training-host-probe.ps1') | ConvertFrom-Json)
if ($qaHost.source -ne 'trusted_windows_host_probe') { throw 'underlying_host_probe_invalid' }
$qaOs = Get-CimInstance Win32_OperatingSystem
$qaMemory = Get-CimInstance Win32_PerfFormattedData_PerfOS_Memory
if ($null -eq $qaOs.FreePhysicalMemory -or $null -eq $qaMemory.CommittedBytes -or $null -eq $qaMemory.CommitLimit -or [double]$qaMemory.CommitLimit -le 0 -or $null -eq $qaMemory.PagesInputPersec) { throw 'windows_commit_counters_unavailable' }
$qaCommitted = [double]$qaMemory.CommittedBytes
$qaCommitLimit = [double]$qaMemory.CommitLimit
if ($qaCommitted -lt 0 -or $qaCommitted -gt $qaCommitLimit) { throw 'windows_commit_counters_invalid' }
[pscustomobject]@{
  schemaVersion = 1
  source = 'public_qa_manual_host_probe'
  observedAt = [DateTimeOffset]::Now.ToString('o')
  host = $qaHost
  windows = [pscustomobject]@{
    physicalFreeGiB = [math]::Round([double]$qaOs.FreePhysicalMemory / 1MB, 3)
    commitFreeGiB = [math]::Round(($qaCommitLimit - $qaCommitted) / 1GB, 3)
    commitUsedPercent = [math]::Round(100 * $qaCommitted / $qaCommitLimit, 3)
    pagesInputPerSecond = [double]$qaMemory.PagesInputPersec
    counterSource = 'Win32_OperatingSystem_and_Win32_PerfFormattedData_PerfOS_Memory'
  }
  gpuInventory = [pscustomobject]@{
    count = $qaHost.gpu.computeProcessCount
    classification = 'wddm_inventory_not_compute_proof'
    limitation = 'Windows WDDM inventory can include graphics processes and unavailable per-process memory; count is not evidence of active ML jobs or their absence.'
  }
} | ConvertTo-Json -Compress -Depth 6
