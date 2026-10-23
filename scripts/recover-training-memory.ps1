param([switch]$SuspendDlp)
$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path $PSScriptRoot -Parent
$taskReceiptDirectory = Join-Path $taskRoot ('.local\training\memory-recovery\' + [DateTimeOffset]::UtcNow.ToString('yyyyMMdd-HHmmss-fff'))
New-Item -ItemType Directory -Path $taskReceiptDirectory | Out-Null
$taskReceiptPath = Join-Path $taskReceiptDirectory 'receipt.json'
$taskNames = @('k3d-dlp-server-0', 'k3d-dlp-serverlb', 'k3d-dlp-proof-server-0', 'k3d-dlp-proof-serverlb', 'k3d-dlp-empirical-20260712-server-0', 'k3d-dlp-empirical-20260712-serverlb')
function Invoke-TaskDocker([string[]]$Arguments) {
    $taskOutput = & docker @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) { throw ('Docker operation failed: ' + ($taskOutput -join "`n")) }
    return ($taskOutput -join "`n")
}
function Get-TaskContainers {
    $taskIds = @((Invoke-TaskDocker -Arguments @('ps', '-aq')) -split '\s+' | Where-Object { $_ })
    if (-not $taskIds.Count) { return @() }
    $taskAll = Invoke-TaskDocker -Arguments (@('inspect') + $taskIds) | ConvertFrom-Json
    return @(@($taskAll) | Where-Object { $_.Name.TrimStart('/') -in $taskNames } | ForEach-Object {
        [pscustomobject]@{ id=$_.Id; name=$_.Name.TrimStart('/'); running=$_.State.Running; memoryLimit=$_.HostConfig.Memory; nanoCpus=$_.HostConfig.NanoCpus; restartPolicy=$_.HostConfig.RestartPolicy }
    })
}
function Get-TaskMemory {
    $taskOs = Get-CimInstance Win32_OperatingSystem
    $taskCounters = Get-CimInstance Win32_PerfFormattedData_PerfOS_Memory
    if ($null -eq $taskCounters.CommittedBytes -or $taskCounters.CommitLimit -le 0 -or $null -eq $taskOs.FreePhysicalMemory) { throw 'Windows memory counters unavailable' }
    [pscustomobject]@{
        observedAt=[DateTimeOffset]::UtcNow.ToString('o')
        physicalFreeGiB=[math]::Round($taskOs.FreePhysicalMemory/1MB,3)
        commitFreeGiB=[math]::Round(($taskCounters.CommitLimit-$taskCounters.CommittedBytes)/1GB,3)
        commitLimitGiB=[math]::Round($taskCounters.CommitLimit/1GB,3)
        commitUsedPercent=[math]::Round(100*$taskCounters.CommittedBytes/$taskCounters.CommitLimit,3)
        pagesInputPerSecond=$taskCounters.PagesInputPersec
    }
}
$taskReceipt = [ordered]@{schemaVersion=1; startedAt=[DateTimeOffset]::UtcNow.ToString('o'); suspendDlp=$SuspendDlp.IsPresent; gpuStarted=$false; cacheReclaimed=$false; containersBefore=@(); stopRequestedIds=@(); before=$null; samples=@(); restored=$false; error=$null}
function Save-TaskReceipt { $taskReceipt | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $taskReceiptPath -Encoding utf8 }
try {
    if (Test-Path -LiteralPath (Join-Path $taskRoot '.local\training\manual-public-qa-active.json')) { throw 'Active or unconfirmed GPU lease; memory recovery not started' }
    $taskReceipt.containersBefore = @(Get-TaskContainers)
    if ($SuspendDlp -and -not $taskReceipt.containersBefore.Count) { throw 'No approved DLP containers found; refusing an empty suspension proof' }
    if ($SuspendDlp -and (Compare-Object ($taskNames | Sort-Object) (@($taskReceipt.containersBefore.name) | Sort-Object))) { throw 'Approved DLP container inventory incomplete; no containers stopped' }
    $taskReceipt.before = Get-TaskMemory
    Save-TaskReceipt
    if ($SuspendDlp) {
        foreach ($taskContainer in $taskReceipt.containersBefore | Where-Object running) {
            $taskReceipt.stopRequestedIds += $taskContainer.id
            Save-TaskReceipt
            Invoke-TaskDocker -Arguments @('stop', '--time', '30', $taskContainer.id) | Out-Null
        }
    }
    # Flush dirty data first. Only reproducible Linux file/dentry/inode caches
    # are reclaimed; user applications, anonymous memory and VM settings remain.
    $taskCacheOutput = & wsl --distribution docker-desktop --user root -- sh -c 'set -eu; sync; echo 3 > /proc/sys/vm/drop_caches' 2>&1
    if ($LASTEXITCODE -ne 0) { throw ('Cache reclaim failed: ' + ($taskCacheOutput -join "`n")) }
    $taskReceipt.cacheReclaimed = $true
    # WSL returns memory asynchronously. Preserve early measurements and wait
    # for three consecutive Windows-floor samples, bounded to 80 seconds.
    for ($taskSampleIndex=0; $taskSampleIndex -lt 9; $taskSampleIndex++) {
        if ($taskSampleIndex) { Start-Sleep -Seconds 10 }
        $taskReceipt.samples += Get-TaskMemory
        Save-TaskReceipt
        $taskRecent = @($taskReceipt.samples | Select-Object -Last 3)
        if ($taskRecent.Count -eq 3 -and @($taskRecent | Where-Object { $_.physicalFreeGiB -lt 4 -or $_.commitFreeGiB -lt 14 -or $_.commitUsedPercent -gt 85 }).Count -eq 0) { break }
    }
    $taskRecent = @($taskReceipt.samples | Select-Object -Last 3)
    $taskReceipt.windowsStartFloorMet = $taskRecent.Count -eq 3 -and @($taskRecent | Where-Object { $_.physicalFreeGiB -lt 4 -or $_.commitFreeGiB -lt 14 -or $_.commitUsedPercent -gt 85 }).Count -eq 0
    $taskReceipt.operationalCommitTargetMet = $taskRecent.Count -eq 3 -and @($taskRecent | Where-Object { $_.commitFreeGiB -lt 17 }).Count -eq 0
    $taskReceipt.fullGpuAdmissionClaimed = $false
} catch {
    $taskReceipt.error = $_.Exception.Message
} finally {
    $taskRestoreErrors = @()
    foreach ($taskContainer in $taskReceipt.containersBefore | Where-Object { $_.running -and $_.id -in $taskReceipt.stopRequestedIds }) {
        try {
            $taskCurrent = Invoke-TaskDocker -Arguments @('inspect', $taskContainer.id) | ConvertFrom-Json
            $taskCurrent = @($taskCurrent)[0]
            if ($taskCurrent.Name.TrimStart('/') -ne $taskContainer.name) { throw 'Container identity changed' }
            if (-not $taskCurrent.State.Running) { Invoke-TaskDocker -Arguments @('start', $taskContainer.id) | Out-Null }
        } catch { $taskRestoreErrors += $_.Exception.Message }
    }
    try {
        $taskReceipt.containersAfter = @(Get-TaskContainers)
        foreach ($taskContainer in $taskReceipt.containersBefore) {
            $taskAfter = @($taskReceipt.containersAfter | Where-Object id -eq $taskContainer.id)
            if ($taskAfter.Count -ne 1 -or ($taskAfter[0] | ConvertTo-Json -Compress -Depth 5) -ne ($taskContainer | ConvertTo-Json -Compress -Depth 5)) { throw ('Original container state or configuration not restored: ' + $taskContainer.name) }
        }
        $taskReceipt.afterRestore = Get-TaskMemory
    } catch { $taskRestoreErrors += $_.Exception.Message }
    $taskReceipt.restoreErrors = $taskRestoreErrors
    $taskReceipt.restored = $taskRestoreErrors.Count -eq 0
    $taskReceipt.finishedAt = [DateTimeOffset]::UtcNow.ToString('o')
    Save-TaskReceipt
}
$taskReceipt | ConvertTo-Json -Depth 8
if ($taskReceipt.error -or -not $taskReceipt.restored) { throw ('Memory recovery did not complete; inspect ' + $taskReceiptPath) }
