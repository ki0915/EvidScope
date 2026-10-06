$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path $PSScriptRoot -Parent
$receiptDir = Join-Path $taskRoot '.local\training\pagefile'
New-Item -ItemType Directory -Force -Path $receiptDir | Out-Null
$resultPath = Join-Path $receiptDir 'result.json'
$backupPath = Join-Path $receiptDir 'before.json'
$taskAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $taskAdmin) { throw 'Administrator token required; no settings changed.' }
$changed = $false
try {
    $taskSystem = Get-CimInstance Win32_ComputerSystem
    $taskSettings = @(Get-CimInstance Win32_PageFileSetting)
    $taskDrive = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"
    if (-not $taskSystem.AutomaticManagedPagefile -or $taskSettings.Count -ne 0) { throw 'Pagefile configuration changed; refusing to replace it.' }
    if ($taskDrive.FreeSpace -lt 28GB) { throw 'Insufficient disk reserve for approved pagefile.' }
    if (Test-Path -LiteralPath $backupPath) {
        $previousResult = Get-Content -LiteralPath $resultPath -Raw | ConvertFrom-Json
        if ($previousResult.status -ne 'failed' -or -not $previousResult.restoredAutomaticManagement) { throw 'Previous attempt was not restored; inspect before retrying.' }
        Copy-Item -LiteralPath $resultPath -Destination (Join-Path $receiptDir ('failed-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.json'))
    }
    @{ observedAt=(Get-Date).ToString('o'); automaticManagedPagefile=$taskSystem.AutomaticManagedPagefile; settings=$taskSettings; usage=@(Get-CimInstance Win32_PageFileUsage | Select-Object Name,AllocatedBaseSize,CurrentUsage); approvedInitialMiB=16384; approvedMaximumMiB=24576 } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $backupPath -Encoding UTF8
    Set-CimInstance -InputObject $taskSystem -Property @{AutomaticManagedPagefile=$false} | Out-Null
    $changed = $true
    $existingSetting = Get-CimInstance Win32_PageFileSetting -Filter "Name='C:\\pagefile.sys'"
    if ($existingSetting) {
        Set-CimInstance -InputObject $existingSetting -Property @{InitialSize=[uint32]16384;MaximumSize=[uint32]24576} | Out-Null
    } else {
        New-CimInstance -ClassName Win32_PageFileSetting -Property @{Name='C:\pagefile.sys';InitialSize=[uint32]16384;MaximumSize=[uint32]24576} | Out-Null
    }
    $after = Get-CimInstance Win32_PageFileSetting -Filter "Name='C:\\pagefile.sys'"
    if ($after.InitialSize -ne 16384 -or $after.MaximumSize -ne 24576) { throw 'Pagefile settings readback failed.' }
    @{ status='configured'; observedAt=(Get-Date).ToString('o'); automaticManagedPagefile=(Get-CimInstance Win32_ComputerSystem).AutomaticManagedPagefile; settings=@($after | Select-Object Name,InitialSize,MaximumSize); usage=@(Get-CimInstance Win32_PageFileUsage | Select-Object Name,AllocatedBaseSize,CurrentUsage); rebootPerformed=$false } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $resultPath -Encoding UTF8
} catch {
    $failure = $_.Exception.Message
    $rollback = $false
    if ($changed) {
        try {
            $ownSetting = Get-CimInstance Win32_PageFileSetting -Filter "Name='C:\\pagefile.sys'"
            if ($ownSetting -and $ownSetting.InitialSize -eq 16384 -and $ownSetting.MaximumSize -eq 24576) { Remove-CimInstance -InputObject $ownSetting }
            Get-CimInstance Win32_ComputerSystem | Set-CimInstance -Property @{AutomaticManagedPagefile=$true} | Out-Null
            $rollback = (Get-CimInstance Win32_ComputerSystem).AutomaticManagedPagefile
        } catch { $failure += '; rollback error: ' + $_.Exception.Message }
    }
    @{status='failed'; error=$failure; restoredAutomaticManagement=$rollback; rebootPerformed=$false} | ConvertTo-Json | Set-Content -LiteralPath $resultPath -Encoding UTF8
    throw
}
