[CmdletBinding(DefaultParameterSetName='Check')]
param(
    [Parameter(Mandatory=$true, ParameterSetName='Apply')][switch]$Apply,
    [Parameter(Mandatory=$true, ParameterSetName='Restore')][switch]$Restore,
    [Parameter(Mandatory=$true, ParameterSetName='Restore')][string]$ReceiptPath
)
$ErrorActionPreference = 'Stop'
$taskRoot = [IO.Path]::GetFullPath((Split-Path $PSScriptRoot -Parent))
$receiptRoot = [IO.Path]::GetFullPath((Join-Path $taskRoot '.local\training\browser-memory'))
$policyPath = 'SOFTWARE\Policies\Google\Chrome'
$desired = [ordered]@{ HighEfficiencyModeEnabled=1; MemorySaverModeSavings=2 }
$taskSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$taskReceipt = [ordered]@{
    schemaVersion=1; kind='chrome_current_user_training_memory_policy_v1'
    startedAt=[DateTimeOffset]::UtcNow.ToString('o'); ownerSid=$taskSid
    action=$PSCmdlet.ParameterSetName.ToLowerInvariant(); registryPath=$policyPath
    desired=@([pscustomobject]@{name='HighEfficiencyModeEnabled';kind='DWord';value=1}, [pscustomobject]@{name='MemorySaverModeSavings';kind='DWord';value=2})
    before=@(); after=@(); chrome=@(); mutationIntent=@(); appliedNames=@()
    restoredNames=@(); restoreDeferred=@(); rollbackErrors=@(); error=$null
    registryWriteVerified=$false; runtimeAdoptionVerified=$false; memoryReductionVerified=$false; sourceReceipt=$null
    receiptWritten=$false; finishedAt=$null
}
function Assert-TaskSafePath([string]$Path) {
    $full = [IO.Path]::GetFullPath($Path)
    if (-not $full.StartsWith($receiptRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'Receipt must be inside workspace .local/training/browser-memory' }
    $cursor = $full
    while ($cursor) {
        if (Test-Path -LiteralPath $cursor) {
            $item = Get-Item -LiteralPath $cursor -Force
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Receipt path contains a reparse point' }
        }
        $next = Split-Path $cursor -Parent
        if ($next -eq $cursor) { break }
        $cursor = $next
    }
    return $full
}
function Get-TaskPolicies {
    $values = @()
    foreach ($hive in @([Microsoft.Win32.RegistryHive]::CurrentUser, [Microsoft.Win32.RegistryHive]::LocalMachine)) {
        foreach ($view in @([Microsoft.Win32.RegistryView]::Registry64, [Microsoft.Win32.RegistryView]::Registry32)) {
            $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey($hive, $view)
            try {
                foreach ($suffix in @('', '\Recommended')) {
                    $key = $base.OpenSubKey($policyPath + $suffix, $false)
                    if ($null -eq $key) { continue }
                    try {
                        foreach ($name in $desired.Keys) {
                            if ($key.GetValueNames() -contains $name) {
                                $values += [pscustomobject]@{hive=$hive.ToString();view=$view.ToString();path=($policyPath+$suffix);name=$name;kind=$key.GetValueKind($name).ToString();value=$key.GetValue($name)}
                            }
                        }
                    } finally { $key.Dispose() }
                }
            } finally { $base.Dispose() }
        }
    }
    return $values
}
function Get-TaskChrome {
    $candidates = @()
    foreach ($hive in @([Microsoft.Win32.RegistryHive]::CurrentUser, [Microsoft.Win32.RegistryHive]::LocalMachine)) {
        foreach ($view in @([Microsoft.Win32.RegistryView]::Registry64, [Microsoft.Win32.RegistryView]::Registry32)) {
            $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey($hive, $view)
            try {
                $key = $base.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe', $false)
                if ($key) { try { $candidates += [string]$key.GetValue('') } finally { $key.Dispose() } }
            } finally { $base.Dispose() }
        }
    }
    foreach ($parent in @($env:LOCALAPPDATA, $env:ProgramFiles, ${env:ProgramFiles(x86)})) {
        if ($parent) { $candidates += Join-Path $parent 'Google\Chrome\Application\chrome.exe' }
    }
    # Include actual running executable paths; do not terminate or alter processes.
    foreach ($process in @(Get-Process -Name chrome -ErrorAction SilentlyContinue)) {
        try { if ($process.Path) { $candidates += $process.Path } } catch { }
    }
    $installed = @()
    foreach ($candidate in @($candidates | Where-Object { $_ } | Select-Object -Unique)) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            $version = [Diagnostics.FileVersionInfo]::GetVersionInfo($candidate)
            if ($version.ProductName -match 'Google Chrome' -and $version.FileMajorPart -gt 0) {
                $installed += [pscustomobject]@{path=[IO.Path]::GetFullPath($candidate);version=$version.FileVersion;major=$version.FileMajorPart}
            }
        }
    }
    return $installed
}
function Save-TaskReceipt {
    Assert-TaskSafePath $taskReceiptPath | Out-Null
    $taskReceipt.receiptWritten = $true
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($taskReceipt | ConvertTo-Json -Depth 12))
    $temporary = $taskReceiptPath + '.' + [guid]::NewGuid().ToString('N') + '.tmp'
    $stream = [IO.File]::Open($temporary, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
    if ([IO.File]::Exists($taskReceiptPath)) {
        # Windows PowerShell 5 binds a null string to an empty path. Supply an
        # actual unique backup path, retaining each previous durable receipt.
        $previous = $taskReceiptPath + '.' + [guid]::NewGuid().ToString('N') + '.previous.json'
        Assert-TaskSafePath $previous | Out-Null
        [IO.File]::Replace($temporary, $taskReceiptPath, $previous)
    }
    else { [IO.File]::Move($temporary, $taskReceiptPath) }
}
function Remove-TaskOwnedValue([string]$Name, [Microsoft.Win32.RegistryKey]$Key) {
    if ($null -eq $Key -or $Key.GetValueNames() -notcontains $Name) { return 'already_absent' }
    if ($Key.GetValueKind($Name) -ne [Microsoft.Win32.RegistryValueKind]::DWord -or [int]$Key.GetValue($Name) -ne [int]$desired[$Name]) { return 'external_change_deferred' }
    $Key.DeleteValue($Name, $false)
    if ($Key.GetValueNames() -contains $Name) { throw ('Policy deletion not confirmed: ' + $Name) }
    return 'deleted'
}
function Undo-TaskWrites {
    foreach ($name in $taskWrittenNames) {
        try {
            $status = Remove-TaskOwnedValue $name $writable
            if ($status -eq 'external_change_deferred') { $taskReceipt.restoreDeferred += $name }
            else { $taskReceipt.restoredNames += $name }
        } catch { $taskReceipt.rollbackErrors += $_.Exception.Message }
    }
    $taskReceipt.registryWriteVerified = $false
}

$taskReceiptPath = Join-Path $receiptRoot ([DateTimeOffset]::UtcNow.ToString('yyyyMMdd-HHmmss-fff') + '-' + [guid]::NewGuid().ToString('N') + '.json')
Assert-TaskSafePath $taskReceiptPath | Out-Null
[IO.Directory]::CreateDirectory($receiptRoot) | Out-Null
Assert-TaskSafePath $taskReceiptPath | Out-Null
$mutex = [Threading.Mutex]::new($false, ('Local\EvidScopeChromeMemoryPolicy-' + $taskSid))
$held = $false
$baseWritable = $null
$writable = $null
$taskWrittenNames = @()
try {
    try { $held = $mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $held = $true }
    if (-not $held) { throw 'Another browser memory policy operation is active' }
    $taskReceipt.before = @(Get-TaskPolicies)
    $taskReceipt.chrome = @(Get-TaskChrome)
    Save-TaskReceipt
    if ($Apply) {
        if (-not $taskReceipt.chrome.Count -or @($taskReceipt.chrome | Where-Object { $_.major -lt 126 }).Count) { throw 'Google Chrome 126 or newer is required; every discovered installation must support both policies' }
        if ($taskReceipt.before.Count) { throw 'Existing HKLM/HKCU managed or recommended value found; nothing overwritten' }
        $baseWritable = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::CurrentUser, [Microsoft.Win32.RegistryView]::Registry64)
        # Create only the user policy container; never remove this key or sibling policies.
        $writable = $baseWritable.CreateSubKey($policyPath, $true)
        foreach ($name in $desired.Keys) {
            $conflicts = @(Get-TaskPolicies | Where-Object {
                -not ($_.hive -eq 'CurrentUser' -and $_.path -eq $policyPath -and $_.name -in $taskWrittenNames -and $_.kind -eq 'DWord' -and $_.value -eq $desired[$_.name])
            })
            if ($conflicts.Count) { throw ('Managed policy appeared before write: ' + $name) }
            $taskReceipt.mutationIntent += $name
            Save-TaskReceipt
            # Register the requested write before invoking the registry API:
            # interruption/ambiguous API failure may occur after the mutation.
            $taskWrittenNames += $name
            $writable.SetValue($name, [int]$desired[$name], [Microsoft.Win32.RegistryValueKind]::DWord)
            $taskReceipt.appliedNames += $name
            if ($writable.GetValueKind($name) -ne [Microsoft.Win32.RegistryValueKind]::DWord -or [int]$writable.GetValue($name) -ne [int]$desired[$name]) { throw ('Policy write not confirmed: ' + $name) }
            Save-TaskReceipt
        }
    } elseif ($Restore) {
        $sourcePath = Assert-TaskSafePath $ReceiptPath
        $source = Get-Content -LiteralPath $sourcePath -Raw | ConvertFrom-Json
        if ($source.schemaVersion -ne 1 -or $source.kind -ne $taskReceipt.kind -or $source.ownerSid -ne $taskSid -or $source.action -ne 'apply' -or $source.registryPath -ne $policyPath -or @($source.before).Count -ne 0) { throw 'Receipt is not an eligible current-user apply receipt' }
        if (@($source.desired).Count -ne 2 -or @($source.mutationIntent).Count -eq 0 -or @($source.mutationIntent | Select-Object -Unique).Count -ne @($source.mutationIntent).Count) { throw 'Receipt policy scope invalid' }
        foreach ($name in $desired.Keys) {
            $entry = @($source.desired | Where-Object { $_.name -eq $name -and $_.kind -eq 'DWord' -and $_.value -eq $desired[$name] })
            if ($entry.Count -ne 1) { throw 'Receipt expected policy values invalid' }
        }
        foreach ($name in @($source.mutationIntent)) { if ($name -notin $desired.Keys) { throw 'Receipt mutation scope invalid' } }
        foreach ($name in @($source.appliedNames)) { if ($name -notin $desired.Keys -or $name -notin @($source.mutationIntent)) { throw 'Receipt applied scope invalid' } }
        $taskReceipt.sourceReceipt = $sourcePath
        Save-TaskReceipt
        $baseWritable = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::CurrentUser, [Microsoft.Win32.RegistryView]::Registry64)
        $writable = $baseWritable.OpenSubKey($policyPath, $true)
        # Durable intent plus originally absent values covers interrupted writes.
        # Only an exact current DWORD match is deleted; other values are deferred.
        foreach ($name in @($source.mutationIntent)) {
            $status = Remove-TaskOwnedValue $name $writable
            if ($status -eq 'external_change_deferred') { $taskReceipt.restoreDeferred += $name }
            else { $taskReceipt.restoredNames += $name }
            Save-TaskReceipt
        }
    }
} catch {
    $taskReceipt.error = $_.Exception.Message
    if ($Apply -and $writable) { Undo-TaskWrites }
} finally {
    try {
        $taskReceipt.after = @(Get-TaskPolicies)
        if ($Apply -and -not $taskReceipt.error) {
            foreach ($name in $desired.Keys) {
                if (@($taskReceipt.after | Where-Object { $_.hive -eq 'CurrentUser' -and $_.view -eq 'Registry64' -and $_.path -eq $policyPath -and $_.name -eq $name -and $_.kind -eq 'DWord' -and $_.value -eq $desired[$name] }).Count -ne 1) { throw ('Final user policy value differs: ' + $name) }
            }
            if (@($taskReceipt.after | Where-Object { $_.hive -ne 'CurrentUser' -or $_.path -ne $policyPath -or $_.kind -ne 'DWord' -or $_.value -ne $desired[$_.name] }).Count) { throw 'Final managed policy conflict detected' }
            $taskReceipt.registryWriteVerified = $true
        }
    } catch {
        if (-not $taskReceipt.error) { $taskReceipt.error = $_.Exception.Message }
        $taskReceipt.rollbackErrors += $_.Exception.Message
        if ($Apply -and $writable) {
            Undo-TaskWrites
            try { $taskReceipt.after = @(Get-TaskPolicies) } catch { $taskReceipt.rollbackErrors += $_.Exception.Message }
        }
    }
    $taskReceipt.finishedAt = [DateTimeOffset]::UtcNow.ToString('o')
    try { Save-TaskReceipt } catch {
        $taskReceipt.error = 'Final atomic receipt write failed: ' + $_.Exception.Message
        if ($Apply -and $writable) {
            Undo-TaskWrites
            try { $taskReceipt.after = @(Get-TaskPolicies) } catch { $taskReceipt.rollbackErrors += $_.Exception.Message }
        }
        # A failed durable receipt can never be reported as an applied success.
        Save-TaskReceipt
    } finally {
        if ($writable) { $writable.Dispose() }
        if ($baseWritable) { $baseWritable.Dispose() }
        if ($held) { $mutex.ReleaseMutex() }
        $mutex.Dispose()
    }
}
[pscustomobject]@{receiptPath=$taskReceiptPath;action=$taskReceipt.action;registryWriteVerified=$taskReceipt.registryWriteVerified;appliedNames=$taskReceipt.appliedNames;restoredNames=$taskReceipt.restoredNames;restoreDeferred=$taskReceipt.restoreDeferred;runtimeAdoptionVerified=$false;memoryReductionVerified=$false;error=$taskReceipt.error} | ConvertTo-Json -Depth 5
if ($taskReceipt.error -or $taskReceipt.rollbackErrors.Count -or $taskReceipt.restoreDeferred.Count) { throw ('Browser policy operation incomplete; inspect ' + $taskReceiptPath) }
