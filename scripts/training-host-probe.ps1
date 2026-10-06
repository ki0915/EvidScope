$ErrorActionPreference = 'Stop'

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class EvidScopeHostState {
  [StructLayout(LayoutKind.Sequential)] public struct LASTINPUTINFO { public uint cbSize; public uint dwTime; }
  [StructLayout(LayoutKind.Sequential)] public struct SYSTEM_POWER_STATUS { public byte ACLineStatus; public byte BatteryFlag; public byte BatteryLifePercent; public byte SystemStatusFlag; public uint BatteryLifeTime; public uint BatteryFullLifeTime; }
  [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Auto)] public struct MEMORYSTATUSEX { public uint dwLength; public uint dwMemoryLoad; public ulong ullTotalPhys; public ulong ullAvailPhys; public ulong ullTotalPageFile; public ulong ullAvailPageFile; public ulong ullTotalVirtual; public ulong ullAvailVirtual; public ulong ullAvailExtendedVirtual; }
  [StructLayout(LayoutKind.Sequential)] public struct FILETIME { public uint Low; public uint High; }
  [DllImport("user32.dll")] public static extern bool GetLastInputInfo(ref LASTINPUTINFO info);
  [DllImport("kernel32.dll")] public static extern uint GetTickCount();
  [DllImport("kernel32.dll")] public static extern bool GetSystemPowerStatus(ref SYSTEM_POWER_STATUS status);
  [DllImport("kernel32.dll", CharSet=CharSet.Auto, SetLastError=true)] public static extern bool GlobalMemoryStatusEx(ref MEMORYSTATUSEX status);
  [DllImport("kernel32.dll", SetLastError=true)] public static extern bool GetSystemTimes(out FILETIME idle, out FILETIME kernel, out FILETIME user);
}
'@

$last = New-Object EvidScopeHostState+LASTINPUTINFO
$last.cbSize = [Runtime.InteropServices.Marshal]::SizeOf($last)
if (-not [EvidScopeHostState]::GetLastInputInfo([ref]$last)) { throw 'last_input_unavailable' }
$tick = [uint64][EvidScopeHostState]::GetTickCount()
$lastTick = [uint64]$last.dwTime
$idleMilliseconds = if ($tick -ge $lastTick) { $tick - $lastTick } else { 4294967296 + $tick - $lastTick }

$power = New-Object EvidScopeHostState+SYSTEM_POWER_STATUS
if (-not [EvidScopeHostState]::GetSystemPowerStatus([ref]$power)) { throw 'power_status_unavailable' }
$memory = New-Object EvidScopeHostState+MEMORYSTATUSEX
$memory.dwLength = [Runtime.InteropServices.Marshal]::SizeOf($memory)
if (-not [EvidScopeHostState]::GlobalMemoryStatusEx([ref]$memory)) { throw 'memory_status_unavailable' }
$idle1 = New-Object EvidScopeHostState+FILETIME; $kernel1 = New-Object EvidScopeHostState+FILETIME; $user1 = New-Object EvidScopeHostState+FILETIME
$idle2 = New-Object EvidScopeHostState+FILETIME; $kernel2 = New-Object EvidScopeHostState+FILETIME; $user2 = New-Object EvidScopeHostState+FILETIME
if (-not [EvidScopeHostState]::GetSystemTimes([ref]$idle1,[ref]$kernel1,[ref]$user1)) { throw 'cpu_status_unavailable' }
Start-Sleep -Milliseconds 250
if (-not [EvidScopeHostState]::GetSystemTimes([ref]$idle2,[ref]$kernel2,[ref]$user2)) { throw 'cpu_status_unavailable' }
function FileTimeValue($value) { return [uint64]$value.High * 4294967296 + [uint64]$value.Low }
$idleDelta = (FileTimeValue $idle2) - (FileTimeValue $idle1)
$totalDelta = ((FileTimeValue $kernel2) - (FileTimeValue $kernel1)) + ((FileTimeValue $user2) - (FileTimeValue $user1))
$cpuPercent = if ($totalDelta -gt 0) { [math]::Round(100 * ($totalDelta - $idleDelta) / $totalDelta, 2) } else { 100 }
$gpuLine = (& nvidia-smi --query-gpu=memory.used,memory.total,utilization.gpu,temperature.gpu --format=csv,noheader,nounits 2>$null | Select-Object -First 1)
if (-not $gpuLine) { throw 'gpu_status_unavailable' }
$gpu = @($gpuLine -split ',' | ForEach-Object { [double]($_.Trim()) })
if ($gpu.Count -ne 4) { throw 'gpu_status_invalid' }
$computeRows = @(& nvidia-smi --query-compute-apps=gpu_uuid,pid --format=csv,noheader,nounits 2>$null)
if ($LASTEXITCODE -ne 0) { throw 'gpu_compute_inventory_unavailable' }
if ($computeRows | Where-Object { $_ -and $_ -notmatch '^GPU-[a-fA-F0-9-]+,\s*\d+\s*$' -and $_ -notmatch '^No running processes found' }) { throw 'gpu_compute_inventory_unsupported' }
$otherCompute = @($computeRows | Where-Object { $_ -match '^GPU-[a-fA-F0-9-]+,\s*\d+\s*$' }).Count

[pscustomobject]@{
  schemaVersion = 1
  source = 'trusted_windows_host_probe'
  observedAt = [DateTimeOffset]::Now.ToString('o')
  idleSeconds = [math]::Floor($idleMilliseconds / 1000)
  cpuPercent = [double]$cpuPercent
  freeMemoryGiB = [math]::Round($memory.ullAvailPhys / 1GB, 3)
  onAcPower = $power.ACLineStatus -eq 1
  gpu = [pscustomobject]@{
    memoryUsedMiB = $gpu[0]
    memoryTotalMiB = $gpu[1]
    utilizationPercent = $gpu[2]
    temperatureC = $gpu[3]
    computeProcessCount = $otherCompute
  }
} | ConvertTo-Json -Compress -Depth 3
