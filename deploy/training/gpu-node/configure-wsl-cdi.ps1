param([string]$NodeName='k3d-evidscope-training-server-0',[string]$EvidenceDirectory)
$ErrorActionPreference='Stop'
if ($NodeName -notmatch '^k3d-evidscope-training(-[a-z0-9]+)*-server-0$') { throw 'Only the separate training node can be configured.' }
if (-not $EvidenceDirectory) { $EvidenceDirectory=Join-Path ([IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../..'))) '.local/training/gpu-node' }
New-Item -ItemType Directory -Path $EvidenceDirectory -Force | Out-Null
function Docker-Checked([string[]]$Arguments) {
  & docker @Arguments
  if ($LASTEXITCODE -ne 0) { throw "Docker failed with exit code $LASTEXITCODE" }
}
Docker-Checked @('exec',$NodeName,'test','-c','/dev/dxg')
Docker-Checked @('exec',$NodeName,'test','-f','/usr/lib/x86_64-linux-gnu/libdxcore.so')
$gpuUuids=@(& docker exec $NodeName nvidia-smi --query-gpu=uuid --format=csv,noheader)
if ($LASTEXITCODE -ne 0 -or $gpuUuids.Count -ne 1 -or $gpuUuids[0] -notmatch '^GPU-[a-f0-9-]+$') { throw 'This WSL adapter is restricted to one verified physical GPU.' }
Docker-Checked @('exec',$NodeName,'nvidia-ctk','cdi','generate','--format=json','--output=/etc/cdi/nvidia.json')
$originalPath=Join-Path $EvidenceDirectory 'nvidia-cdi-original.json'
Docker-Checked @('cp',"${NodeName}:/etc/cdi/nvidia.json",$originalPath)
$spec=Get-Content -Raw -LiteralPath $originalPath | ConvertFrom-Json
if ($spec.kind -ne 'nvidia.com/gpu' -or @($spec.devices).Count -ne 1 -or $spec.devices[0].name -ne 'all') { throw 'Unexpected WSL CDI shape; refusing a guessed device mapping.' }
$spec.cdiVersion='0.6.0'
$dxcorePath='/usr/lib/x86_64-linux-gnu/libdxcore.so'
if (-not @($spec.containerEdits.mounts | Where-Object {$_.containerPath -eq $dxcorePath}).Count) {
  $spec.containerEdits.mounts += [pscustomobject]@{hostPath=$dxcorePath;containerPath=$dxcorePath;options=@('ro','nosuid','nodev','rbind','rprivate')}
}
# WSL's generated CDI exposes 'all' only. On this verified SINGLE-GPU host,
# aliases bind the device plugin's exact UUID/index to that same one DXG device.
# Refuse multi-GPU hosts above rather than pretending DXG gives per-GPU isolation.
foreach ($alias in @($gpuUuids[0],'0')) {
  $device=$spec.devices[0] | ConvertTo-Json -Depth 30 | ConvertFrom-Json
  $device.name=$alias
  $spec.devices += $device
}
$patchedPath=Join-Path $EvidenceDirectory 'nvidia-cdi-verified.json'
[IO.File]::WriteAllText($patchedPath,($spec | ConvertTo-Json -Depth 30),[Text.UTF8Encoding]::new($false))
Docker-Checked @('cp',$patchedPath,"${NodeName}:/etc/cdi/nvidia.json")
Docker-Checked @('exec',$NodeName,'nvidia-ctk','config','--in-place','--set','nvidia-container-runtime.mode=cdi')
$deviceList=@(& docker exec $NodeName nvidia-ctk cdi list)
if ($LASTEXITCODE -ne 0 -or $deviceList -notcontains "nvidia.com/gpu=$($gpuUuids[0])" -or $deviceList -notcontains 'nvidia.com/gpu=all') { throw 'CDI device validation failed.' }
Write-Output $deviceList
