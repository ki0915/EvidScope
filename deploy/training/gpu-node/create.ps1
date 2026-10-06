param(
  [Parameter(Mandatory=$true)][string]$K3dPath,
  [Parameter(Mandatory=$true)][string]$NodeImage,
  [Parameter(Mandatory=$true)][string]$DevicePluginImage,
  [string]$ClusterName='evidscope-training',
  [int]$ApiPort=19646
)
$ErrorActionPreference='Stop'
if ($ClusterName -notmatch '^evidscope-training(-[a-z0-9]+)*$') { throw 'Only a new EvidScope training cluster is accepted.' }
if ($NodeImage -notmatch '^evidscope/k3s-gpu:[a-zA-Z0-9_.-]+$') { throw 'Use a locally built EvidScope GPU node image.' }
if ($DevicePluginImage -notmatch '^nvcr\.io/nvidia/k8s-device-plugin@sha256:[a-f0-9]{64}$') { throw 'Pin the official device plugin to its resolved registry digest.' }
if ($ApiPort -lt 1024 -or $ApiPort -gt 65535) { throw 'Invalid API port.' }
function Invoke-Checked([string]$Program,[string[]]$Arguments) {
  & $Program @Arguments
  if ($LASTEXITCODE -ne 0) { throw "$Program failed with exit code $LASTEXITCODE" }
}
$existing= & $K3dPath cluster list -o json
if ($LASTEXITCODE -ne 0) { throw 'Cannot list existing clusters.' }
if (@($existing | ConvertFrom-Json | Where-Object {$_.name -eq $ClusterName}).Count -gt 0) { throw 'Cluster already exists; refusing to replace or modify it.' }
$nodeId= & docker image inspect $NodeImage --format '{{.Id}}'
if ($LASTEXITCODE -ne 0 -or $nodeId -notmatch '^sha256:[a-f0-9]{64}$') { throw 'Build the node image first.' }
$repoRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../..'))
$runDir=Join-Path $repoRoot ".test-runs/$ClusterName"
if (Test-Path -LiteralPath $runDir) { throw 'Run directory already exists; inspect its earlier evidence first.' }
New-Item -ItemType Directory -Path $runDir | Out-Null
$kubeConfig=Join-Path $runDir 'kubeconfig.yaml'
Invoke-Checked $K3dPath @('cluster','create',$ClusterName,'--image',$NodeImage,'--servers','1','--agents','0','--no-lb','--gpus','all','--servers-memory','14g','--api-port',"127.0.0.1:$ApiPort",'--kubeconfig-update-default=false','--kubeconfig-switch-context=false','--k3s-arg','--disable=traefik,servicelb,metrics-server@server:0','--k3s-node-label','evidscope.io/training-node=true@server:0','--timeout','180s')
$configText= & $K3dPath kubeconfig get $ClusterName
if ($LASTEXITCODE -ne 0) { throw 'Cannot export isolated kubeconfig.' }
[IO.File]::WriteAllText($kubeConfig,($configText -join "`n"),[Text.UTF8Encoding]::new($false))
$nodeName="k3d-$ClusterName-server-0"
& docker exec $nodeName test -c /dev/dxg
if ($LASTEXITCODE -eq 0) {
  & (Join-Path $PSScriptRoot 'configure-wsl-cdi.ps1') -NodeName $nodeName -EvidenceDirectory $runDir
}
$plugin=Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot 'device-plugin.json') | ConvertFrom-Json
$plugin.spec.template.spec.containers[0].image=$DevicePluginImage
$pluginPath=Join-Path $runDir 'device-plugin.json'
[IO.File]::WriteAllText($pluginPath,($plugin | ConvertTo-Json -Depth 30),[Text.UTF8Encoding]::new($false))
Invoke-Checked kubectl @('--kubeconfig',$kubeConfig,'apply','-f',$pluginPath)
Invoke-Checked kubectl @('--kubeconfig',$kubeConfig,'-n','kube-system','rollout','status','daemonset/evidscope-nvidia-device-plugin','--timeout=120s')
$nodeState= & kubectl --kubeconfig $kubeConfig get nodes -o json
if ($LASTEXITCODE -ne 0) { throw 'Cannot inspect GPU allocation.' }
$nodes=$nodeState | ConvertFrom-Json
if ($nodes.items.Count -ne 1 -or $nodes.items[0].status.allocatable.'nvidia.com/gpu' -ne '1') { throw 'The device plugin has not registered exactly one GPU; do not admit training.' }
Write-Output $nodeState
Write-Output "Isolated kubeconfig: $kubeConfig"
Write-Output 'Verify allocatable nvidia.com/gpu=1 and run the actual CUDA/NetworkPolicy probes before admission.'
