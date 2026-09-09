[CmdletBinding()]
param(
    [ValidateSet('Static','ServerValidate','Deploy','Observe','KillIngress','KillVault','HaltVault','ResumeVault')]
    [string]$Action = 'Static',
    [string]$Context,
    [switch]$LocalLab,
    [switch]$AllowFailureDrill,
    [string]$Image = 'evidscope:local',
    [int]$Samples = 6,
    [int]$IntervalSeconds = 10,
    [string]$ReportDirectory = 'deploy/reports'
)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$manifest = Join-Path $projectRoot 'deploy/kubernetes.json'
$list = Get-Content -LiteralPath $manifest -Raw | ConvertFrom-Json
function Require([bool]$Condition, [string]$Reason) { if (-not $Condition) { throw $Reason } }
Require ($list.kind -eq 'List' -and $list.items.Count -eq 23) 'Expected 23 resource Kubernetes List.'
$deployments = @($list.items | Where-Object kind -eq 'Deployment')
Require ($deployments.Count -eq 4) 'Four separate components required.'
foreach ($deployment in $deployments) {
    $component = $deployment.metadata.name
    $pod = $deployment.spec.template.spec
    $container = $pod.containers[0]
    Require ($pod.automountServiceAccountToken -eq $false) "$component mounts service account token."
    Require ($pod.securityContext.runAsNonRoot -and $pod.securityContext.seccompProfile.type -eq 'RuntimeDefault') "$component lacks restricted security context."
    Require ($container.securityContext.readOnlyRootFilesystem -and -not $container.securityContext.allowPrivilegeEscalation -and $container.securityContext.capabilities.drop -contains 'ALL') "$component container is not restricted."
    Require ($container.resources.requests.cpu -and $container.resources.limits.memory) "$component lacks resource bounds."
    Require ($container.readinessProbe.httpGet.scheme -eq 'HTTPS' -and $container.livenessProbe.httpGet.scheme -eq 'HTTPS') "$component health checks must use TLS."
    Require (@($pod.volumes | Where-Object { $_.secret.secretName -eq "$component-tls" }).Count -eq 1) "$component TLS secret missing."
    if ($component -ne 'vault') {
        Require (@($pod.volumes | Where-Object { $_.persistentVolumeClaim -or $_.secret.secretName -in @('vault-signing','vault-config') }).Count -eq 0) "$component can mount vault evidence/credentials/key."
        Require (@($container.env | Where-Object { $_.name -eq 'VAULT_URL' -and $_.value -eq 'https://vault.evidscope.svc:8080' }).Count -eq 1) "$component vault connection must verify TLS."
    } else {
        Require ($deployment.spec.replicas -eq 1 -and $deployment.spec.strategy.type -eq 'Recreate') 'SQLite vault must remain a singleton.'
        Require (@($pod.volumes | Where-Object { $_.secret.secretName -eq 'vault-signing' }).Count -eq 1) 'Vault signing key missing.'
    }
}
$defaultDeny = @($list.items | Where-Object { $_.kind -eq 'NetworkPolicy' -and $_.metadata.name -eq 'deny-all' })
Require ($defaultDeny.Count -eq 1 -and $defaultDeny[0].spec.policyTypes -contains 'Ingress' -and $defaultDeny[0].spec.policyTypes -contains 'Egress') 'Default deny ingress and egress required.'
Require (@($list.items | Where-Object kind -eq 'HorizontalPodAutoscaler').Count -eq 3) 'Three stateless HPA resources required.'
Require (@($list.items | Where-Object kind -eq 'Secret').Count -eq 0) 'Do not check secret values into the manifest.'
Write-Host 'PASS: offline structure and key boundary checks (23 resources). Cluster schema, CNI enforcement, TLS handshakes, HPA and recovery are NOT tested by Static.'
if ($Action -eq 'Static') { exit 0 }
Require (-not [string]::IsNullOrWhiteSpace($Context)) 'Explicit -Context required; the current kube context is never selected implicitly.'
Get-Command kubectl -ErrorAction Stop | Out-Null
function Invoke-Kube([string[]]$Arguments) {
    & kubectl --context $Context @Arguments
    if ($LASTEXITCODE -ne 0) { throw "kubectl failed (exit $LASTEXITCODE): $($Arguments -join ' ')" }
}
if ($Action -eq 'ServerValidate') {
    Invoke-Kube @('apply','--dry-run=server','-f',$manifest)
    exit 0
}
if ($Action -in @('Deploy','KillIngress','KillVault','HaltVault','ResumeVault')) {
    Require $LocalLab.IsPresent 'Mutation requires -LocalLab and an explicitly authorized disposable local cluster context.'
}
if ($Action -eq 'Deploy') {
    Invoke-Kube @('apply','-f',$manifest)
    foreach ($component in @('vault','ingress','audit','worker')) {
        Invoke-Kube @('-n','evidscope','set','image',"deployment/$component","$component=$Image")
        Invoke-Kube @('-n','evidscope','rollout','status',"deployment/$component",'--timeout=180s')
    }
    exit 0
}
if ($Action -eq 'Observe') {
    Require ($Samples -ge 1 -and $Samples -le 360 -and $IntervalSeconds -ge 1 -and $IntervalSeconds -le 60) 'Samples 1..360, interval 1..60 seconds.'
    $reportPath = [IO.Path]::GetFullPath((Join-Path $projectRoot $ReportDirectory))
    Require ($reportPath.StartsWith($projectRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) 'ReportDirectory must be inside this project.'
    New-Item -ItemType Directory -Force -Path $reportPath | Out-Null
    $output = Join-Path $reportPath ('observations-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.jsonl')
    # Fails explicitly if metrics-server/API is not installed or permitted.
    Invoke-Kube @('get','--raw','/apis/metrics.k8s.io/v1beta1/namespaces/evidscope/pods') | Out-Null
    for ($sample = 0; $sample -lt $Samples; $sample++) {
        $record = [ordered]@{ at = [DateTime]::UtcNow.ToString('o'); context = $Context; pods = (Invoke-Kube @('-n','evidscope','get','pods','-o','json') | ConvertFrom-Json); hpa = (Invoke-Kube @('-n','evidscope','get','hpa','-o','json') | ConvertFrom-Json); metrics = (Invoke-Kube @('get','--raw','/apis/metrics.k8s.io/v1beta1/namespaces/evidscope/pods') | ConvertFrom-Json) }
        $record | ConvertTo-Json -Depth 50 -Compress | Add-Content -LiteralPath $output -Encoding UTF8
        if ($sample -lt $Samples - 1) { Start-Sleep -Seconds $IntervalSeconds }
    }
    Invoke-Kube @('-n','evidscope','get','events','--sort-by=.metadata.creationTimestamp')
    Write-Host "Saved actual cluster observations: $output. Compare with generated/accepted/analyzed counts and predeclared acceptance criteria."
    exit 0
}
Require $AllowFailureDrill.IsPresent 'Failure injection requires -AllowFailureDrill; only use the authorized disposable lab.'
if ($Action -eq 'HaltVault') {
    Invoke-Kube @('-n','evidscope','scale','deployment/vault','--replicas=0')
    Write-Host 'Vault deliberately unavailable. Measure failed requests and bounded retries; use ResumeVault to restore. This simulates service unavailability, not a disk I/O failure.'
    exit 0
}
if ($Action -eq 'ResumeVault') {
    Invoke-Kube @('-n','evidscope','scale','deployment/vault','--replicas=1')
    Invoke-Kube @('-n','evidscope','rollout','status','deployment/vault','--timeout=180s')
    exit 0
}
$targetComponent = if ($Action -eq 'KillVault') { 'vault' } else { 'ingress' }
$pods = Invoke-Kube @('-n','evidscope','get','pods','-l',"app.kubernetes.io/component=$targetComponent",'-o','json') | ConvertFrom-Json
Require ($pods.items.Count -gt 0) "No $targetComponent pod found."
$podName = $pods.items[0].metadata.name
$started = [DateTime]::UtcNow
# Short grace period permits termination; this is not an actual node/power failure.
Invoke-Kube @('-n','evidscope','delete','pod',$podName,'--grace-period=1','--wait=true','--timeout=120s')
Invoke-Kube @('-n','evidscope','rollout','status',"deployment/$targetComponent",'--timeout=180s')
$elapsed = ([DateTime]::UtcNow - $started).TotalSeconds
Write-Host "Deleted $podName; rollout available after $elapsed seconds. Availability alone does not prove data completeness: reconcile source IDs, backlog, export verification and tenant-denial results."
