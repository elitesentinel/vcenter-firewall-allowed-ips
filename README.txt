To test use:
.\Apply-EsxiFirewallIPs.ps1 `
    -Mode Sync `
    -VCenter 10.100.1.254 `
    -Cluster "Cluster-v4" `
    -ReferenceHost 10.100.1.20 `
    -TargetHost 10.100.1.30

.\Apply-EsxiFirewallIPs.ps1 `
    -Mode Add `
    -VCenter 10.100.1.254 `
    -Cluster "Cluster-v4" `
    -ReferenceHost 10.100.1.20 `
    -TargetHost 10.100.1.30


Apply to all hosts use:
.\Apply-EsxiFirewallIPs.ps1 `
    -Mode Sync `
    -VCenter 10.100.1.254 `
    -Cluster "Cluster-v4" `
    -ReferenceHost 10.100.1.20

For Linux after installing Powershell and VCF PowerCLI (Install-Module -Name VCF.PowerCLI -Scope CurrentUser):

pwsh ./Apply-EsxiFirewallIPs.ps1 \
    -Mode Sync \
    -VCenter 10.100.1.254 \
    -Cluster "Cluster-v4" \
    -ReferenceHost 10.100.1.20

NeverSyncRules: Commented out for future use, skips the rules specified.
<# $NeverSyncRules = @(
    "etcdClientComm",
    "etcdPeerComm"
)
#>
