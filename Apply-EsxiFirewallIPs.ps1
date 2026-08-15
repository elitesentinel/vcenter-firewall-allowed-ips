param (
    [ValidateSet("Add", "Sync")]
    [string]$Mode = "Add",

    [string]$TargetHost,

    [Parameter(Mandatory = $true)]
    [string]$VCenter,

    [Parameter(Mandatory = $true)]
    [string]$Cluster,

    [Parameter(Mandatory = $true)]
    [string]$ReferenceHost
)
# ============================================================
# SETTINGS
# ============================================================

$IpFile = Join-Path $PSScriptRoot "allowed-ips.txt"

# Critical address which must remain allowed.
$RequiredIP = $VCenter

# Rules that may contain VMware/service-generated IPs.
# The script may ADD our desired IPs, but Sync will NOT delete
# existing addresses from these rules.
<# $NeverSyncRules = @(
    "etcdClientComm",
    "etcdPeerComm"
)
 #>
# ============================================================
# READ DESIRED IPs
# ============================================================

if (!(Test-Path $IpFile)) {
    throw "Cannot find $IpFile"
}

$DesiredIPs = Get-Content $IpFile |
ForEach-Object { $_.Trim() } |
Where-Object {
    $_ -and
    !$_.StartsWith("#")
} |
Select-Object -Unique

Write-Host ""
Write-Host "Desired Allowed IPs:" -ForegroundColor Cyan

$DesiredIPs | ForEach-Object {
    Write-Host "  $_"
}


# ============================================================
# SAFETY CHECK
# ============================================================

if ($RequiredIP -notin $DesiredIPs) {
    throw @"
STOPPED.

The vCenter address $RequiredIP is NOT in allowed-ips.txt.

Add it before running this script so the ESXi hosts do not
lose connectivity with vCenter.
"@
}


# ============================================================
# CONNECT TO VCENTER
# ============================================================

Write-Host ""
Write-Host "Connecting to vCenter $VCenter ..." -ForegroundColor Cyan

$Credential = Get-Credential -Message "Enter vCenter credentials"

Connect-VIServer `
    -Server $VCenter `
    -Credential $Credential

# ============================================================
# FUNCTIONS
# ============================================================

function Get-AllowedIPConfig {

    param (
        $EsxCli,
        [string]$Ruleset
    )

    $esxArgs = $EsxCli.network.firewall.ruleset.allowedip.list.CreateArgs()
    $esxArgs.rulesetid = $Ruleset

    $result = @(
        $EsxCli.network.firewall.ruleset.allowedip.list.Invoke($esxArgs)
    )

    if (!$result -or $result.Count -eq 0) {
        return [PSCustomObject]@{
            All = $false
            IPs = @()
        }
    }

    $row = $result |
    Where-Object { $_.Ruleset -eq $Ruleset } |
    Select-Object -First 1

    if (!$row) {
        $row = $result[0]
    }

    $property = $row.PSObject.Properties |
    Where-Object { $_.Name -eq "AllowedIPAddresses" } |
    Select-Object -First 1

    if (!$property) {
        throw "Could not find AllowedIPAddresses for ruleset $Ruleset"
    }

    # Handles both an array and a comma-separated value
    $ips = @(
        @($property.Value) |
        ForEach-Object { [string]$_ } |
        ForEach-Object { $_ -split ',' } |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ }
    )

    if ($ips.Count -eq 1 -and $ips[0] -eq "All") {
        return [PSCustomObject]@{
            All = $true
            IPs = @()
        }
    }

    return [PSCustomObject]@{
        All = $false
        IPs = $ips
    }
}



function Add-AllowedIP {

    param (
        $EsxCli,
        [string]$Ruleset,
        [string]$IP
    )

    $esxArgs = $EsxCli.network.firewall.ruleset.allowedip.add.CreateArgs()

    $esxArgs.rulesetid = $Ruleset
    $esxArgs.ipaddress = $IP

    $EsxCli.network.firewall.ruleset.allowedip.add.Invoke($esxArgs) |
    Out-Null
}



function Remove-AllowedIP {

    param (
        $EsxCli,
        [string]$Ruleset,
        [string]$IP
    )

    $esxArgs = $EsxCli.network.firewall.ruleset.allowedip.remove.CreateArgs()

    $esxArgs.rulesetid = $Ruleset
    $esxArgs.ipaddress = $IP

    $EsxCli.network.firewall.ruleset.allowedip.remove.Invoke($esxArgs) |
    Out-Null
}



function Set-Restricted {

    param (
        $EsxCli,
        [string]$Ruleset
    )

    $esxArgs = $EsxCli.network.firewall.ruleset.set.CreateArgs()

    $esxArgs.rulesetid = $Ruleset
    $esxArgs.allowedall = $false

    $EsxCli.network.firewall.ruleset.set.Invoke($esxArgs) |
    Out-Null
}



# ============================================================
# GET REFERENCE HOST
# ============================================================

$ReferenceVMHost = Get-VMHost -Name $ReferenceHost

if (!$ReferenceVMHost) {
    throw "Reference host $ReferenceHost not found."
}

$ReferenceEsxCli = Get-EsxCli `
    -VMHost $ReferenceVMHost `
    -V2


# ============================================================
# DETERMINE RULESETS FROM REFERENCE HOST
# ============================================================

$ReferenceRules = @(
    $ReferenceEsxCli.network.firewall.ruleset.list.Invoke()
)

$ManagedRules = @()

Write-Host ""
Write-Host "Checking rulesets on $ReferenceHost ..." -ForegroundColor Cyan


foreach ($rule in $ReferenceRules) {

    $ruleName = $rule.Name

    # Find "Allowed IP configurable" dynamically because
    # property naming can vary between PowerCLI versions.

    $configProperty = $rule.PSObject.Properties |
    Where-Object {
        $_.Name -match 'Allowed.*IP.*Configurable'
    } |
    Select-Object -First 1


    if ($configProperty) {

        $isConfigurable = [System.Convert]::ToBoolean(
            $configProperty.Value
        )

        if (!$isConfigurable) {

            Write-Host "SKIP  $ruleName (system managed)" `
                -ForegroundColor DarkGray

            continue
        }
    }


    # Manage every firewall ruleset whose Allowed IP list
    # is configurable, regardless of whether the ruleset
    # is enabled, disabled, or currently allows all IPs.

    try {

        # Verify that the Allowed-IP command exists/works
        # for this ruleset.
        $cfg = Get-AllowedIPConfig `
            -EsxCli $ReferenceEsxCli `
            -Ruleset $ruleName

        $ManagedRules += $ruleName

        if ($cfg.All) {
            Write-Host "USE   $ruleName (currently allows All)" `
                -ForegroundColor Yellow
        }
        else {
            Write-Host "USE   $ruleName" `
                -ForegroundColor Green
        }
    }
    catch {

        Write-Host "SKIP  $ruleName ($($_.Exception.Message))" `
            -ForegroundColor Yellow
    }
}


# ============================================================
# GET ALL HOSTS IN CLUSTER
# ============================================================

if ($TargetHost) {

    Write-Host "TEST MODE: Only processing $TargetHost" `
        -ForegroundColor Yellow

    $Hosts = @(
        Get-VMHost -Name $TargetHost -ErrorAction Stop
    )
}
else {

    $Hosts = @(
        Get-Cluster -Name $Cluster |
        Get-VMHost |
        Sort-Object Name
    )
}

Write-Host ""
Write-Host "Cluster: $Cluster" -ForegroundColor Cyan
Write-Host "Hosts:   $($Hosts.Count)"
Write-Host "Mode:    $Mode"

Write-Host ""
Write-Host "Rulesets to update:" -ForegroundColor Cyan

$ManagedRules | ForEach-Object {
    Write-Host "  $_"
}


# ============================================================
# APPLY CONFIGURATION
# ============================================================

foreach ($VMHost in $Hosts) {

    Write-Host ""
    Write-Host "==========================================" `
        -ForegroundColor Cyan

    Write-Host "HOST: $($VMHost.Name)" `
        -ForegroundColor Cyan

    Write-Host "==========================================" `
        -ForegroundColor Cyan


    $EsxCli = Get-EsxCli `
        -VMHost $VMHost `
        -V2


    $HostRules = @(
        $EsxCli.network.firewall.ruleset.list.Invoke()
    )


    foreach ($RuleName in $ManagedRules) {

        $TargetRule = $HostRules |
        Where-Object {
            $_.Name -eq $RuleName
        } |
        Select-Object -First 1


        if (!$TargetRule) {

            Write-Host "SKIP  $RuleName - not present" `
                -ForegroundColor DarkGray

            continue
        }


        $configProperty = $TargetRule.PSObject.Properties |
        Where-Object {
            $_.Name -match 'Allowed.*IP.*Configurable'
        } |
        Select-Object -First 1


        if ($configProperty) {

            $isConfigurable = [System.Convert]::ToBoolean(
                $configProperty.Value
            )

            if (!$isConfigurable) {

                Write-Host "SKIP  $RuleName - system managed" `
                    -ForegroundColor DarkGray

                continue
            }
        }


        try {

            # ----------------------------------------------
            # READ CURRENT CONFIGURATION
            # ----------------------------------------------

            $Current = Get-AllowedIPConfig `
                -EsxCli $EsxCli `
                -Ruleset $RuleName


            # ----------------------------------------------
            # IF IT CURRENTLY ALLOWS ALL,
            # FIRST SWITCH TO THE ALLOWED-IP LIST
            # ----------------------------------------------


            if ($Current.All -and $RuleName -in $NeverSyncRules) {

                Write-Host " KEEP  $RuleName - currently Allow All / protected" `
                    -ForegroundColor Magenta

                continue
            }

            if ($Current.All) {

                Set-Restricted `
                    -EsxCli $EsxCli `
                    -Ruleset $RuleName

                Write-Host " RESTRICT $RuleName" `
                    -ForegroundColor Yellow

                # Re-read after changing allowed-all
                $Current = Get-AllowedIPConfig `
                    -EsxCli $EsxCli `
                    -Ruleset $RuleName
            }


            # ----------------------------------------------
            # FIND MISSING IPs
            # ----------------------------------------------

            $MissingIPs = @(
                $DesiredIPs | Where-Object {
                    $_ -notin $Current.IPs
                }
            )


            # ----------------------------------------------
            # ADD MISSING IPs
            # ----------------------------------------------

            foreach ($IP in $MissingIPs) {

                try {

                    Add-AllowedIP `
                        -EsxCli $EsxCli `
                        -Ruleset $RuleName `
                        -IP $IP

                    Write-Host " ADD  $RuleName -> $IP" `
                        -ForegroundColor Green
                }
                catch {

                    # A duplicate should NOT abort the entire ruleset.
                    if ($_.Exception.Message -match "already exist") {

                        Write-Host " EXISTS $RuleName -> $IP" `
                            -ForegroundColor DarkGray
                    }
                    else {
                        throw
                    }
                }
            }


            # ----------------------------------------------
            # SYNC: REMOVE EVERYTHING NOT IN TXT FILE
            # ----------------------------------------------

            if ($Mode -eq "Sync") {

                if ($RuleName -in $NeverSyncRules) {

                    Write-Host " KEEP  $RuleName - service-managed IPs preserved" `
                        -ForegroundColor Magenta
                }
                else {

                    # Re-read after additions
                    $Current = Get-AllowedIPConfig `
                        -EsxCli $EsxCli `
                        -Ruleset $RuleName

                    foreach ($ExistingIP in $Current.IPs) {

                        if ($ExistingIP -notin $DesiredIPs) {

                            Remove-AllowedIP `
                                -EsxCli $EsxCli `
                                -Ruleset $RuleName `
                                -IP $ExistingIP

                            Write-Host " DEL  $RuleName -> $ExistingIP" `
                                -ForegroundColor Yellow
                        }
                    }
                }
            }


            Write-Host " OK   $RuleName" `
                -ForegroundColor Green
        }
        catch {

            Write-Warning "$($VMHost.Name) / $RuleName : $($_.Exception.Message)"
        }
    }


    # Refresh firewall after changes.

    try {
        $EsxCli.network.firewall.refresh.Invoke() | Out-Null
    }
    catch {
        Write-Warning "Could not refresh firewall on $($VMHost.Name)"
    }
}


Write-Host ""
Write-Host "==========================================" `
    -ForegroundColor Green

Write-Host "FINISHED" `
    -ForegroundColor Green

Write-Host "==========================================" `
    -ForegroundColor Green