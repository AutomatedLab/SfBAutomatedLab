function Start-SfBLabDeployment
{
    param
    (
        [Parameter(Mandatory)]
        [string]$TopologyFilePath,

        [Parameter(Mandatory)]
        [string]$LabName,

        [switch]$PassThru
    )

    if (-not (Test-Path -Path $TopologyFilePath))
    {
        Write-Error "The file '$TopologyFilePath' could not be found"
        return
    }
    
    if ($LabName -in (Get-Lab -List))
    {
        Write-Error "A lab with the name '$LabName' does already exist"
        return
    }

    $script = New-SfBLab -TopologyFilePath $TopologyFilePath -LabName $LabName
    
    $scriptPath = '{0}\{1}.ps1' -f (Get-LabSourcesLocation), $LabName
    Write-Host "Saving the AutomatedLab deployment script to '$scriptPath'"
    $script | Out-File -FilePath $scriptPath -Force

    if ($PassThru)
    {
        $script
    }

    Write-Host
    Write-Host 'The AutomatedLab deployment script is ready. You can either invoke it right away or modify the script to further customize your lab.' -ForegroundColor Yellow
    Write-Host "Do you want to start the deployment now? Type 'Y' to start the deplyment or any other key to stop this script: " -ForegroundColor Yellow -NoNewline
    if ((Read-Host) -eq 'y')
    {
        $script.Invoke()
    }
    else
    {
        Write-Host "OK, the AutomatedLab deplyment script is stored here: $scriptPath. You can call it whenever you want to start the lab deployment." -ForegroundColor Yellow
    }    
}

function New-SfBLab
{
    [OutputType([System.Management.Automation.ScriptBlock])]
    param(
        [Parameter(Mandatory)]
        [string]$TopologyFilePath,

        [Parameter(Mandatory)]
        [string]$LabName,
        
        [switch]$ExportOnly
    )

    if (-not (Test-Path -Path $TopologyFilePath))
    {
        Write-Error "The file '$TopologyFilePath' could not be found"
        return
    }
    
    Write-Host '-------------------------------------------------------------'
    Write-Host "Importing S4B topoligy file '$TopologyFilePath'"
    Write-Host '-------------------------------------------------------------'
    
    Import-SfBTopology -Path $TopologyFilePath -ErrorAction Stop
    $script:labName = $LabName
    $script:discoveredNetworks = @()
    
    $script:sb = New-Object System.Text.StringBuilder
    
    $script:machines = New-Object System.Collections.ArrayList
    $machines.AddRange((Get-SfBTopologyCluster | Get-SfBTopologyMachine))
    
    Add-SfBLabFundamentals
    
    Add-SfBLabInternalNetworks
    Add-SfBLabExternalNetworks
    
    Add-SfBLabDomains    
    
    Write-Host "Found $($machines.Count) machines in the topology file"
    foreach ($machine in $machines)
    {        
        $name = if ($machine.Fqdn) { $machine.Fqdn } else { $machine.ClusterFqdn }
        if ($name -like '*.*')
        {
            $name = $name.Substring(0, $name.IndexOf('.'))
        }
        $domain = $machine.Fqdn.Substring($machine.Fqdn.IndexOf('.') + 1)        

        $roles = $machine | Get-SfBMachineRoleString

        if ($roles)
        {
            Write-Host ">> Adding machine '$($machine.Fqdn)' with roles '$roles'" 
        }
        else
        {
            Write-Host ">> Adding machine '$($machine.Fqdn)'" 
        }
        
        
        $netInterfaces = @()
        $machine.NetInterface | Where-Object InterfaceSide -in 'Primary', 'Internal' | ForEach-Object { $netInterfaces += $_ }
        if ($netInterfaces.Count -eq 0)
        {
            $netInterfaces += New-Object PSObject -Property @{ 
                'InterfaceSide' = 'Internal'
            }
        }

        if ($machine.NetInterface | Where-Object InterfaceSide -in 'External')
        {
            $netInterfaces += New-Object PSObject -Property @{ 
                'InterfaceSide' = 'External'
                'InterfaceNumber' = '1'
                'IPAddress' = ($machine.NetInterface | Where-Object InterfaceSide -eq 'External').IPAddress
            }
        }

        if ($netInterfaces)
        {
            $sb.AppendLine('$netAdapter = @()') | Out-Null
            foreach ($netInterface in $netInterfaces)
            {
                $connectedSwitch = if ($netInterface.InterfaceSide -eq 'External')
                {
                    '$external'
                }
                else
                {
                    '$internal'
                }
                
                if ($netInterface.IPAddress -eq [AutomatedLab.IPAddress]::Null -or -not $netInterface.IPAddress)
                {
                    if ($connectedSwitch -like '$external')
                    {
                        $line = '$netAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch {0} -UseDhcp' -f $connectedSwitch
                    }
                    else
                    {
                        $line = '$netAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch {0}' -f $connectedSwitch
                    }
                }
                else
                {
                    $ipAddressesStrings = foreach ($ipAddress in $netInterface.IPAddress)
                    {
                        $prefix = ($discoveredNetworks | Where-Object { [AutomatedLab.IPNetwork]::Contains($_, [AutomatedLab.IPAddress]$ipAddress) }).Cidr
                        $ipAddress + '/' + $prefix
                    }
                    
                    $line = '$netAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch {0} -Ipv4Address {1}' -f $connectedSwitch, ($ipAddressesStrings -join ', ')
                }
                
                $sb.AppendLine($line) | Out-Null
            }
            
            $cluster = Get-SfBTopologyCluster -Id $machine.ClusterUniqueId | Get-SfBTopologyClusterService
            if ($cluster.RoleName -contains 'EdgeServer')
            {
                $line = 'Add-LabMachineDefinition -Name {0} -Memory 2GB -NetworkAdapter $netAdapter -OperatingSystem "Windows Server 2012 R2 SERVERDATACENTER"' -f $name, $domain, $roles
            }
            else
            {
                $line = 'Add-LabMachineDefinition -Name {0} -Memory 2GB -NetworkAdapter $netAdapter -DomainName {1}{2} -OperatingSystem "Windows Server 2012 R2 SERVERDATACENTER"' -f $name, $domain, $roles
            }
        }
        else
        {
            if ($cluster.RoleName -contains 'EdgeServer')
            {
                $line = 'Add-LabMachineDefinition -Name {0} -Memory 2GB -Network $internal -OperatingSystem "Windows Server 2012 R2 SERVERDATACENTER"' -f $name, $domain, $roles
            }
            else
            {
                $line = 'Add-LabMachineDefinition -Name {0} -Memory 2GB -Network $internal -DomainName {1}{2} -OperatingSystem "Windows Server 2012 R2 SERVERDATACENTER"' -f $name, $domain, $roles
            }
        }
        $sb.AppendLine($line ) | Out-Null
        $sb.AppendLine() | Out-Null
    }
    Write-Host

    if ($ExportOnly)
    {
        $sb.AppendLine('Export-LabDefinition -Force') | Out-Null
    }
    else
    {
        $sb.AppendLine('Install-Lab') | Out-Null
    
        $sb.AppendLine('Add-SfbClusterDnsRecords') | Out-Null
        $sb.AppendLine('Add-SfbFileShares') | Out-Null    
    
        $sb.AppendLine('Show-LabInstallationTime') | Out-Null
    }

    [scriptblock]::Create($sb.ToString())
}

function Add-SfBLabInternalNetworks
{
    $internalIps = Get-SfBTopologyCluster |
    Get-SfBTopologyMachine |
    ForEach-Object { $_.NetInterface } |
    Where-Object { ($_.InterfaceSide -eq 'Internal' -or $_.InterfaceSide -eq 'Primary') -and $_.IPAddress -ne [AutomatedLab.IPAddress]::Null } |
    Select-Object -Property IPAddress, Prefix

    $internalNetworks = foreach ($internalIp in $internalIps)
    {
        foreach ($discoveredInternalNetwork in $discoveredNetworks)
        {
            if ([AutomatedLab.IPNetwork]::Contains($discoveredInternalNetwork, [AutomatedLab.IPAddress]$internalIp.IPAddress))
            {
                Write-Host ">> Assigning prefix $($discoveredInternalNetwork.Cidr ) to IP address $($internalIp.IPAddress)"
                $internalIp.Prefix = $discoveredInternalNetwork.Cidr 
            }
        }
        
        if (-not $internalIp.Prefix)
        {
            $internalIp.Prefix = Read-Host -Prompt "The IP address $($internalIp.IPAddress) is defined. What is the subnet prefix, for example 24 for 255.255.255.0?"
            $script:discoveredNetworks += [AutomatedLab.IPNetwork]"$($internalIp.IPAddress)/$($internalIp.Prefix)"
        }

        [AutomatedLab.IPNetwork]"$($internalIp.IPAddress)/$($internalIp.Prefix)"
    }
    
    Write-Host

    $internalNetworks = $internalNetworks | Sort-Object -Property Network -Unique

    if (-not $internalNetworks)
    {
        throw 'Something seems to be wring with the defined subnets. No internal network could be found. Please review the IP addresses and prefixes.'
    }

    Write-Host 'Defining the following networks'
    $i = 1
    foreach ($network in $internalNetworks)
    {
        Write-Host (">> '{0}-{1}'. The host adapter's IP is {2}/{3}" -f $labName, $i, $network.Network, $network.Cidr)
        $line = '$internal = Add-LabVirtualNetworkDefinition -Name {0}-{1} -AddressSpace {2}/{3} -PassThru' -f $labName, $i, $network.Network, $network.Cidr
        $sb.AppendLine($line) | Out-Null
    }
    
    $sb.AppendLine() | Out-Null
    Write-Host
}

function Add-SfBLabExternalNetworks
{
    $externalIps = Get-SfBTopologyCluster |
    Get-SfBTopologyMachine |
    ForEach-Object { $_.NetInterface } |
    Where-Object { $_.InterfaceSide -eq 'External' -and $_.IPAddress -ne [AutomatedLab.IPAddress]::Null } |
    Select-Object -Property IPAddress, Prefix

    $hasExternalNetworks = [bool]$externalIps
    $externalSwitches = Get-VMSwitch -SwitchType External
    $physicalAdapters = Get-NetAdapter -Physical

    foreach ($externalIp in $externalIps)
    {
        foreach ($discoveredExternalNetwork in $discoveredNetworks)
        {
            if ([AutomatedLab.IPNetwork]::Contains($discoveredExternalNetwork, [AutomatedLab.IPAddress]$externalIp.IPAddress))
            {
                Write-Host ">> Assigning prefix $($discoveredExternalNetwork.Cidr ) to IP address $($externalIp.IPAddress)"
                $externalIp.Prefix = $discoveredExternalNetwork.Cidr
            }
        }
        
        if (-not $externalIp.Prefix)
        {
            $externalIp.Prefix = Read-Host -Prompt "The IP address $($externalIp.IPAddress) is defined. What is the subnet prefix, for example 24 for 255.255.255.0?"
            $script:discoveredNetworks += [AutomatedLab.IPNetwork]"$($externalIp.IPAddress)/$($externalIp.Prefix)"
        }
    }
    
    Write-Host

    if ($hasExternalNetworks -and $externalSwitches)
    {
        $choices = @()
        
        $i = 0
        foreach ($externalSwitch in $externalSwitches)
        {
            $choices += New-Object System.Management.Automation.Host.ChoiceDescription("&$i Existing Switch '$($externalSwitch.Name)'")
            $i++
        }
        foreach ($netAdapter in $physicalAdapters)
        {
            $choices += New-Object System.Management.Automation.Host.ChoiceDescription("&$i New Switch bridging '$($netAdapter.Name)'")
            $i++
        }
        $choices += New-Object System.Management.Automation.Host.ChoiceDescription('&Cancel')

        $result = $host.UI.PromptForChoice(
            'External Virtual Switch',
            'The topology requires an external virtual switch. There is already an external virtual switch existing. Do you want to connect this lab to the existing switch or create a new one?',
        $choices, 0)
        
        if (($result -eq $choices.Count - 1) -or $result -eq -1)
        {
            throw 'Lab deployment aborted'
        }
            
        if ($result -lt $externalSwitches.Count)
        {
            $externalSwitch = $externalSwitches[$result]
            $externalAdapter = Get-NetAdapter -Physical | Where-Object InterfaceDescription -eq $externalSwitch.NetAdapterInterfaceDescription
            $sb.AppendLine(("`$external = Add-LabVirtualNetworkDefinition -Name {0} -HyperVProperties @{{ SwitchType = 'External'; AdapterName = '{1}' }} -PassThru" -f $externalSwitch.Name, $externalAdapter.Name)) | Out-Null
                
        }
        else
        {
            $physicalAdapter = $physicalAdapters[$result - $externalSwitches.Count]
            $sb.AppendLine(("`$external = Add-LabVirtualNetworkDefinition -Name External -HyperVProperties @{{ SwitchType = 'External'; AdapterName = '{0}' }} -PassThru" -f $physicalAdapter.Name)) | Out-Null
        }
        
        $sb.AppendLine() | Out-Null
    }
    elseif ($hasExternalNetworks -and -not $externalSwitches)
    {
        $choices = @()
        
        $i = 0
        foreach ($netAdapter in $physicalAdapters)
        {
            $choices += New-Object System.Management.Automation.Host.ChoiceDescription("&$i New Switch bridging '$($netAdapter.Name)'")
            $i++
        }
        $choices += New-Object System.Management.Automation.Host.ChoiceDescription('&Cancel')

        $result = $host.UI.PromptForChoice(
            'External Virtual Switch',
            'The topology requires an external virtual switch. There is no external virtual switch existing and a new one needs to be created. Which adapter shall be used?',
        $choices, 0)
        
        if (($result -eq $choices.Count - 1) -or $result -eq -1)
        {
            throw 'Lab deployment aborted'
        }

        $physicalAdapter = $physicalAdapters[$result - $externalSwitches.Count]
        $sb.AppendLine(("`$external = Add-LabVirtualNetworkDefinition -Name External -HyperVProperties @{{ SwitchType = 'External'; AdapterName = '{0}' }} -PassThru" -f $physicalAdapter.Name)) | Out-Null
        
        $sb.AppendLine() | Out-Null
    }
}

function Add-SfBLabDomains
{
    $domains = Get-SfBTopologyActiveDirectoryDomains
    Write-Host "Domains found in the topology: $($domains)"
    
    foreach ($domain in $domains)
    {
        Write-Host "Setting default installation credentials for domain '$($domain)' machines to user 'Install' with password 'Somepass1'"
        $line = 'Add-LabDomainDefinition -Name {0} -AdminUser Install -AdminPassword Somepass1' -f $domain
        $sb.AppendLine($line) | Out-Null
    }

    Write-Host
    $i = 1
    foreach ($domain in $domains)
    {
        $numberOfDcs = Read-Host -Prompt "How many Domain Controllers do you want to have for domain '$($domain)'?"


        Write-Host "Adding domain controller 'DC$i' to domain $($domain)"
        #$line = 'Add-LabMachineDefinition -Name DC{1} -Memory 512MB -Network $internal -DomainName {0} -Roles RootDC -OperatingSystem "Windows Server 2012 R2 SERVERDATACENTER"' -f $domain, $i
        #$sb.AppendLine($line) | Out-Null
        $i++
        
        $fqdn = 'DC1.domain.local'
        $machine = $machines | Where-Object FQDN -eq $fqdn
        if ($machine)
        {
            $machine | Add-Member -Name DomainRole -MemberType NoteProperty -Value RootDC
        }
        else
        {
            $machine = New-Object PSObject -Property @{ DomainRole = 'RootDC'; FQDN = $fqdn }
            $machines.Add($machine)
        }

        <#if ($numberOfDcs -gt 1)
                {
                2..$numberOfDcs | ForEach-Object {
                Write-Host "Adding domain controller 'DC$i' to domain $($domain)"
                $line = 'Add-LabMachineDefinition -Name DC{1} -Memory 512MB -Network $internal -DomainName {0} -Roles DC -OperatingSystem "Windows Server 2012 R2 SERVERDATACENTER"' -f $domain, $i
                $sb.AppendLine($line) | Out-Null
                $i++
                }
        }#>
    }
    
    Write-Host
}

function Add-SfBLabFundamentals
{
    $sb.AppendLine(('$labName = "{0}"' -f $LabName)) | Out-Null
    $sb.AppendLine('$labSources = Get-LabSourcesLocation') | Out-Null

    $sb.AppendLine('New-LabDefinition -Name $labName -DefaultVirtualizationEngine HyperV') | Out-Null
    $sb.AppendLine('Add-LabIsoImageDefinition -Name SQLServer2014 -Path $labSources\ISOs\en_sql_server_2014_standard_edition_x64_dvd_3932034.iso') | Out-Null

    Write-Host "Setting default installation credentials for machines to user 'Install' with password 'Somepass1'"
    $sb.AppendLine('Set-LabInstallationCredential -Username Install -Password Somepass1') | Out-Null
    $sb.AppendLine() | Out-Null
    
    Write-Host
}

function Add-SfBClusterDnsRecords
{
    $clusters = Get-SfBTopologyCluster

    foreach ($cluster in $clusters)
    {
        $clusterMachines = $cluster | Get-SfBTopologyMachine
        $clusterName = $cluster.Fqdn.Substring(0, $cluster.Fqdn.IndexOf('.'))
        $clusterDnsZone = $cluster.Fqdn.Substring($cluster.Fqdn.IndexOf('.') + 1)
        $dc = Get-LabMachine -Role RootDC | Where-Object DomainName -eq $clusterDnsZone

        foreach ($clusterMachine in $clusterMachines)
        {
            $name = $clusterMachine.Fqdn.Substring(0, $clusterMachine.Fqdn.IndexOf('.'))
            $labMachine = Get-LabMachine -ComputerName $name

            $dnsCmd = 'Add-DnsServerResourceRecord -Name {0} -ZoneName {1} -IPv4Address {2} -A' -f $clusterName, $clusterDnsZone, $labMachine.IpV4Address

            Invoke-LabCommand -ActivityName AddClusterDnsRecord -ComputerName $dc -ScriptBlock ([scriptblock]::Create($dnsCmd))
        }
    }
}

function Add-SfBFileShares
{
    $cmd = {
        param(
            [Parameter(Mandatory)]
            [string]$Name
        )

        $data = mkdir c:\data -Force

        $newFolder = mkdir -Path (Join-Path -Path $data -ChildPath $name)
        New-SmbShare -Path $newFolder -Name $name -Description SfB
    }

    $fileStores = Get-SfBTopologyFileStore

    foreach ($fileStore in $fileStores)
    {
        $installedOnMachines = $fileStore.InstalledOnMachines.Substring(0, $fileStore.InstalledOnMachines.IndexOf('.'))
        Invoke-LabCommand -ActivityName NewFileStore -ComputerName $installedOnMachines -ScriptBlock $cmd -ArgumentList $fileStore.ShareName
    }
}