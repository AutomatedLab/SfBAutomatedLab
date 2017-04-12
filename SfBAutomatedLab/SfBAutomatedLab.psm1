function Start-SfBLabDeployment
{
    param
    (
        [Parameter(Mandatory)]
        [string]$TopologyFilePath,

        [Parameter(Mandatory)]
        [string]$LabName,
        
        [string]$OutputScriptPath
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

    if (-not $OutputScriptPath)
    {
        $OutputScriptPath= '{0}\{1}.ps1' -f (Get-LabSourcesLocation), $LabName  
    }
  
    Write-Host "Saving the AutomatedLab deployment script to '$OutputScriptPath'"
    New-SfBLab -TopologyFilePath $TopologyFilePath -LabName $LabName -OutputScriptPath $OutputScriptPath

    Write-Host
    Write-Host 'The AutomatedLab deployment script is ready. You can either invoke it right away or modify the script to further customize your lab.' -ForegroundColor Yellow
    Write-Host "Do you want to start the deployment now? Type 'Y' to start the deployment or any other key to stop this script: " -ForegroundColor Yellow -NoNewline
    
    $startScript = if ($global:SfBALTestMode -eq 2)
    {
        $true
    }
    else
    {
        if ((Read-Host) -eq 'y')
        {
            $true    
        }
    }

    if ($startScript)
    {
        Invoke-SfBLabScript
    }
    else
    {
        Write-Host "OK, the AutomatedLab deployment script is stored here: $scriptPath. You can call it whenever you want to start the lab deployment." -ForegroundColor Yellow
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
        
        [Parameter(Mandatory)]
        [string]$OutputScriptPath,
        
        [switch]$ExportOnly,
        
        [switch]$PassThru
    )

    if (-not (Test-Path -Path $TopologyFilePath))
    {
        Write-Error "The file '$TopologyFilePath' could not be found"
        return
    }
    
    Write-Host '-------------------------------------------------------------'
    Write-Host 'Checking for prerequisites...' -NoNewline
    
    $testPrerequisites = Test-SfBLabRequirements
    if (-not $testPrerequisites)
    { Write-Host 'NOT FOUND' } else { Write-Host 'found' }
    Write-Host '-------------------------------------------------------------'
    
    if (-not $testPrerequisites)
    {
        try
        {
            Set-SfBLabRequirements -ErrorAction Stop
        }
        catch
        {
            throw "The cmdlet 'Set-SfBLabRequirements' did not complete. Please finish this task first."
        }
    }
    else
    {
        $script:prerequisites = Get-SfBLabRequirements -ErrorAction Stop
    }
    
    Write-Host '-------------------------------------------------------------'
    Write-Host "Importing SfB topoloigy file '$TopologyFilePath'"
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

    Add-SfBLabExchangeServers
    
    Add-SfBLabOfficeClients
    
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

            $os = if ($machine.IsClient)
            { $PSCmdlet.MyInvocation.MyCommand.Module.PrivateData.OS.Client }
            else
            { $PSCmdlet.MyInvocation.MyCommand.Module.PrivateData.OS.Server }

            if (($machine.Roles -band [SfBAutomatedLab.SfBServerRole]::Edge) -eq [SfBAutomatedLab.SfBServerRole]::Edge)
            {
                $line = 'Add-LabMachineDefinition -Name {0} -Memory 2GB -NetworkAdapter $netAdapter -OperatingSystem "{1}" -Notes @{{ SfBRoles = "{2}" }}' -f $name, $os, $machine.Roles
            }
            elseif(($machine.Roles -band [SfBAutomatedLab.SfBServerRole]::SqlServer) -eq [SfBAutomatedLab.SfBServerRole]::SqlServer -and [bool]($machine.PSobject.Properties.Name -eq "AlwaysOnPartner"))
            {				
                $line = 'Add-LabMachineDefinition -Name {0} -Memory 2GB -NetworkAdapter $netAdapter -DomainName {1}{2} -OperatingSystem "{3}" -Notes @{{ SfBRoles = "{4}"; AlwaysOnPartner = "{5}" }}' -f $name, $domain, $roles, $os, $machine.Roles,$machine.AlwaysOnPartner
            }
            else
            {
                $line = 'Add-LabMachineDefinition -Name {0} -Memory 2GB -NetworkAdapter $netAdapter -DomainName {1}{2} -OperatingSystem "{3}" -Notes @{{ SfBRoles = "{4}" }}' -f $name, $domain, $roles, $os, $machine.Roles
            }
        }
        else
        {
            if ($machine.IsEdgeServer)
            {
                $line = 'Add-LabMachineDefinition -Name {0} -Memory 2GB -Network $internal -OperatingSystem "{1}" -Notes @{{ SfBRoles = "{2}" }}' -f $name, $os, $machine.Roles
            }
            elseif(($machine.Roles -band [SfBAutomatedLab.SfBServerRole]::SqlServer) -eq [SfBAutomatedLab.SfBServerRole]::SqlServer -and [bool]($machine.PSobject.Properties.Name -eq "AlwaysOnPartner"))
            {				
                $line = 'Add-LabMachineDefinition -Name {0} -Memory 2GB -Network $internal -DomainName {1}{2} -OperatingSystem "{3}" -Notes @{{ SfBRoles = "{4}"; AlwaysOnPartner = "{5}" }}' -f $name, $domain, $roles, $os, $machine.Roles,$machine.AlwaysOnPartner
            }
            else
            {
                $line = 'Add-LabMachineDefinition -Name {0} -Memory 2GB -Network $internal -DomainName {1}{2} -OperatingSystem "{3}" -Notes @{{ SfBRoles = "{4}" }}' -f $name, $domain, $roles, $os, $machine.Roles
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
        
        $sb.AppendLine("Import-SfBTopology -Path '$((Get-SfBTopology).Path)'") | Out-Null
        
        $sb.AppendLine('Add-SfbClusterDnsRecords') | Out-Null
        $sb.AppendLine('Add-SfBEdgeServerDnsRecords') | Out-Null		

        $sb.AppendLine('Add-SfbFileShares') | Out-Null

        $sb.AppendLine('Install-SfBLabRequirements') | Out-Null

        $sb.AppendLine('Install-SfbLabActiveDirectory') | Out-Null

        $sb.AppendLine('Install-SfbLabSfbComponents') | Out-Null
    
        $sb.AppendLine('Show-LabDeploymentSummary -Detailed') | Out-Null
    }

    [scriptblock]::Create($sb.ToString()) | Out-File -FilePath $OutputScriptPath -Width 5000
    $script:scriptFilePath = $OutputScriptPath
    Write-Host
    Write-Host "Script for AutomatedLab stored in '$scriptFilePath'"
    
    Write-Host
    Write-Host '############################################################################'
    Write-Host '# The script to deploy the SfB lab using AutomatedLab is completed         #'
    Write-Host '# Please alter the script if required and call Invoke-SfBLabScript then    #'
    Write-Host '# The next steps are:                                                      #'
    Write-Host '# - Call Invoke-SfBLabScript (this may take one or two hours)              #'
    Write-Host '# - Call Install-SfbLabSfbComponents (this may take an hour)               #'
    Write-Host '############################################################################'
    
    if ($PassThru)
    {
        [scriptblock]::Create($sb.ToString())
    }
}

function Install-SfBLabRequirements
{
    if (-not (Get-Lab))
    {
        Write-Error "Lab not imported. Use 'Import-Lab' first"
        return
    }
    if (-not $prerequisites) { $script:prerequisites = Get-SfBLabRequirements -ErrorAction Stop }
    
    $frontendServers = Get-LabMachine | Where-Object { $_.Notes.SfBRoles -like '*FrontEnd*' }
    $edgeServers = Get-LabMachine | Where-Object { $_.Notes.SfBRoles -like '*Edge*' }
    $wacServers = Get-LabMachine | Where-Object { $_.Notes.SfBRoles -like '*WacService*' }
    
    Write-Host "Installing required features on Frontend Servers"
    Install-LabWindowsFeature -ComputerName $frontendServers -FeatureName NET-Framework-Core, RSAT-ADDS, Windows-Identity-Foundation, Web-Server, Web-Static-Content, Web-Default-Doc, Web-Http-Errors, Web-Dir-Browsing, Web-Asp-Net, Web-Net-Ext, Web-ISAPI-Ext, Web-ISAPI-Filter, Web-Http-Logging, Web-Log-Libraries, Web-Request-Monitor, Web-Http-Tracing, Web-Basic-Auth, Web-Windows-Auth, Web-Client-Auth, Web-Filtering, Web-Stat-Compression, Web-Dyn-Compression, NET-WCF-HTTP-Activation45, Web-Asp-Net45, Web-Mgmt-Tools, Web-Scripting-Tools, Web-Mgmt-Compat, Server-Media-Foundation, BITS -NoDisplay
    Write-Host "Installing required features on Edge Servers"
    Install-LabWindowsFeature -ComputerName $edgeServers -FeatureName RSAT-ADDS, Web-Server, Web-Static-Content, Web-Default-Doc, Web-Http-Errors, Web-Asp-Net, Web-Net-Ext, Web-ISAPI-Ext, Web-ISAPI-Filter, Web-Http-Logging, Web-Log-Libraries, Web-Request-Monitor, Web-Http-Tracing, Web-Basic-Auth, Web-Windows-Auth, Web-Client-Auth, Web-Filtering, Web-Stat-Compression, NET-WCF-HTTP-Activation45, Web-Asp-Net45, Web-Scripting-Tools, Web-Mgmt-Compat, Desktop-Experience, Telnet-Client -NoDisplay
    Write-Host "Installing required features on Office Online Servers"
    Install-LabWindowsFeature -ComputerName $wacServers -FeatureName Web-Server, Web-Mgmt-Tools, Web-Mgmt-Console, Web-WebServer, Web-Common-Http, Web-Default-Doc, Web-Static-Content, Web-Performance, Web-Stat-Compression, Web-Dyn-Compression, Web-Security, Web-Filtering, Web-Windows-Auth, Web-App-Dev, Web-Net-Ext45, Web-Asp-Net45, Web-ISAPI-Ext, Web-ISAPI-Filter, Web-Includes, InkandHandwritingServices  -NoDisplay
    Write-Host "Installing Windows features completed"
    
    Restart-LabVM -ComputerName $wacServers -Wait
    
    Write-Host
    
    foreach ($requiredWindowsFix in $prerequisites.RequiredWindowsFixes.GetEnumerator())
    {
        $jobs = @()
        Write-Host "Installing required fix on Frontend Servers '$($requiredWindowsFix.Key)' on Frontend Servers"
        $jobs += Install-LabSoftwarePackage -ComputerName $frontendServers -Path $requiredWindowsFix.Value -CommandLine /quiet -AsJob -PassThru
        
        Write-Host "Installing required fix on Frontend Servers '$($requiredWindowsFix.Key)' on Edge Servers"
        $jobs += Install-LabSoftwarePackage -ComputerName $edgeServers -Path $requiredWindowsFix.Value -CommandLine /quiet -AsJob -PassThru
        
        Write-Host "Installing required fix on Frontend Servers '$($requiredWindowsFix.Key)' on Office Online Servers"
        $jobs += Install-LabSoftwarePackage -ComputerName $wacServers -Path $requiredWindowsFix.Value -CommandLine /quiet -AsJob -PassThru
        
        $jobs | Wait-Job | Out-Null
        
        Write-Host "Installation of '$requiredWindowsFix' finished"
    }
    Write-Host
    
    Write-Host 'Installing SilverLight on Frontend and Edge Servers...'
    
    $silverLightDownloadUrl = $PSCmdlet.MyInvocation.MyCommand.Module.PrivateData.DownloadUrls.SilverLight
    $silverLightPath = "$labSources\SoftwarePackages\Silverlight_x64.exe"
    Get-LabInternetFile -Uri $silverLightDownloadUrl -Path $silverLightPath
    
    $jobs = @()
    Install-LabSoftwarePackage -Path $SilverLightPath -CommandLine '/q /doNotRequireDRMPrompt /ignorewarnings' -ComputerName $edgeServers -AsJob -PassThru
    Install-LabSoftwarePackage -Path $SilverLightPath -CommandLine '/q /doNotRequireDRMPrompt /ignorewarnings' -ComputerName $frontendServers -AsJob -PassThru
    $jobs | Wait-Job | Out-Null
    
    Write-Host 'finished installing SilverLight on Frontend and Edge Servers'
    
    Write-Host "Installing Office Online Server on '$($wacServers.Name -join "', '")'"
    $drive = Mount-LabIsoImage -ComputerName $wacServers -IsoPath $prerequisites.ISOs.OfficeOnline2016Iso -PassThru -SupressOutput
    Install-LabSoftwarePackage -ComputerName $wacServers -LocalPath "$($drive.DriveLetter)\setup.exe" -CommandLine "/config $($drive.DriveLetter)\Files\SetupSilent\config.xml" -UseShellExecute -Timeout 30 -NoDisplay
    Dismount-LabIsoImage -ComputerName $wacServers -SupressOutput
    
    Write-Host "Installing .net 3.5 on all lab machines"
    $machines = Get-LabMachine
    Install-LabWindowsFeature -ComputerName $machines -FeatureName NET-Framework-Features -IncludeAllSubFeature -AsJob -PassThru | Wait-Job | Out-Null
}

function Install-SfBLabActiveDirectory
{
    if (-not (Get-Lab))
    {
        Write-Error "Lab in not imported. Use 'Import-Lab' first"
        return
    }
    if (-not $prerequisites) { $script:prerequisites = Get-SfBLabRequirements -ErrorAction Stop }
    
    $rootDc = Get-LabMachine -Role RootDC
    
    Write-Host "Installing SfB Management Tools on '$rootDc'"
    $drive = Mount-LabIsoImage -ComputerName $rootDc -IsoPath $prerequisites.ISOs.SfB2015Iso -PassThru -SupressOutput
    Install-LabSoftwarePackage -ComputerName $rootDc -LocalPath "$($drive.DriveLetter)\Setup\amd64\Setup.exe" -CommandLine /bootstrapcore -Timeout 30 -UseShellExecute -NoDisplay
    Dismount-LabIsoImage -ComputerName $rootDc -SupressOutput

    #The existing session must be removed to use the newly installed module
    Remove-LabPSSession -ComputerName $rootDc

    Write-Host
    Write-Host "Preparing AD Schema"
    Invoke-LabCommand -ComputerName $rootDc -ScriptBlock { Install-CSAdServerSchema -Confirm:$false -Report C:\SfBSchemaPrep.html } -NoDisplay

    Write-Host "Preparing AD Forest"
    Invoke-LabCommand -ComputerName $rootDc -ScriptBlock { Enable-CSAdForest -Confirm:$false -Report C:\SfBForestPrep.html } -NoDisplay

    Write-Host "Preparing AD Domain"
    Invoke-LabCommand -ComputerName $rootDc -ScriptBlock { Enable-CSAdDomain -Confirm:$false -Report C:\SfBDomainPrep.html } -NoDisplay

    Write-Host "Adding Install user to CSAdministrators"
    $installUser = ((Get-Lab).Domains | Where-Object Name -eq $rootDc.DomainName).Administrator.UserName
    Invoke-LabCommand -ComputerName $rootDc -ScriptBlock { Get-ADGroup CSAdministrator | Add-ADGroupMember -Members $installUser } -Variable (Get-Variable -Name installUser) -NoDisplay

    #TODO: Creating DNS entries

    Write-Host "AD Preparations finished"
    Write-Host
}

function Install-SfbLabSfbComponents
{
    if (-not (Get-Lab))
    {
        Write-Error "Lab in not imported. Use 'Import-Lab' first"
        return
    }
    if (-not $prerequisites) { $script:prerequisites = Get-SfBLabRequirements -ErrorAction Stop }
    
    $lab = Get-Lab
    $frontEndServers = Get-LabMachine | Where-Object { $_.Notes.SfBRoles -like '*frontend*' }
    $databaseServers = Get-LabMachine | Where-Object { $_.Notes.SfBRoles -like '*SqlServer*'} | Sort-Object -Property Name
    $1stFrontendServer = $frontEndServers | Select-Object -First 1
    $firstDbServer = $databaseServers | Select-Object -First 1

    Write-Host "Restarting machine '$($frontEndServers -join ',')'..." -NoNewline
    Restart-LabVM -ComputerName $frontEndServers -Wait
    Write-Host 'done'
    
    Write-Host "Installing SfB Management Tools on '$1stFrontendServer'"
    $drive = Mount-LabIsoImage -ComputerName $1stFrontendServer -IsoPath $prerequisites.ISOs.SfB2015Iso -PassThru -SupressOutput
    
    Write-Host "Calling SfB 'setup.exe /bootstrapcore' on '$1stFrontendServer'"
    Install-LabSoftwarePackage -ComputerName $1stFrontendServer -LocalPath "$($drive.DriveLetter)\Setup\amd64\Setup.exe" -CommandLine /bootstrapcore -UseShellExecute -Timeout 30 -NoDisplay
    
    Write-Host "Calling SfB 'admintools.msi' on '$1stFrontendServer'"
    Install-LabSoftwarePackage -ComputerName $1stFrontendServer -LocalPath C:\Windows\System32\msiexec.exe -CommandLine "/i $($drive.DriveLetter)\Setup\amd64\Setup\admintools.msi ADDLOCAL=Feature_AdminTools REBOOT=ReallySuppress /qb! /L*v C:\Feature_AdminTools.log INSTALLDIR=`"C:\Program Files\Skype for Business Server 2015\`"" -NoDisplay

    Write-Host "Calling SfB 'setup.exe /bootstraplocalmgmt' on '$1stFrontendServer'..."
    Install-LabSoftwarePackage -ComputerName $1stFrontendServer -LocalPath "$($drive.DriveLetter)\Setup\amd64\Setup.exe" -CommandLine /bootstraplocalmgmt -UseShellExecute -Timeout 30 -NoDisplay
    Write-Host
    
    Copy-LabFileItem -Path $lab.Notes.SfBTopologyPath -ComputerName $1stFrontendServer
    Write-Host "SfB Topology copied to '$1stFrontendServer' (C:\)"

    Dismount-LabIsoImage -ComputerName $1stFrontendServer -SupressOutput

    Write-Host "Removing PSSessions in order to use the newly installed modules"
    Remove-LabPSSession -ComputerName $1stFrontendServer
    
    Write-Host "Calling 'Install-CsDatabase'..." -NoNewline
    Invoke-LabCommand -ComputerName $1stFrontendServer -ScriptBlock { Install-CsDatabase -CentralManagementDatabase -SqlServerFqdn ($args[0]) } -ArgumentList $firstDbServer.Fqdn
    Write-Host 'done'
    
    Write-Host "Calling 'Set-CsConfigurationStoreLocation'..." -NoNewline
    Invoke-LabCommand -ComputerName $1stFrontendServer -ScriptBlock { Set-CsConfigurationStoreLocation -SqlServerFqdn ($args[0]) } -ArgumentList $firstDbServer.Fqdn
    Write-Host 'done'

    Write-Host
    Write-Host '############################################################################'
    Write-Host '# SfBAutomatedLab has created the following based on the given topology    #'
    Write-Host '# - created all virtual machines                                           #'
    Write-Host '# - installed all required features and hotfixes                           #'
    Write-Host '# - created DNS records                                                    #'
    Write-Host '# - created file shares                                                    #'
    Write-Host '# - installed Office Online Server                                         #'
    Write-Host '# - prepared AD forest and domain                                          #'
    Write-Host '# - created SQL database                                                   #'
    Write-Host '# The next steps are:                                                      #'
    Write-Host '# - Manually publish the SfB topology on the 1st frontend server using the #'
    Write-Host '#   Topology Builder. The topology is stored in c:\ on the 1st Frontned.   #'
    Write-Host '############################################################################'
    Write-Host '# Press enter to continue the deployment process after manually            #'
    Write-Host '# publishing the topology or press  CTRL + C to exit                       #'    
    Write-Host '############################################################################'
    Read-Host | Out-Null
    Write-Host
    Write-Host "SfbAutomatedLab is continuing the deployment..."
    Write-Host

    foreach ($frontEndServer in $frontEndServers)
    {
        $drive = Mount-LabIsoImage -ComputerName $frontEndServer -IsoPath $prerequisites.ISOs.SfB2015Iso -PassThru -SupressOutput

        Write-Host "Calling SfB 'setup.exe /bootstrapcore' on '$frontEndServer'"
        Install-LabSoftwarePackage -ComputerName $frontEndServer -LocalPath "$($drive.DriveLetter)\Setup\amd64\Setup.exe" -CommandLine /bootstrapcore -UseShellExecute -Timeout 30 -NoDisplay
        
        Write-Host "Calling SfB 'setup.exe /bootstraplocalmgmt' on '$frontEndServer'..."
        Install-LabSoftwarePackage -ComputerName $frontEndServer -LocalPath "$($drive.DriveLetter)\Setup\amd64\Setup.exe" -CommandLine /bootstraplocalmgmt -UseShellExecute -Timeout 30 -NoDisplay
    
        #The existing session must be removed to use the newly installed module
        Remove-LabPSSession -ComputerName $frontEndServer
    
        Write-Host "Calling 'Export-CsConfiguration' on '$frontEndServer'"
        Invoke-LabCommand -ComputerName $frontEndServer -ScriptBlock { Export-CsConfiguration -FileName C:\CsConfigData.zip } -NoDisplay
        Write-Host "Calling 'Import-CSConfiguration' on '$frontEndServer'"
        Invoke-LabCommand -ComputerName $frontEndServer -ScriptBlock { Import-CSConfiguration -FileName C:\CsConfigData.zip -LocalStore } -NoDisplay
        Write-Host "Calling 'Enable-CSReplica' on '$frontEndServer'"
        Invoke-LabCommand -ComputerName $frontEndServer -ScriptBlock { Enable-CSReplica -Confirm:$false -Report C:\Enable-CSReplica.html }

        Write-Host "Calling SfB 'setup.exe /bootstrap' on '$frontEndServer'..." -NoNewline
        Install-LabSoftwarePackage -ComputerName $frontEndServer -LocalPath "$($drive.DriveLetter)\Setup\amd64\Setup.exe" -CommandLine /bootstrap -UseShellExecute -Timeout 30 -NoDisplay -PassThru
        Write-Host 'done'
    
        Dismount-LabIsoImage -ComputerName $frontEndServer -SupressOutput
        
        Restart-LabVM -ComputerName $frontEndServer -Wait
        
        Write-Host "Requesting and assigning default certificate on '$frontEndServer'"
        $ca = Get-LabIssuingCA -DomainName $frontEndServer.DomainName
        Invoke-LabCommand -ComputerName $frontEndServer -ScriptBlock {
            $cert = Request-CSCertificate -New -Type Default,WebServicesInternal,WebServicesExternal -CA $args[0] -FriendlyName "Skype for Business Server 2015 Default certificate" -KeySize 2048 -PrivateKeyExportable $false -Organization "NA" -OU "NA" -DomainName "sip.sipdomain.com" -AllSipDomain -Report C:\Request-CSCertificateDefault.html
            Set-CSCertificate -Type Default,WebServicesInternal,WebServicesExternal -Thumbprint $cert.Thumbprint -Confirm:$false -Report C:\Set-CSCertificateDefault.html
        } -ArgumentList $ca.CaPath -PassThru -NoDisplay
        
        Write-Host "Requesting and assigning OAuth certificate on '$frontEndServer'"
        Invoke-LabCommand -ComputerName $frontEndServer -ScriptBlock {
            $cert = Request-CSCertificate -New -Type OAuthTokenIssuer -CA $args[0] -FriendlyName "Skype for Business Server 2015 OAuthTokenIssuer" -KeySize 2048 -PrivateKeyExportable $true -AllSipDomain -Report C:\Request-CSCertificateOAuth.html
            Set-CSCertificate -Identity Global -Type OAuthTokenIssuer -Thumbprint $cert.Thumbprint -Confirm:$false -Report C:\Set-CSCertificateOAuth.html
        } -ArgumentList $ca.CaPath -PassThru -NoDisplay
    }
}

function Start-SfbLabPool
{
    $lab = Get-Lab -ErrorAction SilentlyContinue
    if (-not $lab)
    {
        Write-Error "Lab in not imported. Use 'Import-Lab' first"
        return
    }
    if (-not $prerequisites) { $script:prerequisites = Get-SfBLabRequirements -ErrorAction Stop }
    
    Import-SfBTopology -Path $lab.Notes.SfBTopologyPath

    $frontendServers = Get-LabMachine | Where-Object { $_.Notes.SfBRoles -like '*frontend*' }
    $1stFrontendServer = $frontendServers | Select-Object -First 1
    $frontendPool = Get-SfBTopologyCluster | Where-Object { ($_ | Get-SfBTopologyClusterService).RoleName -eq 'UserServices' }
    
    #Reset-CsPoolRegistrarState -PoolFqdn pool.domain.local -ResetType FullReset

    Invoke-LabCommand -ActivityName 'Setting Sfb services startup type to manual' -ComputerName $frontendServers -ScriptBlock { Get-Service master, fta, rtc* | Set-Service -StartupType Manual }
    
    Get-SfBTopologyCluster | Select-Object -First 1 | Get-SfBTopologyMachine | Select-Object -ExpandProperty ClusterFqdn -Unique | ForEach-Object {
    
        Write-Host "Starting Pool '$_'"

        Invoke-LabCommand -ComputerName $1stFrontendServer -ScriptBlock { Start-CsPool -PoolFqdn $args[0] -Confirm:$false } -ArgumentList $frontendPool.Fqdn

    }
}

function Invoke-SfBLabScript
{
    if (-not $script:scriptFilePath)
    {
        Write-Error "No SfB Install script for AutomatedLab created yet. Use the cmdlet 'New-SfBLab' first"
        return
    }
    
    &$script:scriptFilePath
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
            if ($global:SfBALTestMode -gt 0)
            {
                $internalIp.Prefix = 24
            }
            else
            {
                $internalIp.Prefix = Read-Host -Prompt "The IP address $($internalIp.IPAddress) is defined. What is the subnet prefix, for example 24 for 255.255.255.0?"
            }
            $script:discoveredNetworks += [AutomatedLab.IPNetwork]"$($internalIp.IPAddress)/$($internalIp.Prefix)"
        }

        [AutomatedLab.IPNetwork]"$($internalIp.IPAddress)/$($internalIp.Prefix)"
    }
    
    Write-Host

    $internalNetworks = $internalNetworks | Sort-Object -Property Network -Unique

    if (-not $internalNetworks)
    {
        Write-Host 'No IP addresses found in the topology to derive an IP network. AutomatedLab will auto-generate networks.'
    }

    Write-Host 'Defining the following networks'
    $i = 1
    if ($internalNetworks)
    {
        foreach ($network in $internalNetworks)
        {
            Write-Host (">> '{0}-{1}'. The host adapter's IP is {2}/{3}" -f $labName, $i, $network.Network, $network.Cidr)
            $line = '$internal = Add-LabVirtualNetworkDefinition -Name "{0}-{1}" -AddressSpace {2}/{3} -PassThru' -f $labName, $i, $network.Network, $network.Cidr
            $sb.AppendLine($line) | Out-Null
        }
    }
    else
    {
        Write-Host (">> '{0}-1'. The host adapter's IP is {1}/{2}" -f $labName, 'auto', 'auto')
        $line = '$internal = Add-LabVirtualNetworkDefinition -Name "{0}-1" -PassThru' -f $labName
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
            if ($global:SfBALTestMode -gt 0)
            {
                $externalIp.Prefix = 24
            }
            else
            {
                $externalIp.Prefix = Read-Host -Prompt "The IP address $($externalIp.IPAddress) is defined. What is the subnet prefix, for example 24 for 255.255.255.0?"
            }
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
        
        Write-Host "You have choose option '$($choices[$result].Label.Substring(1))'"
        Write-Host
            
        if ($result -lt $externalSwitches.Count)
        {
            $externalSwitch = $externalSwitches[$result]
            $externalAdapter = Get-NetAdapter -Physical | Where-Object InterfaceDescription -eq $externalSwitch.NetAdapterInterfaceDescription
            $sb.AppendLine(("`$external = Add-LabVirtualNetworkDefinition -Name '{0}' -HyperVProperties @{{ SwitchType = 'External'; AdapterName = '{1}' }} -PassThru" -f $externalSwitch.Name, $externalAdapter.Name)) | Out-Null
                
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
        $numberOfDcs = if ($global:SfBALTestMode -gt 0)
        {
            1
        }
        else
        {
            Read-Host -Prompt "How many Domain Controllers do you want to have for domain '$domain'?"
        }
        
        Write-Host "You have chosen $numberOfDcs domain controllers for domain '$domain'"

        foreach ($i in (1..$numberOfDcs))
        {
            $fqdn = "DC$i.$($domain)"
            $machine = $machines | Where-Object FQDN -eq $fqdn
            $domainRole = if ($i -eq 1) { 'RootDC' } else { 'DC' }
            
            if ($machine)
            {
                $machine | Add-Member -Name DomainRole -MemberType NoteProperty -Value $domainRole
            }
            else
            {
                $machine = New-Object PSObject -Property @{ DomainRole = $domainRole; FQDN = $fqdn }
                $machines.Add($machine) | Out-Null
            }
        }
    }
    
    Write-Host
}

function Add-SfBLabOfficeClients
{
    $domains = Get-SfBTopologyActiveDirectoryDomains
    Write-Host "Domains found in the topology: $($domains)"

    Write-Host
    $i = 1
    foreach ($domain in $domains)
    {
        $numberOfOfficeClients = if ($global:SfBALTestMode -gt 0)
        {
            1
        }
        else
        {
            Read-Host -Prompt "How many Office 2016 Clients do you want to have in domain '$domain'?"
        }
        
        Write-Host "You have chosen $numberOfOfficeClients Office 2016 Clients to be added to domain '$domain'"

        foreach ($i in (1..$numberOfOfficeClients))
        {
            $fqdn = "Client$i.$($domain)"
            $role = 'Office2016'
            
            $machine = New-Object PSObject -Property @{ 
                DomainRole = $role
                FQDN = $fqdn
                IsClient = $true
            }
            $machines.Add($machine) | Out-Null
        }
    }
    
    Write-Host
}

function Add-SfBLabExchangeServers
{
    $domains = Get-SfBTopologyActiveDirectoryDomains
    Write-Host "Domains found in the topology: $($domains)"

    Write-Host
    $i = 1
    foreach ($domain in $domains)
    {
        $numberOfExchangeServers = if ($global:SfBALTestMode -gt 0)
        {
            1
        }
        else
        {
            Read-Host -Prompt "How many Exchange 2016 Servers do you want to have in domain '$domain'?"
        }
        
        Write-Host "You have chosen $numberOfExchangeServers Office 2016 Clients to be added to domain '$domain'"

        foreach ($i in (1..$numberOfExchangeServers))
        {
            $fqdn = "Exchange$i.$($domain)"
            $role = 'Exchange2016'
            
            $machine = New-Object PSObject -Property @{ 
                DomainRole = $role
                FQDN = $fqdn
                IsClient = $false
            }
            $machines.Add($machine) | Out-Null
        }
    }
    
    Write-Host
}

function Add-SfBLabFundamentals
{
    $sb.AppendLine(('$labName = "{0}"' -f $LabName)) | Out-Null
    $sb.AppendLine('$labSources = Get-LabSourcesLocation') | Out-Null

    $line = 'New-LabDefinition -Name $labName -DefaultVirtualizationEngine HyperV -Notes @{{ SfBTopologyPath = "{0}" }}' -f $TopologyFilePath
    $sb.AppendLine($line) | Out-Null
    $sb.AppendLine("Add-LabIsoImageDefinition -Name SQLServer2014 -Path $($prerequisites.ISOs.SqlServer2014)") | Out-Null
    $sb.AppendLine("Add-LabIsoImageDefinition -Name Office2016 -Path $($prerequisites.ISOs.Office2016)") | Out-Null

    Write-Host "Setting default installation credentials for machines to user 'Install' with password 'Somepass1'"
    $sb.AppendLine('Set-LabInstallationCredential -Username Install -Password Somepass1') | Out-Null
    $sb.AppendLine() | Out-Null
    
    Write-Host
}

function Add-SfBClusterDnsRecords
{
    $clusters = Get-SfBTopologyCluster | Where-Object { $_.IsSingleMachineOnly -eq 'false' }

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

            Invoke-LabCommand -ActivityName "AddClusterDnsRecord ($clusterName -> $($labMachine.IpV4Address))" -ComputerName $dc -ScriptBlock ([scriptblock]::Create($dnsCmd))
        }
    }
}

function Add-SfBEdgeServerDnsRecords
{
    $edgeServers = Get-SfBTopologyCluster | Get-SfBTopologyMachine | Where-Object Roles -like *Edge*
    
    foreach ($edgeServer in ($edgeServers | Where-Object { $_.NetInterface.InterfaceSide -eq 'Internal' }))
    {
        $domainName = $edgeServer.Fqdn.Substring($edgeServer.Fqdn.IndexOf('.') + 1)
        $dc = Get-LabMachine -Role RootDC | Where-Object DomainName -eq $domainName
        $name = $edgeServer.Fqdn.Substring(0, $edgeServer.Fqdn.IndexOf('.'))
        $ipAddress = $edgeServers[0].NetInterface | Where-Object InterfaceSide -eq Internal | Select-Object -ExpandProperty IPAddress
        
        Invoke-LabCommand -ActivityName "AddEdgeServerDnsRecord ($name -> $ipAddress)" -ComputerName $dc -ScriptBlock ([scriptblock]::Create($dnsCmd))
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
        New-SmbShare -Path $newFolder -Name $name -Description SfB -FullAccess Everyone
    }

    $fileStores = Get-SfBTopologyFileStore

    foreach ($fileStore in $fileStores)
    {
        $installedOnMachines = $fileStore.InstalledOnMachines.Substring(0, $fileStore.InstalledOnMachines.IndexOf('.'))
        Invoke-LabCommand -ActivityName NewFileStore -ComputerName $installedOnMachines -ScriptBlock $cmd -ArgumentList $fileStore.ShareName
    }
}

function Test-SfBLabRequirements
{
    [CmdletBinding()]
    
    param()
    
    $regCache = Get-SfBLabRequirements
    
    return [bool]$regCache
}

function Get-SfBLabRequirements
{
    [CmdletBinding()]
    
    param()
    
    $type = Get-Type -GenericType AutomatedLab.DictionaryXmlStore -T String, (Get-Type -GenericType AutomatedLab.SerializableDictionary -T string,string)
    
    try
    {
        $type::ImportFromRegistry('Cache', 'SfB')
    }
    catch
    {
        Write-Error 'No settings found in the registry'
        return
    }
}

function Set-SfBLabRequirements
{
    [CmdletBinding()]
    
    param()

    $labSources = Get-LabSourcesLocation
    
    $requiredIsos = $PSCmdlet.MyInvocation.MyCommand.Module.PrivateData.RequiredIsos
    $requiredWindowsFixes = $PSCmdlet.MyInvocation.MyCommand.Module.PrivateData.RequiredWindowsFixes
    
    $type = Get-Type -GenericType AutomatedLab.DictionaryXmlStore -T String, (Get-Type -GenericType AutomatedLab.SerializableDictionary -T string,string)
    
    Write-Verbose 'Trying to find existing settings...'
    
    try
    {
        $regCache = $type::ImportFromRegistry('Cache', 'SfB')        
        $result = Read-Choice -ChoiceList '&Yes', '&No' -Caption 'Do you want to change and overwrite the existing settings?' -Default 1
    }
    catch
    {
        $result = 0
    }
    
    if ($result -eq 0)
    {
        Write-Host
        Write-Host 'In order to install the lab, some ISO files need to be present and known to SfBAutomatedLab. Please provide the paths to:'
        $data = Read-HashTable -ChoiceList $requiredIsos -Caption 'Please copy and paste the paths to the required ISO files here:'
    }
    
    if ($data)
    {
        $isos = New-Object (Get-Type -GenericType AutomatedLab.SerializableDictionary -T string,string)
        $data.GetEnumerator() | ForEach-Object {
            $isos.Add($_.Key, $_.Value)
        }
        
        $regCache = New-Object $type
        $regCache.Add('ISOs', $isos)
    }
    
    $regCache.ISOs.GetEnumerator() | ForEach-Object {
        if (-not $_.Value)
        {
            throw "The path for '$($_.Key)' is empty. Please start the function 'Set-SfBLabRequirements' again and overwrite the existing settings."
        }
        if (-not (Test-Path -Path $_.Value -PathType Leaf))
        {
            throw "The path for $($_.Key) ($($_.Value)) could not be validated. Please start the function 'Set-SfBLabRequirements' again"
        }
    }
    
    #-------------------------------
    
    $allRequiredFixesAvailable = 1
    
    Write-Host
    Write-Host "Checking for required fixes..."
    
    $fixes = New-Object (Get-Type -GenericType AutomatedLab.SerializableDictionary -T string,string)
    
    $isOneFixMissing = $false
    foreach ($requiredWindowsFix in $requiredWindowsFixes)
    {
        Write-Host "$requiredWindowsFix - " -NoNewline
        $exists = (Get-ChildItem -Path $labSources -Filter $requiredWindowsFix -Recurse).FullName
        
        if ($exists) { Write-Host 'ok' } else { Write-Host 'NOT FOUND';$isOneFixMissing = $true }

        $fixes.Add($requiredWindowsFix, $exists)
    }
    
    Write-Host
    if ($isOneFixMissing)
    {
        throw 'Required fixes are missing. Please put the files into the OSUpdates folder which is inside the LabSources folder'
    }
    
    $regCache.RequiredWindowsFixes = $fixes
    
    $regCache.ExportToRegistry('Cache', 'SfB')
}