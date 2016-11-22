function Import-SfBTopology
{
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path
    )
	
    $script:tp = [xml](Get-Content -Path $Path)
    $script:ns = @{ 
        tp = 'urn:schema:Microsoft.Rtc.Management.Deploy.TopologyBuilder.2008'
        wt = 'urn:schema:Microsoft.Rtc.Management.Deploy.WritableTopology.2008'
        t = 'urn:schema:Microsoft.Rtc.Management.Deploy.Topology.2008'
    }
}

function Get-SfBTopologySipDomain
{
    $script:tp | Select-Xml -XPath '//tp:TopologyBuilder/tp:NewTopology/wt:PartialTopology/t:InternalDomains/t:InternalDomain' -Namespace $script:ns | Select-Object -ExpandProperty Node
}

function Get-SfBTopologyActiveDirectoryDomains
{
    $fqdns = Get-SfBTopologyCluster | Get-SfBTopologyMachine | Select-Object -ExpandProperty Fqdn
    $fqdns | ForEach-Object { $_.Substring($_.IndexOf('.') + 1) } | Select-Object -Unique
}

function Get-SfBTopologyCentralSite
{
    param(
        [string[]]$SiteName
    )

    if ($SiteName)
    {
        foreach ($name in $SiteName)
        {
            $xPath = '//tp:TopologyBuilder/tp:NewTopology/wt:PartialTopology/wt:CentralSites/wt:CentralSite[t:Name = "{0}"]' -f $name
            $script:tp | Select-Xml -XPath $xPath -Namespace $script:ns |
            Select-Object -ExpandProperty Node |
            ForEach-Object {
                $_ | Add-Member -MemberType NoteProperty -Name CentralSiteName -Value $_.Name.'#text' -PassThru
            }
        }
    }
    else
    {
        $script:tp | Select-Xml -XPath '//tp:TopologyBuilder/tp:NewTopology/wt:PartialTopology/wt:CentralSites/wt:CentralSite' -Namespace $script:ns |
        Select-Object -ExpandProperty Node |
        ForEach-Object {
            $_ | Add-Member -MemberType NoteProperty -Name CentralSiteName -Value $_.Name.'#text' -PassThru
        }
    }
}

function Get-SfBTopologyCluster
{
    [cmdletBinding(DefaultParameterSetName = 'ByXmlElement')]
    param(
        [Parameter(ValueFromPipeline, ParameterSetName = 'ByXmlElement')]
        [System.Xml.XmlElement[]]$CentralSite,

        [Parameter(ParameterSetName = 'ByName')]
        [string[]]$SiteName,

        [Parameter(ParameterSetName = 'ByFqdn')]
        [string[]]$Fqdn,

        [Parameter(ParameterSetName = 'ById')]
        [guid[]]$Id
    )

    process
    {
        if ($SiteName)
        {
            $CentralSite = Get-SfBTopologyCentralSite -SiteName $SiteName
            if (-not $CentralSite)
            {
                Write-Error "The site '$SiteName' could not be found"
                return
            }
        }

        if (-not $CentralSite)
        {
            $CentralSite = Get-SfBTopologyCentralSite
        }

        if ($PSCmdlet.ParameterSetName -eq 'ByFqdn')
        {
            foreach ($item in $Fqdn)
            {
                $xPath = '//tp:TopologyBuilder/tp:NewTopology/wt:PartialTopology/wt:CentralSites/wt:CentralSite/wt:Clusters/wt:Cluster[translate(@Fqdn, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz") = "{0}"]' -f $item.ToLower()
            
                $script:tp | Select-Xml -XPath $xPath -Namespace $script:ns | 
                Select-Object -ExpandProperty Node       
            }     
        }
        elseif ($PSCmdlet.ParameterSetName -eq 'ById')
        {
            foreach ($item in $Id)
            {
                $xPath = '//tp:TopologyBuilder/tp:NewTopology/wt:PartialTopology/wt:CentralSites/wt:CentralSite/wt:Clusters/wt:Cluster[translate(@UniqueId, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz") = "{0}"]' -f $item.ToString().ToLower()
            
                $script:tp | Select-Xml -XPath $xPath -Namespace $script:ns | 
                Select-Object -ExpandProperty Node
            }
        }
        else
        {
            foreach ($site in $CentralSite)
            {
                $xPath = '//tp:TopologyBuilder/tp:NewTopology/wt:PartialTopology/wt:CentralSites/wt:CentralSite[@SiteId = {0}]/wt:Clusters/wt:Cluster' -f $site.SiteId
            
                $script:tp | Select-Xml -XPath $xPath -Namespace $script:ns | 
                Select-Object -ExpandProperty Node
            }
        }
    }
}

function Get-SfBTopologyMachine
{
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [System.Xml.XmlElement[]]$Cluster
    )

    process
    {
        if (-not $Cluster)
        {
            $CentralSite = Get-SfBTopologyCluster
        }

        foreach ($c in $Cluster)
        {
            $xPath = '//tp:TopologyBuilder/tp:NewTopology/wt:PartialTopology/wt:CentralSites/wt:CentralSite/wt:Clusters/wt:Cluster[@UniqueId = "{0}"]/wt:Machines/wt:Machine' -f $c.UniqueId
            
            $nodes = $script:tp | Select-Xml -XPath $xPath -Namespace $script:ns |
            Select-Object -ExpandProperty Node

            foreach ($node in $nodes)
            {
                $node | Add-Member -MemberType NoteProperty -Name ClusterFqdn -Value $c.Fqdn
                $node | Add-Member -MemberType NoteProperty -Name ClusterUniqueId -Value $c.UniqueId

                if (-not $node.Fqdn)
                {
                    $node | Add-Member -MemberType NoteProperty -Name Fqdn -Value $c.Fqdn
                }

                $node | Add-Member -MemberType NoteProperty -Name CentralSiteId -Value $node.ParentNode.ParentNode.SiteId
                $node | Add-Member -MemberType NoteProperty -Name CentralSiteName -Value $node.ParentNode.ParentNode.Name

                $node | Add-Member -MemberType NoteProperty -Name IsSqlServer -Value ([bool]$node.ParentNode.ParentNode.SqlInstances)
                $node | Add-Member -MemberType NoteProperty -Name IsFileServer -Value ($node.Fqdn -in (Get-SfBTopologyFileStore).InstalledOnMachines)

                $node
            }
        }
    }
}

function Get-SfBTopologyFileStore
{
    $xPath = '//tp:TopologyBuilder/tp:NewTopology/wt:PartialTopology/wt:Services/wt:Service[@RoleName = "FileStore"]'
        
    $fileStores = $tp | Select-Xml -XPath $xPath -Namespace $ns | Select-Object -ExpandProperty Node
        
    foreach ($fileStore in $fileStores)
    {
        $fileStore | Add-Member -Name ShareName -MemberType NoteProperty -Value $fileStore.FileStoreService.ShareName
        $fileStore | Add-Member -Name InstalledOnCluster -MemberType NoteProperty -Value (Get-SfBTopologyCluster -Id $fileStore.InstalledOn)

        $xPath = '//tp:TopologyBuilder/tp:NewTopology/wt:PartialTopology/wt:CentralSites/wt:CentralSite/wt:Clusters/wt:Cluster[@UniqueId = "{0}"]/wt:Machines/wt:Machine' -f $fileStore.InstalledOn
            
        $nodes = $script:tp | Select-Xml -XPath $xPath -Namespace $script:ns |
        Select-Object -ExpandProperty Node

        $installedOnMachines = foreach ($node in $nodes)
        {
            if (-not $node.Fqdn)
            {
                $node.ParentNode.ParentNode.Fqdn
            }
            else
            {
                $node.Fqdn
            }
        }
        $fileStore | Add-Member -Name InstalledOnMachines -MemberType NoteProperty -Value $installedOnMachines

        $fileStore
    }
}

function Get-SfBMachineRoleString
{
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSObject]$Machine
    )

    $roleString = @()

    if ($Machine.IsFileServer)
    {
        $roleString += 'FileServer'
    }

    if ($Machine.IsSqlServer)
    {
        $roleString += 'SqlServer2014'
    }
    
    if ($Machine.DomainRole -eq 'RootDC')
    {
        $roleString += 'RootDC'
    }    
    elseif ($Machine.DomainRole -eq 'DC')
    {
        $roleString += 'DC'
    }

    if ($roleString)
    {
        ' -Roles ' + ($roleString -join ', ')
    }
}

function Get-SfBTopologyClusterService
{
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSObject]$Cluster
    )
    
    process
    {
        $xPath = '//tp:TopologyBuilder/tp:NewTopology/wt:PartialTopology/wt:Services/wt:Service[@InstalledOn = "{0}"]' -f $Cluster.UniqueId
        
        $tp | Select-Xml -XPath $xPath -Namespace $ns | Select-Object -ExpandProperty Node
    }
}