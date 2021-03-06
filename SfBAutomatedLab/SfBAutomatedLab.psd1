@{
    RootModule = 'SfBAutomatedLab.psm1'

    ModuleVersion = '0.6.1'

    GUID = '957b3d00-8ff2-42d4-a067-065514e5f045'

    Author = 'Raimund Andree'

    CompanyName = 'Microsoft'

    Copyright = '2017'

    Description = 'SfB Lab Automation based on AutomatedLab'

    PowerShellVersion = '5.0'

    DotNetFrameworkVersion = '4.0'

    FormatsToProcess = @()

    NestedModules = @('SfBAutomatedLabTopology.psm1', 'SfBAutomatedLabInternals.psm1')

    RequiredModules = @('AutomatedLab')

    AliasesToExport = '*'
    
    ModuleList = @('SfBAutomatedLab.psm1', 'SfBAutomatedLabTopology.psm1', 'SfBAutomatedLabInternals.psm1')

    FileList = @('SfBAutomatedLab.psm1', 'SfBAutomatedLabTopology.psm1', 'SfBAutomatedLabInternals.psm1', 'SfBAutomatedLab.psd1')

    FunctionsToExport = 'Add-SfBClusterDnsRecords',
    'Add-SfBFileShares',
    'Get-SfBLabRequirements',
    'Get-SfBTopology',
    'Import-SfBTopology',
    'Install-SfBLabActiveDirectory',
    'Install-SfBLabRequirements',
    'Install-SfbLabSfbComponents',
    'Start-SfbLabPool',
    'Invoke-SfBLabScript',
    'New-SfBLab',
    'Set-SfBLabRequirements',
    'Start-SfBLabDeployment',
    'Test-SfBLabRequirements'

    PrivateData = @{
        RequiredIsos = 'SfB2015Iso', 'OfficeOnline2016Iso', 'SqlServer2014', 'Office2016'
        RequiredWindowsFixes = 'Windows8.1-KB2999226-x64.msu', 'Windows8.1-KB3003057-x64.msu', 'Windows8.1-KB3016437-x64.msu', 'Windows8.1-KB2982006-x64.msu'

        DownloadUrls = @{
            SilverLight = 'http://silverlight.dlservice.microsoft.com/download/8/E/7/8E7D9B4B-2088-4AED-8356-20E65BE3EC91/40728.00/Silverlight_x64.exe'
            LatestCumulativeUpdate = 'https://download.microsoft.com/download/F/B/C/FBC09794-2DB9-415E-BBC7-7202E8DF7072/SkypeServerUpdateInstaller.exe'
            CallQualityDashboard = 'https://download.microsoft.com/download/1/B/1/1B161A2C-12B0-4CF6-B5C7-805D53C21714/CallQualityDashboard.msi'
        }

        OS = @{
            Server = 'Windows Server 2012 R2 SERVERDATACENTER'
            Client = 'Windows 10 Enterprise'
        }
    }
}
