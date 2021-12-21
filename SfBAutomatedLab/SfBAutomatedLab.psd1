@{
    RootModule             = 'SfBAutomatedLab.psm1'

    ModuleVersion          = '0.6.2'

    GUID                   = '957b3d00-8ff2-42d4-a067-065514e5f045'

    Author                 = 'Raimund Andree'

    CompanyName            = 'Microsoft'

    Copyright              = '2021'

    Description            = 'SfB Lab Automation based on AutomatedLab - not in active development!'

    CompatiblePSEditions   = 'Desktop'
    PowerShellVersion      = '5.1'

    DotNetFrameworkVersion = '4.0'

    FormatsToProcess       = @()

    NestedModules          = @('SfBAutomatedLabTopology.psm1', 'SfBAutomatedLabInternals.psm1')

    RequiredModules        = @(@{ModuleName = 'AutomatedLab'; ModuleVersion = '5.40.0' })

    AliasesToExport        = '*'

    FileList               = @('SfBAutomatedLab.psm1', 'SfBAutomatedLabTopology.psm1', 'SfBAutomatedLabInternals.psm1', 'SfBAutomatedLab.psd1')

    FunctionsToExport      = 'Add-SfBClusterDnsRecords',
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

    PrivateData            = @{
        RequiredIsos         = 'SfB2015Iso', 'OfficeOnline2016Iso', 'SqlServer2014', 'Office2016'
        RequiredWindowsFixes = 'KB2999226', 'KB3003057', 'KB3016437', 'KB2982006'

        DownloadUrls         = @{
            SilverLight            = 'http://silverlight.dlservice.microsoft.com/download/8/E/7/8E7D9B4B-2088-4AED-8356-20E65BE3EC91/40728.00/Silverlight_x64.exe'
            LatestCumulativeUpdate = 'https://download.microsoft.com/download/F/B/C/FBC09794-2DB9-415E-BBC7-7202E8DF7072/SkypeServerUpdateInstaller.exe'
            CallQualityDashboard   = 'https://download.microsoft.com/download/1/B/1/1B161A2C-12B0-4CF6-B5C7-805D53C21714/CallQualityDashboard.msi'
            KB2999226              = 'https://download.microsoft.com/download/D/1/3/D13E3150-3BB2-4B22-9D8A-47EE2D609FFF/Windows8.1-KB2999226-x64.msu'
            KB3003057              = 'https://download.microsoft.com/download/7/D/0/7D05B8C7-EBA4-452C-9220-B5ED46DE275D/IE11-Windows6.1-KB3003057-x86.msu'
            KB3016437              = 'https://download.microsoft.com/download/D/C/6/DC69B595-9C62-4B31-B154-B3722250D296/Windows8.1-KB3016437-x64.msu'
            KB2982006              = 'http://download.windowsupdate.com/d/msdownload/update/software/htfx/2014/09/windows8.1-kb2982006-x64_d96bea78d5746c48cb712c8ef936c29b5077367f.msu'
        }

        OS                   = @{
            Server = 'Windows Server 2012 R2 Datacenter (Server with a GUI)'
            Client = 'Windows 10 Enterprise'
        }
    }
}
