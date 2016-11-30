# SfBAutomatedLab (still in development)

How to use:

$scriptFilePath = 'D:\SfBTest.ps1'
$topologyFilePath = 'D:\export.tbxml'

$script = New-SfBLab -TopologyFilePath $topologyFilePath -LabName SfBTest2 -OutputScriptPath $scriptFilePath

Invoke-SfBLabScript
Invoke-SfBLabPostInstallations
