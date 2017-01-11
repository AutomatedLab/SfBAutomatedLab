# SfBAutomatedLab (still in development)

How to use:

if (-not (Test-SfBLabRequirements))
{
    Set-SfBLabRequirements
}

Start-SfBLabDeployment -LabName SfbTest1 -TopologyFilePath C:\Users\Raimund\Desktop\export.tbxml
