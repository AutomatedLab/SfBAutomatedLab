## Project Summary


***THIS MODULE IS NOT IN ACTIVE DEVELOPMENT ANY LONGER DUE TO LACK OF FUNDING***
***NONE OF ITS FUNCTIONALITY WAS OR WILL BE TESTED OUTSIDE OF THE OUTLINED PARAMETERS***


Building lab environments is a time-consuming task. First you are creating your topology using the SfB Topology Builder. Then you need to create the virtual machines, configure the networking, setup Active Directory, a PKI, IIS, Office Online Server and SQL Server. This takes a lot of time and it is easy to forget a configuration item or click the wrong button.

SfBAutomatedLab does it all for you. It reads the topology file (tbxml) created by the Topology Builder and creates all the machines defined there. It also sets up Active Directory with an Enterprise PKI and SQL Server, all according to what is defined in the topology file. After that, the SfB components are installed on the edge and frontend servers.

### [1. Installation of SfbAutomatedLab](https://github.com/AutomatedLab/SfBAutomatedLab/wiki/1.-Installation-of-SfbAutomatedLab)
### [2. Getting Ready for the Automated Deployment](https://github.com/AutomatedLab/SfBAutomatedLab/wiki/2.-Getting-Ready-for-the-Automated-Deployment)
### [3. Starting an Automated Deployment (Part 1)](https://github.com/AutomatedLab/SfBAutomatedLab/wiki/3.-Starting-an-Automated-Deployment-(Part-1))
### [4. Starting an Automated Deployment (Part 2)](https://github.com/AutomatedLab/SfBAutomatedLab/wiki/4.-Starting-an-Automated-Deployment-(Part-2))
### [Version History](https://github.com/AutomatedLab/SfBAutomatedLab/wiki/Version-History)

## Requirements
* [AutomatedLab 5.40 or higher]( https://github.com/AutomatedLab/AutomatedLab/releases)
* Hyper-V/Azure subscription, see also <https://automatedlab.org/en/latest/#requirement>
* Windows Server 2012 R2 ISO file
* Skype for Business 2015 ISO file
* Office Online Server ISO file (Last updated November 2016 or newer)
* SQL Server 2014 ISO file

## How to use it
These lines are all it requires, assuming you use the Topology Builder to export the topology to `D:\export.tbxml`:  
```PowerShell
if (-not (Test-SfBLabRequirements))
{
    Set-SfBLabRequirements
}

Start-SfBLabDeployment -LabName SfbTest1 -TopologyFilePath D:\export.tbxml
```
