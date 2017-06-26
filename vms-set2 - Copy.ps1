<# I am learning Powershell and requires help in this script.
 
The aim  from this script is "Automatically create  lab setup VMs (2016/Win10) from powershell" which includes

A. Create VMs automatically from a Base 2016/W10 Disk
B. Install multiple VMs from that disk
C. Assign IP Addresses and add those servers to domain
D. Install required Roles and applications on these servers (For example AD/DNS on one server and File server on other)

The intention is to supply a CSV file which has all the required Server/VM details and let it loop through creating
required number of servers and install required roles on created VMs using invoke-command (using powershell direct)
The challenge seems to be on Passing variables under Invoke-command and executing the correct invoke-command scripblock
on what needs to be installed on which VMs
Would like to supply all variables values on the CSV and NOT individually. For example when creating 5 VMs,
the script needs to assign variables automatically during the loop and install the roles only on the 
relevant machines (Domain services on AD, File services on File server etc)

So far, I have been able to do below things
Create VMs and different types of disks from a CSV file --- 

But I have not been able to do the below things

1. Assigning IPs and adding servers to Domain
Could not send variables with in the invoke command and I get Variable empty error mesage. 
Need help on how variables can be send across Invoke -scripblock multiple times (as server need to restart and then execute actions)

2. How the script would take correct variable and execute the actions on the correct server.
For example in my csv, I have two servers (one AD and other File server) when the object VM.name comes through the pipe,
How the script would identify VM.name on first loop refers to AD server and execute invoke-command relates ony
AD server and when it comes for the second loop, VM.name is Fileserver and execute invoke-command relatest only
to File server install tasks and so on...

If anyone can make this script work, it would help anyone who would like to build their standard lab 
consistently and quickly.

#>

# Clear the screen
#Start of the script
# As part of testing, some of the commands are commented out.
cls

$CSVPath = "D:\OneDrive\Work\Scripts\Hyper-v\HomeLab\VMLab.csv"
$LogPath = "D:\OneDrive\Work\Scripts\Hyper-v\HomeLab\VMsLog.txt"

# Remove the log file
Remove-Item -Path $LogPath -ErrorAction SilentlyContinue

Import-Csv $CSVPath | ForEach-Object {

# Construct some paths
$Path = $_.VMPath
$VMName = $_.VMName
$VMstate = $_.state
$VHDPath = "$Path\$VMName"
$VMIP= $_.IPAddress
$VMGW= $_.Gateway
$VMMask= $_.Mask
$VMDNS= $_.DNS
$VMServerName= $_.ServerName
$VMSwitchName= $_.Switch
$VMAdapterName= $_.Adapter
$VMversion=$_.version
$xmlloc="D:\OneDrive\Work\Scripts\Hyper-v\HomeLab\unattend.xml"
$xmlroot="D:\OneDrive\Work\Scripts\Hyper-v\HomeLab"


$VMLogin = "$VMName\Administrator"
$VMPW = ConvertTo-SecureString -String "Password1" -AsPlainText -Force
$VMcred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $VMLogin, $VMPW

# The below credentials are used by operations below once the domain controller virtual machine and the new domain are in place. These credentials should match the credentials
# used during the provisioning of the new domain. 
#$DomainUser = "$DomainName\administrator"
#$DomainPWord = ConvertTo-SecureString -String "Password01" -AsPlainText -Force
#$DomainCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $DomainUser, $DomainPWord 

# Only create the virtual machine if it does not already exist
if ((Get-VM $VMName -ErrorAction SilentlyContinue))
    {
    Add-Content $LogPath "FAIL: $VMName already existed."
    }
    else
    {

    # Create a new folder for the VM if it does not already exist
    if (!(Test-Path $VHDPath))
        { 
        New-Item -Path $VHDPath -ItemType "Directory"
        }

    # Create a new folder for the VHD if it does not already exist
    if (!(Test-Path "$VHDPath\Virtual Hard Disks"))
        {    
        $VhdDir = New-Item -Path "$VHDPath\Virtual Hard Disks" -ItemType "Directory"
        }

    # Create the VHD if it does not already exist
    $NewVHD = "$VhdDir\$VMName-Disk0.vhdx"
    if (!(Test-Path $NewVHD))
        {
        # Have to set these variables because $_.Variables are not available inside the switch.
        $ParentDisk = $_.DiffParent
        $DiskSize = [int64]$_.DiskSize * 1073741824
        switch ($_.DiskType)
            {
            'Differencing' {New-VHD -Differencing -Path $NewVHD -ParentPath $ParentDisk}
            'Fixed' {New-VHD -Fixed -Path $NewVHD -SizeBytes $DiskSize}
            Default {New-VHD -Dynamic -Path $NewVHD -SizeBytes $DiskSize}
            }
        if (Test-Path $NewVHD)
            {
            Add-Content $LogPath "  Progress: $NewVHD was created."
            }
            else
            {
            Add-Content $LogPath "  Error: $NewVHD was not created."
            }
        }
        else
        {
        Add-Content $LogPath "  Progress: $NewVHD already existed"
        }

    # Create the VM and configure
    New-VM -Name $VMName -Path $Path -SwitchName Internal -VHDPath $NewVHD -MemoryStartupBytes ([int64]$_.StartupRam * 1048576) -Generation $VMversion
    #Remove any auto generated adapters and add new ones with correct names for Consistent Device Naming
    Get-VMNetworkAdapter -VMName $VMName |Remove-VMNetworkAdapter
    Add-VMNetworkAdapter -VMName $VMName -SwitchName $VMSwitchName -Name $VMAdapterName -DeviceNaming On
    #Rename-VMNetworkAdapter -VMName $_.VMName -NewName VirtuaDeskMGMT
    #Add-VMNetworkAdapter -VMName $_.VMName -Name VirtuaDeskOSMGMT -SwitchName VirtuaDeskOSMGMT
    #Set-VMNetworkAdapterVlan -VMName $_.VMName -VMNetworkAdapterName VirtuaDeskMGMT -VlanId 2519 -Access 
    #Set-VMNetworkAdapterVlan -VMName $_.VMName -VMNetworkAdapterName VirtuaDeskOSMGMT -VlanId 2519 -Access
    set-VM -Name $VMName -AutomaticStopAction ShutDown -AutomaticStartAction Nothing -AutomaticCriticalErrorAction None
    # Configure the processors
    Set-VMProcessor $VMName -Count $_.ProcessorCount

    # Configure Dynamic Memory if required
    If ($_.DynamicMemory -Eq "Yes")
        {
        Set-VMMemory -VMName $_.VMName -DynamicMemoryEnabled $True -MaximumBytes ([int64]$_.MaxRAM * 1048576) -MinimumBytes ([int64]$_.MinRAM * 1048576) -Priority $_.MemPriority -Buffer $_.MemBuffer
        }

    #Set first boot device to the disk we attached
    #$Drive=Get-VMHardDiskDrive -VMName $Name | where {$_.Path -eq "$VHDPath"}
    #Get-VMFirmware -VMName $Name | Set-VMFirmware -FirstBootDevice $Drive
    
    #Mount the new virtual machine VHD
    # The below steps are done to copy unattend.xml to VMs so that it can autologon 
    mount-vhd -Path $NewVHD
    #Find the drive letter of the mounted VHD
    $VolumeDriveLetter=GET-DISKIMAGE $NewVHD | GET-DISK | GET-PARTITION |get-volume |?{$_.FileSystemLabel -ne "Recovery"}|select DriveLetter -ExpandProperty DriveLetter
    #Construct the drive letter of the mounted VHD Drive
    $DriveLetter="$VolumeDriveLetter"+":"
    #Copy the unattend.xml to the drive
    Copy-Item $xmlloc $DriveLetter\unattend.xml
    #Dismount the VHD
    Dismount-Vhd -Path $NewVHD
    #Write-Verbose "Unattend.xml was copied from $xmlloc location to C Drive"

    # Start the newly created VMs
    Start-VM -Name $VMName

    Write-Verbose “Waiting for PowerShell Direct to start on VM [$VMName]” -Verbose
   while ((icm -VMName $VMName -Credential $VMcred {“Test”} -ea SilentlyContinue) -ne “Test”) {Sleep -Seconds 1}

Write-Verbose "PowerShell Direct responding on VM [$VMName]. Moving On...." -Verbose


Invoke-Command -VMName $VMName -Credential $VMcred -ScriptBlock {
    #param ($VMIA, $VMIP, $VMName, $NewIP,$VMMask, $VMGW) -- Param and Argument list has not worked.
    $VMIA=Get-NetAdapter | select -expandproperty interfacealias
    New-NetIPAddress -InterfaceAlias $VMIA -IPAddress $VMIP -PrefixLength $VMMask -DefaultGateway $VMGW | Out-Null
    #New-NetIPAddress -IPAddress "$VMIP" -InterfaceAlias "Ethernet" -PrefixLength "$VMMask" | Out-Null
    $NewIP = Get-NetIPAddress -InterfaceAlias $VMIA | Select-Object IPAddress
    Write-Verbose "Assigned IPv4 and IPv6 IPs for VM [$VMName] are as follows" -Verbose 
    Write-Host $NewIP | Format-List
    Write-Verbose "Setting DNS Source to [$VMName] with IP [$NewIP]" -Verbose
    #Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses "$VMDNS"
    Set-DnsClientServerAddress -InterfaceAlias $VMIA -ServerAddresses $VMDNS
    Write-Verbose "Updating Hostname for VM [$VMName]" -Verbose
    Rename-Computer -NewName "$VMName" -Force
    Write-Verbose "Rebooting VM [$VMName] for hostname change to take effect" -Verbose
    Restart-Computer -Force
    } #-ArgumentList $VMIA, $VMIP, $VMName, $NewIP $VMMask, $VMGW

 Write-Verbose “Waiting for PowerShell Direct to start on VM [$VMName]” -Verbose
   while ((icm -VMName $VMName -Credential $VMcred {“Test”} -ea SilentlyContinue) -ne “Test”) {Sleep -Seconds 1}

Write-Verbose "PowerShell Direct responding on VM [$VMName]. Moving On...." -Verbose

Invoke-Command -VMName $VMName -Credential $VMcred -ScriptBlock {
Add-WindowsFeature "RSAT-AD-Tools"
Add-WindowsFeature -Name "ad-domain-services" -IncludeAllSubFeature -IncludeManagementTools
Add-WindowsFeature -Name "dns" -IncludeAllSubFeature -IncludeManagementTools
Add-WindowsFeature -Name "gpmc" -IncludeAllSubFeature -IncludeManagementTools
Add-WindowsFeature -Name "rds-licensing"
Add-WindowsFeature -Name "rds-licensing-ui"
Install-ADDSForest `
-CreateDnsDelegation:$false `
-DatabasePath "C:\Windows\NTDS" `
-DomainMode "Win2012R2" `
-DomainName "ctxlab.local" `
-DomainNetbiosName "ctxlab" `
-ForestMode "Win2012R2" `
-InstallDns:$true `
-LogPath "C:\Windows\NTDS" `
-NoRebootOnCompletion:$false `
-SysvolPath "C:\Windows\SYSVOL" `
-Force:$true
Restart-Computer -Force
    } 
 Write-Verbose “Waiting for PowerShell Direct to start on VM [$VMName]” -Verbose
   while ((icm -VMName $VMName -Credential $VMcred {“Test”} -ea SilentlyContinue) -ne “Test”) {Sleep -Seconds 1}

Write-Verbose "PowerShell Direct responding on VM [$VMName]. Moving On...." -Verbose

Invoke-Command -VMName $VMName -Credential $VMcred -ScriptBlock {
#configure DNS servers (Execute on AD server)
Set-DnsServerPrimaryZone –Name "ctxlab.local" –ReplicationScope "Forest"
Set-DnsServerScavenging –ScavengingState $True –RefreshInterval  7:00:00:00 –NoRefreshInterval  7:00:00:00 –ScavengingInterval 7:00:00:00 –ApplyOnAllZones –Verbose
Set-DnsServerZoneAging ctxlab.local –Aging $True –NoRefreshInterval 7:00:00:00 –RefreshInterval 7:00:00:00 –ScavengeServers 192.168.1.10 –PassThru –Verbose
Add-DnsServerPrimaryZone –ReplicationScope "Forest"  –NetworkId "192.168.1.0/24" –DynamicUpdate Secure –PassThru –Verbose
Set-DnsServerZoneAging "1.168.192.in-addr.arpa" –Aging $True –NoRefreshInterval 7:00:00:00 –RefreshInterval 7:00:00:00  –PassThru –Verbose
Set-DNSClientServerAddress –interfaceIndex 12 –ServerAddresses ("192.168.1.10","127.0.0.1")
set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server'-name "fDenyTSConnections" -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -name "UserAuthentication" -Value 1
#Install and configure DHCP Server
#Pass DHCP specific variables within invoke command
$DNSDomain="ctxlab.local"
$DNSServerIP="192.168.1.10"
$DHCPServerIP="192.168.1.10"
$StartRange="192.168.1.150"
$EndRange="192.168.1.200"
$Subnet="255.255.255.0"
$Router="192.168.1.1"

Install-WindowsFeature -Name "DHCP" -IncludeManagementTools
cmd.exe /c "netsh dhcp add securitygroups"
Restart-service dhcpserver
Add-DhcpServerInDC -DnsName $Env:COMPUTERNAME
Set-ItemProperty –Path registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ServerManager\Roles\12 –Name ConfigurationState –Value 2
Add-DhcpServerV4Scope -Name "DHCP Scope" -StartRange $StartRange -EndRange $EndRange -SubnetMask $Subnet
Set-DhcpServerV4OptionValue -DnsDomain $DNSDomain -DnsServer $DNSServerIP -Router $Router				
Set-DhcpServerv4Scope -ScopeId $DHCPServerIP -LeaseDuration 1.00:00:00

#Install AD Cert Role (as AD will also act as Certificate server)
Install-WindowsFeature AD-Certificate
Install-AdcsCertificationAuthority -Force
Install-WindowsFeature -Name Web-Server -IncludeManagementTools
Install-WindowsFeature -Name RSAT-ADCS -IncludeManagementTools
#Restart AD server for all changes to take effect
Restart-Computer -Force
}

#Now the below invoke-command is to configure and install file server. How to ensure that the below code 
#gets executed only during second loop (Not during first loop) during which the varibles that gets passed
# on is a file server (not an AD server), please refer CSV sheet

Invoke-Command -VMName $VMName -Credential $VMcred -ScriptBlock {
    #This invoke command is only for file server
    $VMIA=Get-NetAdapter | select -expandproperty interfacealias
    New-NetIPAddress -InterfaceAlias $VMIA -IPAddress $VMIP -PrefixLength $VMMask -DefaultGateway $VMGW | Out-Null
    #New-NetIPAddress -IPAddress "$VMIP" -InterfaceAlias "Ethernet" -PrefixLength "$VMMask" | Out-Null
    $NewIP = Get-NetIPAddress -InterfaceAlias $VMIA | Select-Object IPAddress
    Write-Verbose "Assigned IPv4 and IPv6 IPs for VM [$VMName] are as follows" -Verbose 
    Write-Host $NewIP | Format-List
    Write-Verbose "Setting DNS Source to [$VMName] with IP [$NewIP]" -Verbose
    #Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses "$VMDNS"
    Set-DnsClientServerAddress -InterfaceAlias $VMIA -ServerAddresses $VMDNS
    Write-Verbose "Updating Hostname for VM [$VMName]" -Verbose
    Rename-Computer -NewName "$VMName" -Force
    Write-Verbose "Rebooting VM [$VMName] for hostname change to take effect" -Verbose
    Restart-Computer -Force
    } #-ArgumentList $VMIA, $VMIP, $VMName, $NewIP $VMMask, $VMGW
   
    Write-Verbose “Waiting for PowerShell Direct to start on VM [$VMName]” -Verbose
   while ((icm -VMName $VMName -Credential $VMcred {“Test”} -ea SilentlyContinue) -ne “Test”) {Sleep -Seconds 1}

Write-Verbose "PowerShell Direct responding on VM [$VMName]. Moving On...." -Verbose

Invoke-Command -VMName $VMName -Credential $VMcred -ScriptBlock {
#Install File server role on FS01
Install-WindowsFeature -Name "FS-FileServer" -IncludeManagementTools
 }  
   
   
    # Record the result
    if ((Get-VM $VMName -ErrorAction SilentlyContinue))
        {
        Add-Content $LogPath "Success: $VMName was created."
        }
        else
        {
        Add-Content $LogPath "FAIL: $VMName was NOT created."
        }
    # Record VM running Status
       if (Get-VM -Name ($_.VMName) | Where-Object State -EQ "Running") 
        {
        Add-Content $LogPath "Success: $VMName Is Super running."
        }
        else
        {
        Add-Content $LogPath "FAIL: $VMName Is not running."
        }
    }

}