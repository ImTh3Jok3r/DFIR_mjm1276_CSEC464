function Get-Uptime {
   $os = Get-WmiObject win32_operatingsystem
   $uptime = (Get-Date) - ($os.ConvertToDateTime($os.lastbootuptime))
   $Display = "" + $Uptime.Days + " days, " + $Uptime.Hours + " hours, " + $Uptime.Minutes + " minutes" 
   return $Display
}

# CSV File
$csvData = New-Object -TypeName psobject

$time = Get-Date -Format T
$zone = Get-TimeZone | foreach { $_.Id }
$uptime = Get-Uptime

$timetable = new-object psobject
$timetable | add-member noteproperty Time $time
$timetable | add-member noteproperty "Time Zone" $zone
$timetable | add-member noteproperty Uptime $uptime

# Time Information
Write-Output "Time Information"
Write-Output $timetable

# Version Information
Write-Output "`n`nOS Version Info"
$version = Get-CimInstance Win32_OperatingSystem | Format-Table @{L='Name';E={$_.Caption}},Version,BuildNumber
Write-Output $version

# Hardware Information
$cpubrand= Get-WmiObject Win32_Processor | Select -Property Manufacturer
$cpuname = Get-WmiObject Win32_Processor | Select -Property Name

# Physical RAM Amount
$PhysicalRAM = (Get-WMIObject -class Win32_PhysicalMemory |
Measure-Object -Property capacity -Sum | % {[Math]::Round(($_.sum / 1GB),2)})

$hardware = new-object psobject
$hardware | add-member noteproperty "CPU Brand" $cpubrand.Manufacturer
$hardware | add-member noteproperty "CPU Name" $cpuname.Name
$hardware | add-member noteproperty "RAM (GB)" $PhysicalRam

Write-Output "Hardware Information"
Write-Output $hardware

$disk = Get-Disk

$dinfo = new-object psobject
$dinfo| add-member noteproperty "Drive Name" $disk.FriendlyName
$dinfo | add-member noteproperty "Drive Size" ($disk.Size / 1GB)

Write-Output "General Drive Information"
Write-Output $dinfo

Write-Output "`nMounted Drive Information"

$mounted = Get-WmiObject Win32_Volume | Format-Table Name, Label
Write-Output $mounted

# Domain Information
Write-Output "Domain Info"
$getdomain = [System.Directoryservices.Activedirectory.Domain]::GetCurrentDomain() 
$getdomain | ForEach-Object {$_.DomainControllers} |  
ForEach-Object { 
  $hEntry= [System.Net.Dns]::GetHostByName($_.Name) 
  New-Object -TypeName PSObject -Property @{ 
      Name = $_.Name 
      IPAddress = $hEntry.AddressList[0].IPAddressToString 
     }
   Add-Member -InputObject $csvData -MemberType NoteProperty -Name $hEntry.HostName -Value $hEntry
}

$domaininfo = Get-ADDomainController
Write-Output $domaininfo

# Hostname and Domain
Write-Output "Hostname and Domain"
$host = Get-WmiObject Win32_ComputerSystem | Format-Table Domain,Name
Write-Output $host

# Local User Info - Creation Date not logged locally
Write-Output "Local User Information"
$local = Get-LocalUser | Format-Table Name,SID,InstallDate,LastLogon
Write-Output $local

# Domain User Info
Write-Output "Domain User Information"
$duser = Get-ADUser | Format-Table SamAccountName,SID,WhenCreated,LastLogon
Write-Output $duser

# System User Info
Write-Output "System User Information"
$sysuser = Get-WmiObject Win32_SystemAccount | Format-Table Name,Domain,SID,InstallDate,LastLogon
Write-Output $sysuser

# Service Users
Write-Output "Service User Information"
$servuser = Get-ADUser -Filter 'Name -like "*SvcAccount"' | Format-Table SamAccountName,SID,WhenCreated,LastLogon
Write-Output $servuser

# Startup Services
Write-Output "Startup Services"
$startserv = Get-WmiObject Win32_Service | Where-Object {$_.StartMode -eq "Auto"} | Format-Table Name,ProcessId,State
Write-Output $startserv

# Startup Programs
Write-Output "Startup Programs"
$startpro = Get-WmiObject Win32_StartupCommand | Format-Table Name,Command,Location
Write-Output $startpro

# Scheduled Tasks
Write-Output "Task Information"
$tasks = Get-ScheduledTask | Select-Object TaskName,TaskPath
Write-Output $tasks

# Arp Table
Write-Output "ARP Information"
$arp = arp -a
Write-Output $arp

# Network Adapter Info
Write-Output "Network Adapter Information"
$net = Get-WmiObject Win32_NetworkAdapterConfiguration | Format-Table Description,IPAddress,MACAddress,DefaultIPGateway,DHCPServer,InterfaceIndex
Write-Output $net

Write-Output "IP Information"
$ipinfo = Get-NetIPAddress | Format-Table InterfaceAlias,IPAddress,AddressFamily
Write-Output $ipinfo

# Routing Table
Write-Output "Route Table"
$route = Get-NetRoute | Format-Table DestinationPrefix,NextHop
Write-Output $route

# DNS
Write-Output "DNS Server Information"
$dns = Get-DnsClientServerAddress | Format-Table InterfaceAlias,AddressFamily,ServerAddresses
Write-Output $dns

Write-Output "DNS Cache Information"
$cache = Get-DnsClientCache | Format-Table Entry,Name,Data
Write-Output $cache

Write-Output "Active Connections"
$active = Get-NetTCPConnection | Format-Table RemoteAddress,LocalPort,RemotePort,CimClass,CreationTime,ElementName
Write-Output $active

# Net Shares
Write-Output "Network Shares"
$shares = Get-WmiObject Win32_share | Select-Object Path
Write-Output $shares

Write-Output "Printer Information"
$print = Get-WmiObject Win32_Printer | Format-Table Name
Write-Output $print

# Wifi Profiles
Write-Output "Wifi Profiles"
$wifi = netsh.exe wlan show profiles
Write-Output $wifi

# Installed Programs
Write-Output "List of Installed Programs"
$ins = Get-Wmiobject -Class Win32_Product | Format-Table Name,Vendor,Version
Write-Output $ins

# Process List
# Note: Wmi was having issues with getting User, so switched to Cim
Write-Output "Process List"
$proc = Get-CimInstance Win32_Process | Select-Object Name,ProcessID,ParentProcessID,Path,@{l="Running User";e={(Invoke-CimMethod -InputObject $_ -MethodName GetOwner).User}}
Write-Output $proc

# Drivers
Write-Output "Driver Info"
$driver = DRIVERQUERY | Format-Table *
Write-Output $driver

# Downloads and Documents
# Note: Will Show lots of errors due to service/system accounts without these folders
$userlist = Get-ChildItem -Path "C:\Users" | Select-Object Name
ForEach ($user in $userlist){
Write-Host -NoNewline $user.Name "Downloads/Documents"
$down = Get-ChildItem -Path ("C:\Users\" + $user.Name + "\Downloads") | Format-Table Name
Write-Output $down
Add-Member -InputObject $csvData -MemberType NoteProperty -Name $user.name+"down" -Value $down
$doc = Get-ChildItem -Path ("C:\Users\" + $user.Name + "\Documents") | Format-Table Name
Write-Output $doc
Add-Member -InputObject $csvData -MemberType NoteProperty -Name $user.name+"doc" -Value $doc
}

# Personal

# Auditing Domain Admins
Write-Output "List of Domain Admins"
$da = Get-ADGroupMember Domain Admins
Write-Output $da

# Auditing Workstations in Domain (Check for new ones)
Write-Output "Workstation Information"
$aud = Get-QADComputer
Write-Output $aud

# Get Patch Information
Write-Output "Patch Info"
$patch = wmic qfe get Caption,Description,HotFixID,InstalledOn
Write-Output $patch

# CSV Creation
Add-Member -InputObject $csvData -MemberType NoteProperty -Name Time -Value $timetable
Add-Member -InputObject $csvData -MemberType NoteProperty -Name Version -Value $version
Add-Member -InputObject $csvData -MemberType NoteProperty -Name Hardware -Value $hardware
Add-Member -InputObject $csvData -MemberType NoteProperty -Name Disk -Value $dinfo
Add-Member -InputObject $csvData -MemberType NoteProperty -Name Mounts -Value $mounted
Add-Member -InputObject $csvData -MemberType NoteProperty -Name Domain -Value $domaininfo
Add-Member -InputObject $csvData -MemberType NoteProperty -Name Host -Value $host 
Add-Member -InputObject $csvData -MemberType NoteProperty -Name LocalUser -Value $local
Add-Member -InputObject $csvData -MemberType NoteProperty -Name Domainuser -Value $duser
Add-Member -InputObject $csvData -MemberType NoteProperty -Name SystemUser -Value $sysuser
Add-Member -InputObject $csvData -MemberType NoteProperty -Name ServiceUser -Value $servuser
Add-Member -InputObject $csvData -MemberType NoteProperty -Name BootServices -Value $startserv
Add-Member -InputObject $csvData -MemberType NoteProperty -Name BootPrograms -Value $startpro
Add-Member -InputObject $csvData -MemberType NoteProperty -Name Scheduled -Value $tasks
Add-Member -InputObject $csvData -MemberType NoteProperty -Name ARP -Value $arp
Add-Member -InputObject $csvData -MemberType NoteProperty -Name NetAdapters -Value $net
Add-Member -InputObject $csvData -MemberType NoteProperty -Name IP -Value $ipinfo
Add-Member -InputObject $csvData -MemberType NoteProperty -Name Routes -Value $route
Add-Member -InputObject $csvData -MemberType NoteProperty -Name DNSCache -Value $cache
Add-Member -InputObject $csvData -MemberType NoteProperty -Name Connections -Value $active
Add-Member -InputObject $csvData -MemberType NoteProperty -Name Shares -Value $shares
Add-Member -InputObject $csvData -MemberType NoteProperty -Name Printers -Value $print
Add-Member -InputObject $csvData -MemberType NoteProperty -Name WifiProfiles -Value $wifi
Add-Member -InputObject $csvData -MemberType NoteProperty -Name Installed -Value $ins
Add-Member -InputObject $csvData -MemberType NoteProperty -Name Processes -Value $proc
Add-Member -InputObject $csvData -MemberType NoteProperty -Name Drivers -Value $driver
Add-Member -InputObject $csvData -MemberType NoteProperty -Name DomainAdmin -Value $da
Add-Member -InputObject $csvData -MemberType NoteProperty -Name Workstations -Value $aud
Add-Member -InputObject $csvData -MemberType NoteProperty -Name Patches -Value $patch

$path = Get-Location
$Attachment = $path.Path + "\Results.csv"

$csvData | Export-Csv -Path $Attachment

$From = "enigma.glp@gmail.com"
$To = "mjm1276@g.rit.edu"
$Subject = "Forensics File"
$Body = "See Attached."
$SMTPServer = "smtp.gmail.com"
$SMTPPort = "587"
Send-MailMessage -From $From -to $To -Subject $Subject `
-Body $Body -SmtpServer $SMTPServer -port $SMTPPort -UseSsl `
-Credential (Get-Credential) -Attachments $Attachment