$path = Get-Location
$target = Read-Host -Prompt "Target IP/Host: "
$domain = Read-Host -Prompt "Target Domain: "
$user = Read-Host -Prompt "Admin User On Target: "

# Note: Forensics Script and Remote Script must be in same directory
$script = $path.Path + "\ForensicsInfo.ps1"
Write-Output $script
Invoke-Command -ComputerName $target -FilePath $script -credential $Domain\$User