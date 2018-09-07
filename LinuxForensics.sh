#!/bin/bash



#Time

echo "Time: "

date | cut -d " " -f5



#Time Zone

timedatectl | grep zone | tr -d "\t "



#Uptime

uptime -p

#Version
echo "Version Information"
cat /etc/os-release | grep "VERSION=" | cut -d '"' -f2
cat /etc/os-release | grep -w "NAME=" | cut -d '"' -f2

echo "Kernel: "
uname -v

echo "Processor: "
lscpu | grep "Model name" | tr -d "\t "

echo "Memory: "
cat /proc/meminfo | grep MemTotal | tr -d "\t "

echo "Drives: "
lsblk | grep disk | cut -d " " -f1

echo "Drive Verbose: "
lsblk

echo "File Systems: "
df -h

echo "Hostname: "
hostname

echo "Domain: "
domainname

echo "User Information: "
cat /etc/passwd

echo "Last Login for all users: "
lastlog

echo "Login History: "
last

echo "Startup: :"
initctl list

echo "Scheduled Tasks (cron): "
crontab -l

echo "Network Information: \n\n"

echo "ARP: "
arp -a

echo "Interface MACs: "
ifconfig | grep HWAddr

echo "Routing Table: "
route

echo "DHCP Servers: "
cat $(ps aux | grep -o '[/]var/lib/NetworkManager/\S*.lease') | grep dhcp-server-identifier | cut -d " " -f5 | cut -d ";" -f1

echo "DNS Servers: "
cat /etc/resolv.conf | grep nameserver | cut -d " " -f2

echo "Gateways: "
ip route

echo "Listening: "
netstat -tulp4 | grep "LISTEN"

echo "Established: "
netstat -tula4 | grep ESTABLISHED

# No OS Level DNS Cache for Linux

echo "Printers: "
lpstat -p -d

echo "All packages: "
compgen -c

echo "Process Information: "
# All users, include non-attached, display owner
ps aux

echo "Driver Information: "
lsmod

# Assistance from Scott Brink
for user in `ls /home/`
do
	echo "Documents and Downloads for $user"
	ls /home/$user/Downloads
	ls /home/$user/Documents
done

# Personal

# 1) Useful when Web Server exists on target system
cat /var/log/apache2/access.log

# 2) View actively logged in users
who

# 3) Detailed User Folder Content
for user in `ls /home/`
do
	echo "Bash History for $user: "
	cat /home/$user/.bash_history
	echo "Contents of .SSH Folder for $user: "
	ls /home/$user/.ssh
	echo "Authorized Keys Contents for $user: " 
	cat /home/$user/.ssh/authorized_keys
	echo "BashRC for $user: "
	cat /home/$user/.bashrc
	echo "Contents of Desktop for $user: "
	ls /home/$user/Desktop
done
