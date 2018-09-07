#/bin/bash

echo "Input User: "
read user
echo "Insert Target: "
read target

ssh $user@$target 'bash -s' < LinuxForensics.sh > ForensicsResults.txt
