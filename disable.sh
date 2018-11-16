echo "7.2 - Determine if any system accounts can be accessed: There should be no results returned."
egrep -v "^\+" /etc/passwd | awk -F: '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $3<500 && $7!="/sbin/nologin") {print}'
#Accounts that have been locked are prohibited from running commands on the system. Such accounts are not able to login to the system nor are they able to use scheduled execution facilities such as cron. To make sure system accounts cannot be accessed, using the following script:￼￼￼￼
touch /tmp/disable.sh
cat << 'EOM' > /tmp/disable.sh
#!/bin/bash
for user in `awk -F: '($3 < 500) {print $1 }' /etc/passwd`; do
   if [ $user != "root" ]
then
      /usr/sbin/usermod -L $user
      if [ $user != "sync" ] && [ $user != "shutdown" ] && [ $user != "halt" ]
      then
         /usr/sbin/usermod -s /sbin/nologin $user
      fi
fi done
EOM
bash /tmp/disable.sh
