#!/bin/bash
#simple script to nuke passwords. replace "passwd" below as appropriate for better passwords.
#TODO: make the passwords fancy

cat /etc/passwd | cut -f 1 -d: > ~/users.txt
for i in `cat users.txt`;do echo -e "passwd\npasswd" | passwd $i; done
