#!/bin/bash
#simple script to nuke passwords.#
#TODO: make the passwords fancy#

cat /etc/passwd | cut -f 1 -d: > ~/users.txt
for i in `cat users.txt`;do echo -e "P@ssw0rd\nP@ssw0rd" | passwd $i; done
