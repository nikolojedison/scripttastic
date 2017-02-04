#!/bin/bash
#simple script to nuke passwords.#
#TODO: make the passwords fancy#

cat /etc/passwd | cut -f 1 -d: > ~/users.txt
for i in `cat users.txt`;do echo -e "Andshesbuying4stairway2Heaven\nAndshesbuying4stairway2Heaven" | passwd $i; done
