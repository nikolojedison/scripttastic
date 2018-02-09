#!/bin/sh

NAME=`(uname -a)`
MSG=`(dmesg)`
ROOT=`(ls -a /)`
WEB=`(ls -a /var/www/)`
HOME=`(ls -a /home/)`

echo "Name: ${NAME}"
echo "dmesg: ${MSG}"
echo "Root files: ${ROOT}"
echo "Web-facing files: ${WEB}"
echo "Home files: ${HOME}"

echo "Name: ${NAME}" >> scripting-exercise.txt
echo "dmesg: ${MSG}" >> scripting-exercise.txt
echo "Root files: ${ROOT}" >> scripting-exercise.txt
echo "Web-facing files: ${WEB}" >> scripting-exercise.txt
echo "Home files: ${HOME}" >> scripting-exercise.txt
