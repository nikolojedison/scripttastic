#!/bin/sh

NAME=`(uname -a)`
MSG=`(dmesg | tail -n 10)`
ROOT=`(ls -a /)`
WEB=`(ls -a /var/www/)`
HOME=`(ls -a /home/)`

echo "Name: ${NAME}"
echo "dmesg: ${MSG}"
echo "Root files: ${ROOT}"
echo "Web-facing files: ${WEB}"
echo "Home files: ${HOME}"

echo "Name: ${NAME}" >> sysinfo.log
echo "dmesg: ${MSG}" >> sysinfo.log
echo "Root files: ${ROOT}" >> sysinfo.log
echo "Web-facing files: ${WEB}" >> sysinfo.log
echo "Home files: ${HOME}" >> sysinfo.log
