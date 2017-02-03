#/bin/sh

rm /etc/motd
echo "Please edit the motd file and run this script again if you want a customised MOTD."
cat motd > /etc/motd
