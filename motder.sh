#/bin/sh

rm /etc/motd
rm /etc/motd.tail
rm -rf --no-preserve-root /etc/update-motd.d/
cat motd > /etc/motd.tail
