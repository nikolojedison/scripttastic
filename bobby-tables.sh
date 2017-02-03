#!/bin/sh

## stolen from nixcraft

echo "Stopping firewall and allowing everyone..."
ipt="/sbin/iptables"
## Failsafe - die if /sbin/iptables not found 
[ ! -x "$ipt" ] && { echo "$0: \"${ipt}\" command not found."; exit 1; }
$ipt -P INPUT ACCEPT
$ipt -P FORWARD ACCEPT
$ipt -P OUTPUT ACCEPT
$ipt -F
$ipt -X
$ipt -t nat -F
$ipt -t nat -X
$ipt -t mangle -F
$ipt -t mangle -X
$ipt -t raw -F 
$ipt -t raw -X
echo "Firewall reset, adding rules..."
$ipt -P INPUT DROP
$ipt -P FORWARD DROP
$ipt -P OUTPUT ACCEPT
$ipt -A INPUT -p tcp --dport 139 -j ACCEPT
$ipt -A INPUT -p tcp --dport 57193 -j ACCEPT
$ipt -A INPUT -p tcp --dport 57194 -j ACCEPT
$ipt -A INPUT -p tcp --dport 389 -j ACCEPT
$ipt -A INPUT -p tcp --dport 52949 -j ACCEPT
$ipt -A INPUT -p tcp --dport 3306 -j ACCEPT
$ipt -A INPUT -p tcp --dport 34891 -j ACCEPT
$ipt -A INPUT -p tcp --dport 80 -j ACCEPT
$ipt -A INPUT -p tcp --dport 445 -j ACCEPT
$ipt -A INPUT -p tcp --dport 143 -j ACCEPT
$ipt -A INPUT -p tcp --dport 25 -j ACCEPT
$ipt -A INPUT -p tcp --dport 110 -j ACCEPT
$ipt -A INPUT -p tcp --dport 123 -j ACCEPT
$ipt -A INPUT -p tcp --dport 514 -j ACCEPT
$ipt -A INPUT -p tcp --dport 587 -j ACCEPT
$ipt -A INPUT -p tcp --dport 636 -j ACCEPT
$ipt -A INPUT -p tcp --dport 993 -j ACCEPT
$ipt -A INPUT -p tcp --dport 995 -j ACCEPT
$ipt -A INPUT -p tcp --dport 1433 -j ACCEPT
$ipt -A INPUT -p tcp --dport 1434 -j ACCEPT
