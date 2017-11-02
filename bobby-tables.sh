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

## edit as required for shenanigans, CentOS and Ubuntu will likely need different rules.

echo -n "
Enter 0 for Pi, 1 for Ubuntu, 2 for Debian, and 3 for CentOS: "
read answer1

if [ $answer1 = "0" ]; then

## PI
echo "Firewall reset, adding Pi rules..."
$ipt -P INPUT DROP
$ipt -P FORWARD DROP
$ipt -P OUTPUT ACCEPT
$ipt -A INPUT -p udp -m multiport --dports 5060,5061 -m set --match-set fail2ban-ASTERISK src -j $ipt REJECT --reject-with icmp-port-unreachable
$ipt -A INPUT -p tcp -m multiport --dports 5060,5061 -m set --match-set fail2ban-ASTERISK src -j REJECT --reject-with icmp-port-unreachable
$ipt -A INPUT -p tcp -m multiport --dports 22 -j fail2ban-ssh
$ipt -A INPUT -m set --match-set voip_bl src -j DROP
$ipt -A INPUT -i lo -j ACCEPT
$ipt -A INPUT -p udp -m udp --dport 10000:20000 -j ACCEPT
$ipt -A INPUT -p udp -m udp --dport 2727 -j ACCEPT
$ipt -A INPUT -p udp -m udp --dport 4569 -j ACCEPT
$ipt -A INPUT -s xxx.xxx.xxx.xxx/24 -p udp -m udp --dport 5060:5061 -j ACCEPT
$ipt -A INPUT -s xxx.xxx.xxx.xxx/24 -p tcp -m tcp --dport 5060:5061 -j ACCEPT
$ipt -A INPUT -s known_external_proxy -p udp -m udp --dport 5060:5061 -j ACCEPT
$ipt -A INPUT -p udp -m udp --dport 5060:5061 -m string --string "User-Agent: VaxSIPUserAgent" --algo bm --to 65535 -j DROP
$ipt -A INPUT -p udp -m udp --dport 5060:5061 -m string --string "User-Agent: friendly-scanner" --algo bm --to 65535 -j REJECT --reject-with icmp-port-unreachable
$ipt -A INPUT -p udp -m udp --dport 5060:5061 -m string --string "REGISTER sip:" --algo bm --to 65535 -m recent --set --name VOIP --rsource
$ipt -A INPUT -p udp -m udp --dport 5060:5061 -m string --string "REGISTER sip:" --algo bm --to 65535 -m recent --update --seconds 60 --hitcount 12 --rttl --name VOIP --mask 255.255.255.255 --rsource -j DROP
$ipt -A INPUT -p udp -m udp --dport 5060:5061 -m string --string "INVITE sip:" --algo bm --to 65535 -m recent --set --name VOIPINV --rsource
$ipt -A INPUT -p udp -m udp --dport 5060:5061 -m string --string "INVITE sip:" --algo bm --to 65535 -m recent --update --seconds 60 --hitcount 12 --rttl --name VOIPINV --mask 255.255.255.255 --rsource -j DROP
$ipt -A INPUT -p tcp -m tcp --dport 5060:5061 -m hashlimit --hashlimit-upto 6/sec --hashlimit-burst 5 --hashlimit-mode srcip,dstport --hashlimit-name tunnel_limit -j ACCEPT
$ipt -A INPUT -p udp -m udp --dport 5060:5061 -m hashlimit --hashlimit-upto 6/sec --hashlimit-burst 5 --hashlimit-mode srcip,dstport --hashlimit-name tunnel_limit -j ACCEPT
$ipt -A INPUT -s xxx.xxx.xxx.xxx/24 -p icmp -j ACCEPT
$ipt -A INPUT -s xxx.xxx.xxx.xxx/24 -p tcp -m tcp --dport 137 -j ACCEPT
$ipt -A INPUT -s xxx.xxx.xxx.xxx/24 -p tcp -m tcp --dport 138 -j ACCEPT
$ipt -A INPUT -s xxx.xxx.xxx.xxx/24 -p tcp -m tcp --dport 139 -j ACCEPT
$ipt -A INPUT -s xxx.xxx.xxx.xxx/24 -p tcp -m tcp --dport 445 -j ACCEPT
$ipt -A INPUT -s xxx.xxx.xxx.xxx/24 -p tcp -m tcp --dport 10000 -j ACCEPT
$ipt -A INPUT -s xxx.xxx.xxx.xxx/24 -p tcp -m tcp --dport 22 -j ACCEPT
$ipt -A INPUT -s xxx.xxx.xxx.xxx/24 -p tcp -m tcp --dport 123 -j ACCEPT
$ipt -A INPUT -s xxx.xxx.xxx.xxx/24 -p udp -m udp --dport 123 -j ACCEPT
$ipt -A INPUT -s xxx.xxx.xxx.xxx/24 -p tcp -m tcp --dport 5038 -j ACCEPT
$ipt -A INPUT -s xxx.xxx.xxx.xxx/24 -p tcp -m tcp --dport 58080 -j ACCEPT
$ipt -A INPUT -s xxx.xxx.xxx.xxx/24 -p tcp -m tcp --dport 55050 -j ACCEPT
$ipt -A INPUT -p tcp -m tcp --dport 80 -j ACCEPT
$ipt -A INPUT -p tcp -m tcp --dport 443 -j ACCEPT
$ipt -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
$ipt -A INPUT -s xxx.xxx.xxx.xxx/24 -p tcp -m tcp --dport 514 -j ACCEPT
$ipt -A INPUT -s xxx.xxx.xxx.xxx/24 -p udp -m udp --dport 514 -j ACCEPT
$ipt -A INPUT -j DROP
$ipt -A OUTPUT -j ACCEPT

elif [ $answer1 = "2" ]; then

## DEBIAN
echo "Firewall reset, adding Debian rules..."
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

else
	echo "Error. Please run again."
	exit 1
fi
