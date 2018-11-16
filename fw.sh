#!/bin/bash

CUR_DIR=`pwd`
echo $CUR_DIR

echo -n "
Enter 0 for Pi, 1 for Ubuntu, 2 for Debian, and 3 for CentOS: "
read answer1

echo "IPTabling..."
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

echo "Disabling syn floods..."
sysctl -w net.ipv4.tcp_syncookies=1 > /dev/null
echo "net.ipv4.tcp_syncookies=1" >> /etc/sysctl.conf

echo "Limiting tty..."
echo "tty1" > /etc/securetty

## Pi
if [ $answer1 = "0" ]; then
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

## Ubuntu
elif [ $answer1 = "1" ]; then
echo "Firewall reset, adding Ubuntu rules..."
$ipt -P INPUT DROP
$ipt -P FORWARD DROP
$ipt -P OUTPUT ACCEPT
$ipt -A INPUT -p tcp --dport 22 -s 172.20.0.0/16 -m state --state NEW,ESTABLISHED -j ACCEPT
$ipt -A OUTPUT -p tcp --sport 22 -d 172.20.0.0/16 -m state --state ESTABLISHED -j ACCEPT
$ipt -A INPUT -i eth0 -m state --state ESTABLISHED,RELATED -j ACCEPT
$ipt -A OUTPUT -o eth0 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
$ipt -A INPUT -p icmp --icmp-type 8 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
$ipt -A OUTPUT -p icmp --icmp-type 0 -m state --state ESTABLISHED,RELATED -j ACCEPT
$ipt -A INPUT -j LOG
$ipt -A FORWARD -j LOG

# change these as needed on a port-by-port basis
$ipt -A INPUT -p tcp --dport 3306 -j ACCEPT

## Debian
elif [ $answer1 = "2" ]; then
echo "Firewall reset, adding Debian rules..."
$ipt -P INPUT DROP
$ipt -P FORWARD DROP
$ipt -P OUTPUT ACCEPT
$ipt -A INPUT -p tcp --dport 22 -s 172.20.0.0/16 -m state --state NEW,ESTABLISHED -j ACCEPT
$ipt -A OUTPUT -p tcp --sport 22 -d 172.20.0.0/16 -m state --state ESTABLISHED -j ACCEPT
$ipt -A INPUT -i eth0 -m state --state ESTABLISHED,RELATED -j ACCEPT
$ipt -A OUTPUT -o eth0 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
$ipt -A INPUT -p icmp --icmp-type 8 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
$ipt -A OUTPUT -p icmp --icmp-type 0 -m state --state ESTABLISHED,RELATED -j ACCEPT
$ipt -A INPUT -j LOG
$ipt -A FORWARD -j LOG

$ipt -A INPUT -p tcp --dport 3306 -j ACCEPT

# change these as needed on a port-by-port basis
#$ipt -A INPUT -p tcp --dport 139 -j ACCEPT
#$ipt -A INPUT -p tcp --dport 57193 -j ACCEPT
#$ipt -A INPUT -p tcp --dport 57194 -j ACCEPT
#$ipt -A INPUT -p tcp --dport 389 -j ACCEPT
#$ipt -A INPUT -p tcp --dport 52949 -j ACCEPT
#$ipt -A INPUT -p tcp --dport 3306 -j ACCEPT
#$ipt -A INPUT -p tcp --dport 34891 -j ACCEPT
#$ipt -A INPUT -p tcp --dport 80 -j ACCEPT
#$ipt -A INPUT -p tcp --dport 445 -j ACCEPT
#$ipt -A INPUT -p tcp --dport 143 -j ACCEPT
#$ipt -A INPUT -p tcp --dport 25 -j ACCEPT
#$ipt -A INPUT -p tcp --dport 110 -j ACCEPT
#$ipt -A INPUT -p tcp --dport 123 -j ACCEPT
#$ipt -A INPUT -p tcp --dport 514 -j ACCEPT
#$ipt -A INPUT -p tcp --dport 587 -j ACCEPT
#$ipt -A INPUT -p tcp --dport 636 -j ACCEPT
#$ipt -A INPUT -p tcp --dport 993 -j ACCEPT
#$ipt -A INPUT -p tcp --dport 995 -j ACCEPT
#$ipt -A INPUT -p tcp --dport 1433 -j ACCEPT
#$ipt -A INPUT -p tcp --dport 1434 -j ACCEPT

## CentOS
elif [ $answer1 = "3" ]; then
echo "Firewall reset, adding CentOS rules..."

PUB_IF="eth0"
SPAMLIST="blockedip"
SPAMDROPMSG="BLOCKED IP DROP"

$ipt -A INPUT -i ${PUB_IF} -p tcp ! --syn -m state --state NEW  -m limit --limit 5/m --limit-burst 7 -j LOG --log-level 4 --log-prefix "Drop Sync"
$ipt -A INPUT -i ${PUB_IF} -p tcp ! --syn -m state --state NEW -j DROP
$ipt -A INPUT -i ${PUB_IF} -f  -m limit --limit 5/m --limit-burst 7 -j LOG --log-level 4 --log-prefix "Fragments Packets"
$ipt -A INPUT -i ${PUB_IF} -f -j DROP
$ipt  -A INPUT -i ${PUB_IF} -p tcp --tcp-flags ALL FIN,URG,PSH -j DROP
$ipt  -A INPUT -i ${PUB_IF} -p tcp --tcp-flags ALL ALL -j DROP
$ipt  -A INPUT -i ${PUB_IF} -p tcp --tcp-flags ALL NONE -m limit --limit 5/m --limit-burst 7 -j LOG --log-level 4 --log-prefix "NULL Packets"
$ipt  -A INPUT -i ${PUB_IF} -p tcp --tcp-flags ALL NONE -j DROP # NULL packets
$ipt  -A INPUT -i ${PUB_IF} -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
$ipt  -A INPUT -i ${PUB_IF} -p tcp --tcp-flags SYN,FIN SYN,FIN -m limit --limit 5/m --limit-burst 7 -j LOG --log-level 4 --log-prefix "XMAS Packets"
$ipt  -A INPUT -i ${PUB_IF} -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP #XMAS
$ipt  -A INPUT -i ${PUB_IF} -p tcp --tcp-flags FIN,ACK FIN -m limit --limit 5/m --limit-burst 7 -j LOG --log-level 4 --log-prefix "Fin Packets Scan"
$ipt  -A INPUT -i ${PUB_IF} -p tcp --tcp-flags FIN,ACK FIN -j DROP # FIN packet scans
$ipt  -A INPUT -i ${PUB_IF} -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP
$ipt -A INPUT -i eth0 -m state --state ESTABLISHED,RELATED -j ACCEPT
$ipt -A OUTPUT -o eth0 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
$ipt -A INPUT -p icmp --icmp-type 8 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
$ipt -A OUTPUT -p icmp --icmp-type 0 -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow ssh only in local subnet
$ipt -A INPUT -p tcp --dport 22 -s 172.20.0.0/16 -m state --state NEW,ESTABLISHED -j ACCEPT
$ipt -A OUTPUT -p tcp --sport 22 -d 172.20.0.0/16 -m state --state ESTABLISHED -j ACCEPT

# Allow http/https in/output
$ipt -A INPUT -p tcp --destination-port 80 -j ACCEPT
$ipt -A OUTPUT -p tcp --dport 80 -j ACCEPT
$ipt -A INPUT -p tcp --dport 443 -j ACCEPT
$ipt -A OUTPUT -p tcp --dport 443 -j ACCEPT

# Limit connection limits. Prevent dos attacks.
$ipt -I INPUT -p tcp --dport 80 -m connlimit --connlimit-above 20 --connlimit-mask 32 -j DROP
$ipt -I INPUT -p tcp --dport 443 -m connlimit --connlimit-above 20 --connlimit-mask 32 -j DROP

$ipt -A INPUT -j LOG
$ipt -A FORWARD -j LOG
echo "Enabling kernel auditing..."
chkconfig auditd on

# Harden kernel, apply settings, restart NIC
echo "Hardening kernel..."
yes | cp /etc/sysctl.conf /etc/sysctl.conf-bak
echo "
kernel.printk = 4 4 1 7
kernel.panic = 10
kernel.sysrq = 0
kernel.shmmax = 4294967296
kernel.shmall = 3774873
kernel.msgmni = 2048
kernel.core_uses_pid = 1
kernel.msgmnb = 65536
kernel.msgmax = 65536
vm.swappiness = 30
vm.vfs_cache_pressure = 50
fs.file-max = 359208
net.core.rmem_default = 256960
net.core.rmem_max = 4194304
net.core.wmem_default = 256960
net.core.wmem_max = 4194304
net.core.optmem_max = 57344
net.core.netdev_max_backlog = 3000
net.core.somaxconn = 3000
net.ipv4.route.flush = 1
net.ipv4.conf.all.bootp_relay = 0
net.ipv4.icmp_ratelimit = 20
net.ipv4.icmp_ratemask = 88089
net.ipv4.ipfrag_high_thresh = 512000
net.ipv4.ipfrag_low_thresh = 446464
net.ipv4.tcp_wmem = 4096 87380 4194304
net.ipv4.tcp_rmem = 4096 87380 4194304
net.ipv4.tcp_mem = 512000 1048576 4194304
net.ipv4.tcp_max_tw_buckets = 1440000
net.ipv4.ip_conntrack_max = 1048576
net.ipv4.netfilter.ip_conntrack_max = 1048576
net.ipv4.ip_forward = 1
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 1
net.ipv4.conf.default.forwarding = 1
net.ipv4.conf.all.forwarding = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 1
net.ipv4.conf.all.shared_media = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.default.secure_redirects = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_window_scaling = 0
net.ipv4.tcp_rfc1337 = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.default.proxy_arp = 0
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_sack = 0
net.ipv4.tcp_ecn = 0
net.ipv4.tcp_fin_timeout = 20
net.ipv4.tcp_keepalive_intvl = 15
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_no_metrics_save = 1
net.ipv6.conf.default.disable_ipv6=1
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.secure_redirects = 0
net.ipv6.conf.default.secure_redirects = 0" > /etc/sysctl.conf
sysctl -p
perl -npe 's/ca::ctrlaltdel:\/sbin\/shutdown/#ca::ctrlaltdel:\/sbin\/shutdown/' -i /etc/inittab

fi

yes | cp /etc/resolv.conf /etc/resolv.conf-bak
echo "nameserver 8.8.8.8
nameserver 172.20.241.27
nameserver 8.8.4.4" > /etc/resolv.conf
wall <<ENDOFWALL
Firewall updated.
ENDOFWALL
