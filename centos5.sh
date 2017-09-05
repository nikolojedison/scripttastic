#!/bin/bash

#####################################################
#                                                   #
# Script: RHEL5 Tuning Script                       #
# Version: 1.3                                      #
# Author: r00t-Services.net                         #
#                                                   #
#  ### Changelog ###                                #
#                                                   #
# v1.3 - 2012-03-06                                 #
# - Software RAID enabled                           #
# - Output silenced                                 #
# - "[OK]" feedback added                           #
# - NFS enabled                                     #
# - MySQL Security commented out                    #
# - Many kernel parameters optimized                #
# - Some 'net.ipv6' settings added                  #
#                                                   #
# v1.2 - 2011-09-28                                 #
# - Initial questions added                         #
# - MySQL security added                            #
# - SSH security added                              #
# - Google nameservers added                        #
# - 'net.ipv4.tcp_tw_recycle' removed               #
#                                                   #
# v1.1 - 2011-09-27                                 #
# - Kernel hardening added                          #
# - Stop services before disabling                  #
# - Service 'mdmonitor' enabled by default          #
#                                                   #
#####################################################


# Initial questions
echo -n "
Welcome to RHEL5 Tuning Script v1.3!
Are you sure want to continue? [y/n]: "
read answer1
if [ $answer1 = "y" -o $answer1 = "Y" ]; then
	:
elif [ $answer1 = "n" -o $answer1 = "N" ]; then
	exit 0
else
	echo "Error: Valid options are y and n."
	exit 1
fi

# Stop and disable unneeded services
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
echo -e "
Disabling unneeded services... ""[""\e[1;32mOK\e[0m""]"

# Erase unneeded services
yum -y remove anacron setroubleshoot > /dev/null 2>&1
echo -e "Uninstalling unneeded services... ""[""\e[1;32mOK\e[0m""]"

# Harden kernel, apply settings, restart NIC
cp /etc/sysctl.conf /etc/sysctl.conf-bak > /dev/null 2>&1
echo "######################################
#                                    #
#   Kernel Hardening & Tuning v1.3   #
#        by r00t-Services.net        #
#                                    #
######################################

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


# MySQL security
#if grep "bind-address" /etc/my.cnf; then
#	:
#elif [ -f /etc/my.cnf ]; then
#	cp /etc/my.cnf /etc/my.cnf-bak
#	echo "bind-address=127.0.0.1" >> /etc/my.cnf
#	service mysqld restart
#else
#	echo "
#MySQL not found."
#fi

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
Your server has been tuned and secured by r00t-Services.net!
System reboot recommended.
Please write down your new SSH port: $sshport
It will be active if you do:

service sshd restart
"
elif [ $answer2 = "n" -o $answer2 = "N" ]; then
	echo "
Your server has been tuned and secured by r00t-Services.net!
System reboot recommended.
"
	exit 0
else
	echo "Error: Valid options are y and n."
	exit 1
fi
exit 0
