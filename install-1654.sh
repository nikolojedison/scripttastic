#!/bin/bash
apt-get update
apt-get clean all
echo -e "y\ny\ny" | apt-get install --reinstall coreutils debian-archive-keyring ntp
echo -e "y\n" | apt-get upgrade
echo -e "y\ny\ny\ny" | apt-get install selinux-basics selinux-policy-default auditd snort
