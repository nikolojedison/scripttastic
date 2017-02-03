#!/bin/bash
#a simple backup script for ccdc#
#add directories as required to DATA with the format /[path]/[to]/[dir]/#
 
DATA="/home /root /etc"
 
#choose where you want to pipe the backup to below#
tar cfzp "/scratcher.tgz" $DATA --same-owner
