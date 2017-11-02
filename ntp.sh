echo -n "
Enter the NTP server you wish to connect to: "
read ntpserv
ntpdate $ntpserv
