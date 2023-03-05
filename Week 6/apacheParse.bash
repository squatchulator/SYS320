#!/bin/bash

# Storyline: Parser for an Apache log file; extracts IPs from file
# to create a list of IPs for the Windows and Linux firewall.

# Reads user input for name of log file
read -p "Please enter an apache log file: " APACHE_LOG
if [[ ! -f ${APACHE_LOG} ]]
then
	echo "Please specify the path to a valid log file."
	exit 1
fi

# Runs until the end of the specified log file
for badIP in $( \
sed -e 's/\[//g' -e 's/"//g' "${APACHE_LOG}" | \
# Remove unwanted characters from the log file
grep -Ei 'test|shell|echo|passwd|select|phpmyadmin|setup|admin|w00t' | \
# Searches for lines containing these keywords
awk '{ print $1 }' | sort -u )
# Extracts the IPs from the first field in a line of the log file
do
	echo "netsh advfirewall firewall add rule add rule name=\"BLOCK IP ADDRESS - ${badIP}\" dir=in action=block remoteip=${badIP}" >> blockedips.ps1
	echo "iptables -A INPUT -s ${badIP} -j DROP" >> blockedips.iptables
done
