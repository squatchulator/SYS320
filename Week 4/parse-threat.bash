#!/bin/bash

# Storyline: Extract IPs from emergingthreats.net and create a firewall ruleset

# Checks to see if network threat file exists 

function makeRules() {
	wget http://rules.emergingthreats.net/blockrules/emerging-drop.suricata.rules -O /tmp/emerging-drop.suricata.rules
	egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.0/[0-9]{1,2}' /tmp/emerging-drop.suricata.rules | sort -u | tee badIPs.txt
}

if [[ -f badIPs.txt ]]
then
	read -p "Threat file already exists; would you like to redownload it?: " answer
	case "$answer" in
		y|Y)
			echo "Downloading..."
			makeRules
		;;
		n|N)
			echo "Continuing..."
		;;
		*)
			echo "Invalid entry."
			exit 1
		;;
	esac
else
	echo "Threat file does not yet exist. Creating file..."
	makeRules
fi
clear

while getopts 'icnwmpe' OPTION ; do
	case "$OPTION" in
		i) iptables=${OPTION}
		;;
		c) cisco=${OPTION}
		;;
		n) netscreen=${OPTION}
		;;
		w) wfirewall=${OPTION}
		;;
		m) macOS=${OPTION}
		;;
		p) parseCisco=${OPTION}
		;;
		e) exit 0
		;;
		*)
			echo "Invalid entry."
			exit 1
		;;
	esac
done

if [[ ${iptables} ]]
then
	for eachip in $(cat badIPs.txt)
	do
		echo "iptables -a input -s ${eachip} -j DROP" | tee -a badIPs.iptables
	done
	clear
	echo 'IP tables for firewall drop rules now in file badIPs.iptables'
fi

if [[ ${cisco} ]]
then
	egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.0' badIPs.txt | tee badIPs.nocidr
	for eachip in $(cat badIPs.nocidr)
	do
		echo "deny ip host ${eachip} any" | tee -a badIPs.cisco
	done
	rm badIPs.nocidr
	clear
	echo 'IP tables for firewall drop rules now in file badIPs.cisco'
fi
if [[ ${wfirewall} ]]
then
	egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.0' badIPs.txt | tee badIPs.windowsform
	for eachip in $(cat badIPs.windowsform)
	do
		echo "netsh advfirewall firewall add rule name=\"BLOCK IP ADDRESS - ${eachip}\" dir=in action=block remoteip=${eachip}" | tee -a badIPs.netsh
	done
	rm badIPs.windowsform
	clear
	echo 'IP tables for firewall drop rules now in file badIPs.netsh'
fi

if [[ ${macOS} ]]
then
	echo '
	scrub-anchor "com.apple/*"
	nat-anchor "com.apple/*"
	rdr-anchor "com.apple/*"
	dummynet-anchor "com.apple/*"
	anchor "com.apple/*"
	load anchor "com.apple" from "/etc/pf.anchors/com.apple"
	' | tee pf.conf
	for eachip in $(cat badIPs.txt)
	do
		echo "block in from ${eachip} to any" | tee -a pf.conf
	done
	clear
	echo 'IP tables for firewall drop rules now in file pf.conf'
fi

if [[ ${parseCisco} ]]
then
	wget https://raw.githubusercontent.com/botherder/targetedthreats/master/targetedthreats.csv -O /tmp/targetedthreats.csv
	awk '/domain/ {print}' /tmp/targetedthreats.csv | awk -F \" '{print $4}' | sort -u > threats.txt
	echo 'class-map match-any BAD_URLS' | tee ciscothreats.txt
	for eachip in $(cat threats.txt)
	do
		echo "match protocol http host \"${eachip}\"" | tee -a ciscothreats.txt
	done
	rm threats.txt
	echo 'URL filters file created and parsed at ciscothreats.txt'
fi
