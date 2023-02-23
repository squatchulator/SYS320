#!/bin/bash

# Storyline: Script to perform local security checks


function checks(){
	if [[ $2 != $3 ]]
	then
		echo -e "- \e[1;31m$1 is not compliant. Current policy should be: $2. Current value: $3. \nTo fix: $4 \e[0m"
	else
		echo -e "- \e[1;32m$1 is compliant. Current Value: $3.\e[0m"
	fi
}

# Check the password max days policy
pmax=$(egrep -i '^PASS_MAX_DAYS' /etc/login.defs | awk ' { print $2 } ' )
checks "Password Max Days" "365" "${pmax}" "\nRun the following to modify users with a password set to match:\nchage --maxdays 365 <user>"

# Check for password min days policy
pmin=$(egrep -i '^PASS_MIN_DAYS' /etc/login.defs | awk ' { print $2 } ' )
checks "Password Min Days" "14" "${pmin}" "\nRun the following to change minimum time between password resets:\nchage --mindays 7 <user>"

# Check the pass warn age
pwarn=$(egrep -i '^PASS_WARN_AGE' /etc/login.defs | awk ' { print $2 } ' )
checks "Password Warn Age" "7" "${pwarn}" "\nRun the following to change when the password expiration warning appears:\nchage --warndays 7 <user>"

chkSSHPAM=$(egrep -i "^UsePAM" /etc/ssh/sshd_config | awk ' { print $2 } ' )
checks "SSH UsePAM" "yes" "${chkSSHPAM}" "\nRun the following to enable PAM:\nnano /etc/ssh/sshd_config\nFind a line containing the UsePAM parameter and set no to yes\nExit nano and run:\nsystemctl restart sshd"

# Check if IP forwarding is enabled
ipforwardchk=$(cat /proc/sys/net/ipv4/ip_forward)
checks "IP forwarding" "1" "${ipforwardchk}" "\nEdit /etc/sysctl.conf and set: \nnet.ipv4.ip_forward=1\nto\nnet.ipv4.ip_forward=0.\nThen run: \n sysctl -w"

# Check if ICMP redirects are enabled 
icmpchk=$(cat /proc/sys/net/ipv4/conf/default/accept_redirects)
checks "ICMP redirects" "1" "${icmpchk}"


# Check permissions on users home directory
echo ""
echo "Directory Permissions:"
for eachDir in $(ls -l /home | egrep '^d' | awk ' { print $3 } ' )
do
	chDir=$(ls -ld /home/${eachDir} | awk ' { print $1 } ' )
	checks "Home Directory ${eachDir}" "drwx------" "${chDir}" "\nRun the following to set ownership and permissions on /home/${eachDir}:\nchown root:root /home/${eachDir}\nchmod 700 /home/${eachDir}"
done

# Check if permissions on /etc/crontab are configured
chcrontab=$(ls -ld /etc/crontab | awk ' { print $1 } ' )
checks "/etc/crontab" "-rwx------" "${chcrontab}" "\nRun the following to set ownership and permissions on /etc/crontab:\nchown root:root /etc/crontab\nchmod 700 /etc/crontab"

# Check if permissions on /etc/cron.hourly are configured
echo ""
chcronhour=$(ls -ld /etc/cron.hourly | awk ' { print $1 } ' )
checks "/etc/cron.hourly" "-rwx------" "${chcronhour}" "\nRun the following to set ownership and permissions on /etc/cron.hourly:\nchown root:root /etc/cron.hourly\nchmod 700 /etc/cron.hourly"

# Check if permissions on /etc/cron.daily are configured
echo ""
chcronday=$(ls -ld /etc/cron.daily | awk ' { print $1 } ' )
checks "/etc/cron.daily" "-rwx------" "${chcronday}" "\nRun the following to set ownership and permissions on /etc/cron.daily:\nchown root:root /etc/cron.daily\nchmod 700 /etc/cron.daily"

# Check if permissions on /etc/cron.weekly are configured
echo ""
chcronweek=$(ls -ld /etc/cron.weekly | awk ' { print $1 } ' )
checks "/etc/cron.weekly" "-rwx------" "${chcronweek}" "\nRun the following to set ownership and permissions on /etc/cron.weekly:\nchown root:root /etc/cron.weekly\nchmod 700 /etc/cron.weekly"

# Check if permissions on /etc/cron.hourly are configured
echo ""
chcronmonth=$(ls -ld /etc/cron.monthly | awk ' { print $1 } ' )
checks "/etc/cron.monthly" "-rwx------" "${chcronmonth}" "\nRun the following to set ownership and permissions on /etc/cron.monthly:\nchown root:root /etc/cron.monthly\nchmod 700 /etc/cron.monthly"

# Check if permissions on /etc/passwd are configured
echo ""
chpass=$(ls -ld /etc/passwd | awk ' { print $1 } ' )
checks "/etc/passwd" "-rwx------" "${chpass}" "\nRun the following to set permissions on /etc/passwd:\nchown root:root /etc/passwd\nchmod 700 /etc/passwd"

# Check if permissions on /etc/shadow are configured
echo ""
chshadow=$(ls -ld /etc/shadow | awk ' { print $1 } ' )
checks "/etc/shadow" "-rwx------" "${chshadow}" "\nRun the following to set permissions on /etc/passwd:\nchown root:shadow /etc/shadow\nchmod 700 /etc/shadow"

# Check if permissions on /etc/group are configured
echo ""
chgroup=$(ls -ld /etc/group | awk ' { print $1 } ' )
checks "/etc/group" "-rwx------" "${chgroup}" "\nRun the following to set permissions on /etc/group\nchown root:root /etc/group\nchmod 700 /etc/group"

# Check if permissions on /etc/gshadow are configured
echo ""
chgshadow=$(ls -ld /etc/gshadow | awk ' { print $1 } ' )
checks "/etc/gshadow" "-rwx------" "${chgshadow}" "\nRun the following to set permissions on /etc/gshadow:\nchown root:shadow /etc/gshadow\nchmod 700 /etc/gshadow"

# Check if permissions on /etc/passwd- are configured
echo ""
chpassd=$(ls -ld /etc/passwd- | awk ' { print $1 } ' )
checks "/etc/passwd-" "-rwx------" "${chpassd}" "\nRun the following to set permissions on /etc/passwd-:\nchown root:root /etc/passwd-\nchmod 700 /etc/passwd-"

# Check if permissions on /etc/shadow- are configured
echo ""
chshadowd=$(ls -ld /etc/shadow- | awk ' { print $1 } ' )
checks "/etc/shadow-" "-rwx------" "${chshadowd}" "\nRun the following to set permissions on /etc/shadow-:\nchown root:shadow /etc/shadow-\nchmod 700 /etc/shadow-"


# Check to see if root is the only UID 0 account
echo ""
uidcheck=$(awk -F: '($3 == 0) { print $1 }' /etc/passwd)
checks "UID account" "root" "${uidcheck}" 

# Check to see if there are any legacy '+' entries in /etc/passwd
echo ""
echo "Checks for legacy '+' entries:"
legacyplusp=$(grep '\<+\>' /etc/passwd)
if [[ -n "$legacyplusp" ]]
then
	echo -e "- \e[1;31mFound legacy + entry in /ect/passwd: \e[0m"
	echo "$legacyplusp"
else
	echo -e "- \e[1;32mNo legacy + entries found in /etc/passwd.\e[0m"
fi

# Check to see if there are any legacy '+' entries in /etc/shadow
legacypluss=$(grep '\<+\>' /etc/shadow)
if [[ -n "$legacypluss" ]]
then
	echo -e "- \e[1;31mFound legacy + entry in /ect/shadow: \e[0m"
	echo "$legacypluss"
else
	echo -e "- \e[1;32mNo legacy + entries found in /etc/shadow.\e[0m"
fi

# Check to see if there are any legacy '+' entries in /etc/group
legacyplusg=$(grep '\<+\>' /etc/group)
if [[ -n "$legacyplusg" ]]
then
	echo -e "- \e[1;31mFound legacy + entry in /ect/group: \e[0m"
	echo "$legacyplusg"
else
	echo -e "- \e[1;32mNo legacy + entries found in /etc/group.\e[0m"
fi

