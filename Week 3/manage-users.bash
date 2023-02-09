#!/bin/bash

# Storyline: Script to add and delete VPN peers

while getopts 'hdcau:' OPTION ; do

	case "$OPTION" in

		d) u_del=${OPTION}
		;;
		c) u_check=${OPTION}
		;;
		a) u_add=${OPTION}
		;;
		u) t_user=${OPTARG}
		;;
		h)

			echo ""
			echo "Usage: $(basename $0) [-c][-a]|[-d] -u username"
			echo ""
			exit 1

		;;

		*)

			echo "Invalid value."
			exit 1

		;;
	esac
done

# Check to see if the -a and -d are empty or if they are both specified, then error
if [[ (${u_del} == "" && ${u_add} == "") || (${u_del} != ""  && ${u_add} != "") ]]
then

	echo "Please specify -a, -c, or -d, as well as -u followed by the username."

fi

# Check to ensure -u is specified

if [[ (${u_del} != "" || ${u_add} != "") && ${t_user} == "" ]]
then

	echo "Please specify a user (-u)!"
	echo "Usage: $(basename $0) [-a][-d] -u username"
	exit 1
fi

# Delete a user
if [[ ${u_del} ]]
then
	echo "Deleting user ${t_user}..."
	sed -i "/# ${t_user} begin/,/# ${t_user} end/d" wg0.conf
fi

# Add a user
if [[ ${u_add} ]]
then

	echo "Creating the user ${t_user}..."
	bash peer.bash ${t_user}

fi

# Check for a user
if [[ ${u_check} ]]
then

	if [[ -n $(awk "/# ${t_user} begin/,/# ${t_user} end/" wg0.conf) ]]
	then
		echo "${t_user} already exists in the configuration file."
	else
		echo "${t_user} does NOT exist in the configuration file."
	fi
fi
