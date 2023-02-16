#!/bin/bash

# Storyline: Menu for admin, VPN, and Security Functions

function invalid_opt() {

	echo ""
	echo "Invalid option"
	echo ""
	sleep 2


}
function menu() {
	# Just clears the screen
	clear

	echo "[1] Admin Menu"
	echo "[2] Security Menu"
	echo "[3] Exit"
	read -p "Please enter a choice above: " choice

	case "$choice" in

		1) admin_menu
		;;
		2) security_menu
		;;
		3) exit 0
		;;
		*)

			invalid_opt
			# Call the main menu
			menu
		;;
	esac
}

function admin_menu() {

	clear
	echo "[L]ist Running Processes"
	echo "[V]PN Menu"
	echo "[B]ack"
	echo "[4] Exit"
	read -p "Please enter a choice above: " choice

	case "$choice" in
		L|l) ps -ef |less
		;;
		N|n) netstat -an --inet |less
		;;
		V|v) vpn
		;;
		B|b) menu 
		;;
		4) exit 0
		;;

		*)
			invalid_opt

		;;
	esac
admin_menu
}
function security_menu () {
	clear
	echo "[L]ist all open network sockets"
	echo "[C]heck for users with UID of 0"
	echo "[D]isplay last 10 logged in users"
	echo "[S]how currently logged in users"
	echo "[B]lock list menu"
	echo "[G]o back"
	read -p "Please enter a choice above: " choice

	case "$choice" in

                L|l) netstat -an --inet |less
		;;
		C|c) id -nu 0 |less
		;;
		D|d) last -n 10 |less
		;;
		S|s) w less
		;;
		B|b) block_menu
		;;
		G|g) menu
		;;
		*)
			invalid_opt
		;;
	esac
security_menu
}
function vpn() {
	clear

	echo "[A]dd a peer"
	echo "[D]elete a peer"
	echo "[B]ack to admin menu"
	echo "[M]ain menu"
	echo "[E]xit"
	read -p "Please select an option: " choice

	case "$choice" in

		A|a)

		 bash peer.bash
	 	 tail -6 wg0.conf |less
		;;
		D|d) #  Create a prompt for the user to delete
		     #  Call the manage-user.bash and pass the proper switches and arguement to delete the user
		;;
		B|b) admin_menu
		;;
		M|m) menu
		;;
		E|e) exit 0
		;;
		*)
			invalid_opt

		;;

	esac
vpn
}
function block_menu() {
	clear
	echo Generate a blocklist for:
	echo "[I]P tables"
	echo "[C]isco"
	echo "[W]indows"
	echo "[M]acOS"
	echo "[P]arse Cisco URL"
	echo "[B]ack"
	read -p "Please select an option: " choice
	
	case "$choice" in 
	
		I|i) bash parse-threat.bash -i
		;;
		C|c) bash parse-threat.bash -c
		;;
		N|n) bash parse-threat.bash -n
		;;
		W|w) bash parse-threat.bash -w
		;;
		M|m) bash parse-threat.bash -m
		;;
		P|p) bash parse-threat.bash -p
		;;
		B|b) menu
		;;
		*)
			invalid_opt
		;;
	esac
block_menu	
}
# Call the main function
menu
