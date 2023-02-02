#!/bin/bash

# Storyline: Create peer VPN configuration file

# What is the peer's name?
echo -n "What is the name for the peer?: "
read the_client
# Filename Variable
pFile="${the_client}-wg0.conf"
echo "${pFile}"
# Check if the peer file exists
if [[ -f "${pFile}" ]]
then
	echo "The file ${pFile} already exists."
	echo -n "Would you like to overwrite it? [Y|N]: "
	read to_overwrite
	
	if [[ "${to_overwrite}" == "N" || "${to_overwrite}" == "n" || "${to_overwrite}" == "" ]]
	then
		echo "Exit..."
		exit 0
	elif [[ "${to_overwrite}" == "Y" || "${to_overwrite}" == "y" ]]
	then
		echo "Creating the wireguard configuration file..."
	else
		echo "Invalid value."
		exit 1
	fi
fi 

# Generate private key
p="$(wg genkey)"
# Generate public key
clientPub="$(echo ${p} | wg pubkey)"
# Generate a preshared key
pre="$(wg genpsk)"
# Endpoint
end="$(head -1 /etc/wireguard/wg0.conf | awk ' { print $3 } ')"
# Server Public Key
pub="$(head -1 /etc/wireguard/wg0.conf | awk ' { print $4 } ')"
# DNS Servers
dns="$(head -1 /etc/wireguard/wg0.conf | awk ' { print $5 } ')"
# MTU
mtu="$(head -1 /etc/wireguard/wg0.conf | awk ' { print $6 } ')"
# KeepAlive
keep="$(head -1 /etc/wireguard/wg0.conf | awk ' { print $7 } ')"
# Listen Port
lport="$(shuf -n1 -i 40000-50000)"
# Default Routes for VPN
routes="$(head -1 /etc/wireguard/wg0.conf | awk ' { print $8 } ')"

# Create the client (peer) configuration file
echo "[Interface]
Address = 10.254.132.100/24
DNS = ${dns}
ListenPort = ${lport}
MTU = ${mtu}
PrivateKey = ${p}

[Peer]
AllowedIPs = ${routes}
PersistentKeepAlive = ${keep}
PresharedKey =  ${pre}
PublicKey = ${pub}
Endpoint = ${end}
" > /etc/wireguard/${pFile}

# Add our peer configuration to the server config
echo "

# ${the_client} begin
[Peer]
PublicKey = ${clientPub}
PresharedKey = ${pre}
AllowedIPs = 10.254.132.100/32
# ${the_client} end" | tee -a /etc/wireguard/wg0.conf

echo "
sudo cp wg0.conf /etc/wireguard
sudo wg addconf wg0 <(wg-quick strip wg0)
"
