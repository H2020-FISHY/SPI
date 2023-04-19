#!/bin/bash -e
#expecting interfaces as envronment variable following patter:
#INTERFACES_UP="eth0:123.123.123.123/24 eth1:124.124.124.3/26"
INTERFACE_DEFS=($INTERFACES_UP)

echo "Configuring IP addresses, expecting config in environment variable like this: INTERFACES_UP=\"eth0:123.123.123.123/24 eth1:124.124.124.3/26\""
for i in "${!INTERFACE_DEFS[@]}"
do
	IF=$(cut -d : -f 1 <<< ${INTERFACE_DEFS[$i]})
	IP=$(cut -d : -f 2 <<< ${INTERFACE_DEFS[$i]})
	if [[ -n $(ip address show $IF | grep $IP) ]]; then
		echo "address $IP for interface $IF is already set"
	else	
		echo "setting $IF address to $IP..."
		if ip addr add $IP dev $IF; then
			echo "IP $IP for interface $IF set successfully"
			echo "bringing up interface $IF..."
			else
			echo "unable to set IP address for interface $IF"
		fi
	fi
	if ip link set $IF up; then
		echo "brought $IF up successfully"
		else
		echo "unable to bring up interface $IF"
	fi
done
echo "Interfaces:"
ip addr

echo "Chrooting to keycloak user & executing keycloak entrypoint script"
exec chroot --userspec=1000 / /opt/keycloak/bin/kc.sh "$@"
