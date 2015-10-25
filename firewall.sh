#!/bin/bash
### BEGIN INIT INFO
# Provides:          firwall
# Required-Start:    $remote_fs $syslog
# Required-Stop:     $remote_fs $syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Configuring firwall with iptables
# Description:	     Close all port and open only used port 
### END INIT INFO
#  Script pour firewall iptable

green='\e[0;32m'
nocolor='\e[0m'

# interface reseau concernée
EXT="eth0 eth1"

SSH_PORT="22"
GLASSFISH_ADMIN="4848"
POP="110"
IMAP="143"
SMTP="25"
DNS="53"

# Service offert par le serveur 
TCP_SERVICES="$SSH_PORT https http $GLASSFISH_ADMIN $IMAP $SMTP $DNS"
UDP_SERVICES="$DNS"

# Service que le serveur utilisera sur le réseau
REMOTE_TCP_SERVICES="$SSH_PORT https http $IMAP $SMTP $DNS"
REMOTE_UDP_SERVICES="$DNS"

# si iptables n'est pas une commande exécutable
if ! [ -x /sbin/iptables ]; then
	echo 'iptables cannot be exec (sudo service firewall {start|restart|stop|clear})'
	exit 0
fi

ok() {
	echo -e "\b\b\b\b${green}OK${nocolor} ]"
}

fw_clear() {
	/sbin/iptables -F
	/sbin/iptables -P INPUT ACCEPT
	/sbin/iptables -P OUTPUT ACCEPT
	/sbin/iptables -P FORWARD ACCEPT
}

fw_stop() {
	/sbin/iptables -F
	/sbin/iptables -P INPUT DROP
	/sbin/iptables -P FORWARD DROP
	/sbin/iptables -P OUTPUT ACCEPT
}


fw_start() {
		echo -n "Flush rules [...]"

	/sbin/iptables -t filter -F
	/sbin/iptables -t filter -X
	/sbin/iptables -t nat -F
	/sbin/iptables -t nat -X
	ok

	# On refuse tout par défaut. Le serveur refusera toutes les connections quelque soit la provenance.

		echo -n "Create default rules [...]"

	/sbin/iptables -P INPUT DROP
	/sbin/iptables -P FORWARD DROP
	/sbin/iptables -P OUTPUT DROP
	ok

	# On définit les ports ouverts

		echo -n "Activate loopback [...]"

	## {Etablissement d'une connexion sur lui même (loopback)}
	/sbin/iptables -A INPUT -i lo -j ACCEPT
	/sbin/iptables -A OUTPUT -o lo -j ACCEPT
	ok

	# On autorise les connexions relatives à une autre.
	/sbin/iptables -A OUTPUT --match state --state ESTABLISHED,RELATED -j ACCEPT
	/sbin/iptables -A INPUT --match state --state ESTABLISHED,RELATED -j ACCEPT

	# Ouverture des ports

	for interface in $EXT; do

			echo -n "configure $interface [...]"

		# Entrées autorisées
		if [ -n "$TCP_SERVICES" ] ; then
			for PORT in $TCP_SERVICES; do
				/sbin/iptables -A INPUT -i ${interface} -p TCP --dport ${PORT} -j ACCEPT
			done
		fi

		if [ -n "$UDP_SERVICES" ] ; then
			for PORT in $UDP_SERVICES; do
				/sbin/iptables -A INPUT -i ${interface} -p UDP --dport ${PORT} -j ACCEPT
			done
		fi

		# Sorties autorisées
		if [ -n "$REMOTE_TCP_SERVICES" ] ; then
			for PORT in $REMOTE_TCP_SERVICES; do
				/sbin/iptables -A OUTPUT -o ${interface} -p TCP --dport ${PORT} -j ACCEPT
			done
		fi

		if [ -n "$REMOTE_UDP_SERVICES" ] ; then
			for PORT in $REMOTE_UDP_SERVICES; do
				/sbin/iptables -A OUTPUT -o ${interface} -p UDP --dport ${PORT} -j ACCEPT
			done
		fi

		ok
	done

	# Protection supplémentaire
	# Ne garde pas les connections semi ouverte pour les attaques deni service par SYN (transaction SYN ACK ...)
	echo 1 > /proc/sys/net/ipv4/tcp_syncookies
	# Garde maximum 1024 requête temporaire de SYN
	echo 1024 > /proc/sys/net/ipv4/tcp_max_syn_backlog

	echo 0 > /proc/sys/net/ipv4/ip_forward
	# Permet d'éviter les attaques smurf attack
	echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts
	# active le log des paquets aux adresses sources falficiées ou non routables
	echo 1 > /proc/sys/net/ipv4/conf/all/log_martians

	# Permet de vérifier qu'un paquet arrive bien par l'interface sur laquelle il devrait arriver ?
	echo 1 > /proc/sys/net/ipv4/conf/all/rp_filter

	for IP_SPAM in $IP_SPAM_LIST; do
		# Quelques address qui font un peu de spam
		/sbin/iptables -A INPUT -s $IP_SPAM -j DROP
	done

}

fw_ping_active () {
	for interface in $EXT; do
		/sbin/iptables -A INPUT -i ${interface} -p ICMP -j ACCEPT
		/sbin/iptables -A OUTPUT -o ${interface} -p ICMP -j ACCEPT
	done
}

fw_ping_desactive () {
	 for interface in $EXT; do
		/sbin/iptables -D INPUT -i ${interface} -p ICMP -j ACCEPT
		/sbin/iptables -D OUTPUT -o ${interface} -p ICMP -j ACCEPT
	done
}

case $1 in
	start|restart)
		echo "start firewall [...]"
		fw_stop
		fw_start
		echo -n "start firewall [...]"
		ok
		;;
	stop)
		echo -n "stop firewall [...]"
		fw_stop
		ok
		;;
	clear)
		echo -n "Clear rules [...]"
		fw_clear
		ok
		;;
	ping)
		echo -n "Active ping [...]"
		fw_ping_active
		ok
		;;
	unping)
		echo -n "Desactive ping [...]"
		fw_ping_desactive
		ok
		;;
	*)
		echo "Use : $0 {start|restart|stop|clear|ping|unping}"
		exit 1
		;;
esac
exit 0
