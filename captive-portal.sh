#!/bin/bash

# Project Byzantium: captive-portal.sh
# This script does the heavy lifting of IP tables manipulation under the
# captive portal's hood.  It should only be used by the captive portal daemon.

# Written by Sitwon, The Doctor, and haxwithaxe.
# Copyright (C) 2013 Project Byzantium
# This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or any later version.

IPTABLES=/usr/sbin/iptables
ARP=/sbin/arp

# NB: bash scope is heretable if the parent function  has the variable the child can access it.

get_netblock_from_address() {
    # Convert the IP address of the client interface into a netblock.
	case $2 in 
		8)
            CLIENTNET=`awk -F'.' '{ print $1".0.0.0/8" }' <<< $1`
			;;
		16)
			CLIENTNET=`awk -F'.' '{ print $1"."$2"."0.0/16" }' <<< $1`
			;;
		*)
			CLIENTNET=`awk -F'.' '{ print $1"."$2"."$3"."0/24" }' <<< $1`
			;;
	esac
}

exempt_nonclient_traffic() {
	# Exempt traffic which does not originate from the client network.
	$IPTABLES -t mangle -A PREROUTING ! -s $CLIENTNET -j RETURN
}

grab_new_clients() {
	# Traffic not exempted by the previous rules gets kicked to the captive
	# portal chain.  When a user clicks through a rule is inserted before
	# this one that matches them with a RETURN.
	$IPTABLES -t mangle -A PREROUTING -j internet
}

get_client_mac() {
	CLIENTMAC=`$ARP -n | grep ':' | grep $CLIENT | awk '{print $3}'`
}

mark_new_clients() {
	# Traffic not coming from an accepted user gets marked 99.
	$IPTABLES -t mangle -A internet -j MARK --set-mark 99
}

iptables_redir_marked() {
	rule=PREROUTING
	proto=$2
	port=$3
	clientip=$4
	dport=$5
	$IPTABLES -t nat -A $rule -m mark --mark 99 -p $proto --dport $port
	-j DNAT --to-destination $clientip:$dport
}

iptables_unredir_marked() {
	rule=POSTROUTING
    proto=$2
    port=$3
    client_net=$4
    sport=$5
    $IPTABLES -t nat -A $rule -d $client_net -p $proto --sport $port \
            -j SNAT --to-source :$sport
}

redirect_marked_to_portal() {
	# Traffic which has been marked 99 and is headed for 80/TCP or 443/TCP
    # should be redirected to the captive portal web server.
    iptables_redir_marked tcp 80 $CLIENTIP 31337
    iptables_redir_marked tcp 443 $CLIENTIP 31338
    iptables_redir_marked udp 53 $CLIENTIP 31339
}

redirect_marked_from_portal() {
	# HTTP replies come from the same port the requests were received by.
    # Rewrite the outbound packets to appear to come from the appropriate
    # ports.
    iptables_unredir_marked tcp 31337 $CLIENTNET 80
    iptables_unredir_marked tcp 31338 $CLIENTNET 443
    # Replies from fake_dns.py come from the same port because they're
    # UDP.  Rewrite the packet headers so it loos like it's from port
    # 53/udp.
    iptables_unredir_marked udp 31339 $CLIENTNET 53
}

drop_nonexempt_marked() {
    # All other traffic which is marked 99 is just dropped
	$IPTABLES -t filter -A FORWARD -m mark --mark 99 -j DROP
}

allow_incoming() {
	$IPTABLES -t filter -A INPUT -j ACCEPT
}

add_client() {
    # Isolate the MAC address of the client in question.
    CLIENTMAC=`$ARP -n | grep ':' | grep $CLIENT | awk '{print $3}'`
    # Add the MAC address of the client to the whitelist, so it'll be able
    # to access the mesh even if its IP address changes.
    $IPTABLES -t mangle -I internet -m mac --mac-source $CLIENTMAC -j RETURN
	return 0
}

remove_client(){
    # Isolate the MAC address of the client in question.
    CLIENTMAC=''
    get_client_mac
    # Delete the MAC address of the client from the whitelist.
    $IPTABLES -t mangle -D internet -m mac --mac-source \
    $CLIENTMAC -j RETURN
    return 0
}

iptables_purge() {
    # Purge all of the IP tables rules.
    $IPTABLES -F
    $IPTABLES -X
    $IPTABLES -t nat -F
    $IPTABLES -t nat -X
    $IPTABLES -t mangle -F
    $IPTABLES -t mangle -X
    $IPTABLES -t filter -F
	$IPTABLES -t filter -X
}

iptables_list() {
    # Display the currently running IP tables ruleset.
    $IPTABLES --list -n
    $IPTABLES --list -t nat -n
    $IPTABLES --list -t mangle -n
	$IPTABLES --list -t filter -n
}

iptables_init_mangle() {
	# Initialize the IP tables ruleset by creating a new chain for captive
    # portal users.
	$IPTABLES -N internet -t mangle
}

init_captive_portal(){
        # Initialize the IP tables ruleset by creating a new chain for captive
        # portal users.
        iptables_init_mangle

        # Convert the IP address of the client interface into a netblock.
        get_netblock_from_address $CLIENTIP $CIDRMASK

        # Exempt traffic which does not originate from the client network.
        exempt_nonclient_traffic

        # Traffic not exempted by the above rules gets kicked to the captive
        # portal chain.  When a use clicks through a rule is inserted above
        # this one that matches them with a RETURN.
        grab_new_clients    

        # Traffic not coming from an accepted user gets marked 99.
        mark_new_clients

        # Traffic which has been marked 99 and is headed for 80/TCP or 443/TCP
        # should be redirected to the captive portal web server.
        redirect_marked_to_portal

        # HTTP replies come from the same port the requests were received by.
        # Rewrite the outbound packets to appear to come from the appropriate
        # ports. Also replies from fake_dns.py come from the same port because
        # they're UDP.  Rewrite the packet headers so it loos like it's from port
        # 53/udp.
        redirect_marked_from_portal

        # All other traffic which is marked 99 is just dropped
        $IPTABLES -t filter -A FORWARD -m mark --mark 99 -j DROP

        # Allow incoming traffic that is headed for the local node.
        allow_incoming

        # But reject anything else coming from unrecognized users.
        $IPTABLES -t filter -A INPUT -m mark --mark 99 -j DROP
}


# Set up the choice tree of options that can be passed to this script.
case "$1" in
    'initialize')
        # $2: IP address of the client interface.  Assumes final octet is .1.
        CLIENTIP=$2
		CIDRMASK=${3:-24}
        CLIENTNET=''
		init_captive_portal $CLIENTIP $CIDRMASK
        exit 0
        ;;

	'add')
        # $2: IP address of client.
        CLIENT=$2
		add_client
		exit 0
		;;
    'remove')
        # $2: IP address of client.
        CLIENT=$2
		remove_client
		exit 0
		;;
    'purge')
        # Purge all of the IP tables rules.
		iptables_purge
        exit 0
        ;;

    'list')
        # Display the currently running IP tables ruleset.
		iptables_list
        exit 0
        ;;

    *)
        echo "USAGE: $0 {initialize <IP> <interface>|add <IP> <interface>|remove <IP> <interface>|purge|list}"
        exit 0
		;;

esac
