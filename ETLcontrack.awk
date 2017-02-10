#!/usr/bin/awk -f
# 
# 
# ETLconntrack.awk: log data of current connections for defining communication-matrices
# 
# HowTo Use:
# on Linux:	# see http://www.iptables.info/en/connection-state.html
#	modprobe nf_conntrack || modprobe ip_conntrack
#	./bin/ETLcontrack.awk 
#   or on RHEL[5,6] and compatible systems
#	netstat -tune --notrim	| awk -f ETLconntrack.awk
#   or on Debian and compatible systems
#	netstat -tune --wide	| awk -f ETLconntrack.awk
# 
# on SunOS:
#	netstat -n -f inet -f inet6 | /usr/local/bin/gawk -f ETLconntrack.awk
#   or
#	netstat -n -f inet -f inet6 | /usr/xpg4/bin/awk -f ETLconntrack.awk
#   or on ancient versions like Solaris v8:
#	( netstat -n -f inet; netstat -n -f inet6 ) |	\
#	> /usr/xpg4/bin/awk -f ETLconntrack.awk
# 
# on HP-UX:
#	netstat -an -f inet | awk -f ETLconntrack.awk
# 
# 
# parameters considered to be used frequently
# -v STATEFILE=$PATH/$FILE.csv 
# 
# 
# additionally accepted parameters:
# -v OutputFormat="service,direction,localIP,remoteIP,counter"
# -v IPblacklist="127.0.0.1 192.168.49.1"
# -v PORTblacklist="22 111 2048 2049"
# -v NOWARNINGS=1
# *_conntrack-file	# if some other file is to be read beyond /proc/net/nf_conntrack or /proc/net/ip_conntrack or STDIN for netstat-output
# 
# parameters NOT to be used beyond special circumstances like e.g. analyzing data from remote hosts:
# -v HOSTNAME="othername"
# -v IPlist="10.119.146.19 10.110.7.244"
# -v Services="tcp/22 tcp/80"
# 
# parameters usable for development and debugging
# -v DEBUG=1
# -v LOGFILE=$PATH/$FILE.log
# 
# 
# v2.95 - Copyright (C) 2016,2017 - Henning Rohde (HeRo@amalix.de)
# 
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
#  
# 
# FixMe: No IPv6 yet
# FixMe: netstat never shows any UDP-communication
# FixMe: only accurate regarding UDP on modern Linux >v2.4 by using kernel-module for connection-tracking
# FixMe: netstat shows listening daemons only on Linux, and only if running with root-privileges || maybe daemon = "lsof -nPi :$PORT"
# 
# feel free to ask for further customization
# 

BEGIN{
	SUBSEP = ",";
	# print ERROR > /dev/stderr" is not portable for HP-UX!
	if ( LOGFILE == "" && ( "find /dev/stderr" | getline i ) > 0 )
		LOGFILE = "/dev/stderr";
	    else if ( LOGFILE == "" )
		LOGFILE = "/dev/tty";
	close( "find /dev/stderr" );

	# Define fields in Output and StateFile
	if ( OutputFormat != "" ) {
		if ( OutputFormat ~ SUBSEP )
			split( OutputFormat, OUTPUTFORMAT, SUBSEP );
		    else
			split( OutputFormat, OUTPUTFORMAT );
	    } else {
		split( "hostname,service,direction,localIP,localPort,remoteIP,remotePort,daemon,counter", OUTPUTFORMAT, SUBSEP );
#		split( "l4proto,localIP,localPort,remoteIP,remotePort,counter", OUTPUTFORMAT, SUBSEP );
#		split( "service,direction,localIP,remoteIP,counter", OUTPUTFORMAT, SUBSEP );
#		split( "service,client,server,counter", OUTPUTFORMAT, SUBSEP );
	    }

	# read StateFile
	if ( STATEFILE != "" ) {

		# sleep for up to four seconds to distribute load on virtual systems
		if ( DEBUG != "" && DEBUG != "0" && DEBUG != 0 ) {
		    } else {
			if (( "echo $$" | getline SEED ) > 0 && SEED > 0 ) {
				srand( SEED % 32767 );
				system( "sleep " int( 1 + rand() * 4 ) );
			    }
		    }

		while (( getline CONNECTION < STATEFILE ) > 0 )
			if ( CONNECTION !~ /^#/ ) {
				split( CONNECTION, LINE, SUBSEP );
				CONNINDEX = LINE[ 1 ];
				for ( i=2; OUTPUTFORMAT[ i+1 ] != ""; i++ )
					CONNINDEX = CONNINDEX SUBSEP LINE[i];
				COUNTER = LINE[i];
				# cap maxcount at some arbitrary number as e.g. 1440
				SAVEDCONNECTIONS[ CONNINDEX ] = ( COUNTER > 24*60 ? 24*60 : COUNTER );
				if ( DEBUG != "" && DEBUG != "0" && DEBUG != 0 ) {
					printf( "%s = %s\n", CONNINDEX, SAVEDCONNECTIONS[ CONNINDEX ] ) > LOGFILE;
				    }
			    }
		close( STATEFILE );
		if ( DEBUG != "" && DEBUG != "0" && DEBUG != 0 ) {
			printf( "\n" ) > LOGFILE;
		    }
	    } else {
		if ( ( "find /dev/stdout" | getline i ) > 0 )
			STATEFILE = "/dev/stdout";
		    else
			STATEFILE = "/dev/tty";
		close( "find /dev/stdout" );
	    }

	# blacklist local or remote IPs
	if ( IPblacklist != "" ) {
		if ( IPblacklist ~ SUBSEP )
			split( IPblacklist, IPBLACKLIST, SUBSEP );
		    else
			split( IPblacklist, IPBLACKLIST );
		# transponate values to indices for easier searching
		for ( i in IPBLACKLIST ) {
			IPBLACKLIST[ IPBLACKLIST[i] ] = i;
			delete IPBLACKLIST[i];
		    }
	    } else if ( DEBUG != "" && DEBUG != "0" && DEBUG != 0 ) {
		split( "", IPBLACKLIST );
	    } else {
		IPBLACKLIST[ "127.0.0.1"   ]	= "localhost";
#		IPBLACKLIST[ "" ]	= "";
	    }

	# blacklist local or remote Ports
	if ( PORTblacklist != "" ) {
		if ( PORTblacklist ~ SUBSEP )
			split( PORTblacklist, PORTBLACKLIST, SUBSEP );
		    else
			split( PORTblacklist, PORTBLACKLIST );
		# transponate values to indices for easier searching
		for ( i in PORTBLACKLIST ) {
			PORTBLACKLIST[ PORTBLACKLIST[i] ] = i;
			delete PORTBLACKLIST[i];
		    }
	    } else if ( DEBUG != "" && DEBUG != "0" && DEBUG != 0 ) {
		split( "", PORTBLACKLIST );
	    } else {
		split( "", PORTBLACKLIST );
#		PORTBLACKLIST[ "" ] = "";
	    }

	# 
	if ( HOSTNAME == "" || HOSTNAME == "localhost" ) {
		if (( "uname -n" | getline HOSTNAME ) > 0 && HOSTNAME == "localhost" ) {
			print "ERROR: Hostname unknown!\n   Please provide Hostname with parameter '-v HOSTNAME=[...]'\n" > LOGFILE;
			if ( DEBUG != "" && DEBUG != "0" && DEBUG != 0 ) {
			    } else
				exit ERROR = 1;
		    }
		close( "uname -n" );
	    }
	sub( /[^A-Za-z0-9-].*$/, "", HOSTNAME );
	if ( DEBUG != "" && DEBUG != "0" && DEBUG != 0 ) {
		print "Hostname: " HOSTNAME > LOGFILE;
	    }

	#
	if (( OS == "" ) && ( "uname -s" | getline OS ) > 0 && ( OS != "Linux" && OS != "SunOS" && OS != "HP-UX" && OS != "AIX" )) {
		print "ERROR: Unknown OS \"" OS "\"!\n   Please gather netstat-data manually and run skript on supported awk-version.\n" > LOGFILE;
		if ( DEBUG != "" && DEBUG != "0" && DEBUG != 0 ) { 
		    } else
			exit ERROR = 1;
	    }
	close( "uname -s" );
	if ( DEBUG != "" && DEBUG != "0" && DEBUG != 0 ) {
		print "Operating System: " OS > LOGFILE;
	    }

	#
	if ( IPlist != "" ) {
		# IPs to be analyzed are specified on commandline
		if ( IPlist ~ SUBSEP )
			split( IPlist, localIPs, SUBSEP );
		    else
			split( IPlist, localIPs );
		# transponate values to indices for easier searching
		for ( i in localIPs ) {
			delete IPBLACKLIST[ localIPs[i] ];
			localIPs[ localIPs[i] ] = i;
			delete localIPs[i];
		    }
	    } else {
		# any local IP is to be analyzed

		if ( OS == "Linux" ) {
			if (( "type ip 2>/dev/null" | getline Path2IP ) > 0) {
				CMD = "ip -4 -o a s 2>/dev/null | awk '{ print $4 }' | cut -d '/' -f 1 ";
				if ( DEBUG != "" && DEBUG != "0" && DEBUG != 0 ) {
					print "Command to figure out IPs: " Path2IP > LOGFILE;
				    }
			    } else if (( "find /sbin/ifconfig 2>/dev/null" | getline Path2IP ) > 0) {
				# $ /sbin/ifconfig -a
				# eth0      Link encap:Ethernet  HWaddr 00:02:A5:48:08:48
				#           inet addr:10.193.17.105  Bcast:10.198.17.255  Mask:255.255.255.0
				# [...]

				CMD = "/sbin/ifconfig -a | awk '{ if ( $1 ~ /^inet$/ ) { if ( $2 ~ /:/ ) print substr( $2, index( $2, \":\" ) +1 ); else print $2; }}'"
				if ( DEBUG != "" && DEBUG != "0" && DEBUG != 0 ) {
					print "Command to figure out IPs: " Path2IP > LOGFILE;
				    }
			    } else {
				print "ERROR: Neither ip nor ifconfig found!\n   Please provide relevant IP-addresses with parameter '-v IPlist=[...]'\n" > LOGFILE;
				if ( DEBUG != "" && DEBUG != "0" && DEBUG != 0 ) { 
				    } else
					exit ERROR = 1;
			    }
			close( "type ip 2>/dev/null" );
			close( "find /sbin/ifconfig 2>/dev/null" );

			while ( ( CMD | getline i ) > 0 && Path2IP != "" )
				++localIPs[i];
			close( CMD );

			if ( DEBUG != "" && DEBUG != "0" && DEBUG != 0 ) {
				print CMD > LOGFILE;
				for ( i in localIPs )
					print i > LOGFILE;
				printf( "\n" ) > LOGFILE;
			    }
		    } else if ( OS == "HP-UX" || OS == "AIX" || OS == "SunOS" ) {
			if (( "find /usr/bin/netstat 2>/dev/null" | getline NETSTAT ) > 0) {
				#$ netstat -ni
				#Name      Mtu  Network	 Address	 Ipkts	      Ierrs Opkts	      Oerrs Coll
				#lan1:1    1500 10.91.176.0     10.91.176.156   1366	       0     0		  0     0
				#lan1      1500 10.91.176.0     10.91.176.153   3487569	    0     3693219	    0     0

				CMD = NETSTAT " -ni | awk '{ if ( $1 ~ /[0-9]$/ ) print $4;}'"
				if ( DEBUG != "" && DEBUG != "0" && DEBUG != 0 ) {
					print "Command to figure out IPs: " NETSTAT;
				    }
			    } else {
				print "ERROR: netstat not found!\n   Please provide relevant IP-addresses with parameter '-v IPlist=[...]'\n" > LOGFILE;
				if ( DEBUG != "" && DEBUG != "0" && DEBUG != 0 ) {
				    } else
					exit ERROR = 1;
			    }
			close( "find /usr/bin/netstat 2>/dev/null" );

			while ( ( CMD | getline i ) > 0 && NETSTAT != "" )
				++localIPs[i];
			close( CMD );

			if ( DEBUG != "" && DEBUG != "0" && DEBUG != 0 ) {
				print CMD > LOGFILE;
				for ( i in localIPs )
					print i > LOGFILE;
				printf( "\n" ) > LOGFILE;
			    }
		    }
	    }

	# 
	if ( L4Protocol != "" ) {
		if ( L4Protocol ~ SUBSEP )
			split( L4Protocol, L4PROTOCOLS, SUBSEP );
		    else
			split( L4Protocol, L4PROTOCOLS );

		# transponate values to indices for easier searching
		for ( i in L4PROTOCOLS ) {
			L4PROTOCOLS[ L4PROTOCOLS[i] ] = i;
			delete L4PROTOCOLS[i];
		    }
#	    } else if ( DEBUG != "" && DEBUG != "0" && DEBUG != 0 ) {
#		# FixMe: autogenerate List from /proc/net/protocols
	    } else {
		++L4PROTOCOLS[ "tcp" ];
		++L4PROTOCOLS[ "tcp6" ];
		++L4PROTOCOLS[ "udp" ];
		++L4PROTOCOLS[ "udp6" ];
	    }

	#
	if ( Services != "" ) {
		# manually provide list of listening l4proto/ports
		# e.g. to process remotely gathered data
		if ( Services ~ SUBSEP )
			split( Services, SERVICES, SUBSEP );
		    else
			split( Services, SERVICES );

		# transponate values to indices for easier searching
		for ( i in SERVICES ) {
			SERVICES[ SERVICES[i] ] = "!";
			delete SERVICES[i];
		    }
	    } else {

		if ( OS == "Linux" ) {
			CMD = "netstat -tulpn 2>/dev/null";
			if ( DEBUG != "" && DEBUG != "0" && DEBUG != 0 ) {
				print "Command to figure out services: " CMD > LOGFILE;
			    }

			if ( ( getline i < "/proc/sys/net/ipv4/ip_local_port_range" ) > 0 )
				split( i, Portrange );

			while (( CMD | getline i) > 0) {

				gsub( /[ ]+/, SUBSEP, i );
				lastColumn = split( i, Service, SUBSEP );

				port = Service[ 4 ];
				sub( /^.*[.:]/, "", port );

				if ( index( Service[ lastColumn ], "/" ) )
					daemon = Service[ lastColumn ];
				    else if ( index( Service[ lastColumn -1 ], "/" ) )
					daemon = Service[ lastColumn -1 ];
				    else
					daemon = "-";
				sub( /[0-9]*\//, "", daemon );

				if ( Service[ 1 ] in L4PROTOCOLS && !( port >= Portrange[ 1 ] && port <= Portrange[ 2 ] ) ) {
					SERVICES[ substr( Service[ 1 ], 1, 3 ) "/" port ] = daemon;
				    } else if ( DEBUG != "" && DEBUG != "0" && DEBUG != 0 ) {
					print i > LOGFILE;
				    }
			    }
			close( CMD );

		    } else if ( OS == "SunOS" ) {
			# combined command "netstat -f inet -f inet6 -P ..." is not supported by Solaris < v10
			CMD = "netstat -f inet -P tcp -an 2>/dev/null | awk '{ print $NF,$1;}'; netstat -f inet6 -P tcp -an 2>/dev/null | awk '{ print $NF,$1;}'"
			if ( DEBUG != "" && DEBUG != "0" && DEBUG != 0 ) {
				print "Command to figure out services: " CMD > LOGFILE;
			    }
			while (( CMD | getline i ) > 0)
				if ( tolower( i ) ~ /^listen/ && tolower( i ) !~ /^listen 127.0.0.1/ ) {
					sub( /^.*\./, "", i );
					SERVICES[ "tcp/" i ] = ( daemon != "" ? daemon : "-" );
				    } else if ( DEBUG != "" && DEBUG != "0" && DEBUG != 0 ) {
#					print i > LOGFILE;
				    }
			close( CMD );

			CMD = "netstat -f inet -P udp -an 2>/dev/null | awk '{ print $NF,$1;}'; netstat -f inet6 -P udp -an 2>/dev/null | awk '{ print $NF,$1;}'"
			if ( DEBUG != "" && DEBUG != "0" && DEBUG != 0 ) {
				print "Command to figure out services: " CMD > LOGFILE;
			    }
			while (( CMD | getline i ) > 0)
				if ( tolower( i ) ~ /^idle/ && tolower( i ) !~ /^idle 127.0.0.1/ ) {
					sub( /^.*\./, "", i );
					SERVICES[ "udp/" substr( i, index( i, "." ) +1 ) ] = ( daemon != "" ? daemon : "-" );
				    } else if ( DEBUG != "" && DEBUG != "0" && DEBUG != 0 ) {
#					print i > LOGFILE;
				    }
			close( CMD );

		    } else if ( OS == "HP-UX" ) {
			CMD = "netstat -an -f inet 2>/dev/null | grep -v 'ESTABLISHED'";
			if ( DEBUG != "" && DEBUG != "0" && DEBUG != 0 ) {
				print "Command to figure out services: " CMD > LOGFILE;
			    }
			while (( CMD | getline i) > 0) {

				gsub( /[ ]+/, SUBSEP, i );
				lastColumn = split( i, Service, SUBSEP );

				if ( Service[ 1 ] in L4PROTOCOLS && tolower( Service[ lastColumn ] ) == "listen") {
					port = Service[ 4 ];
					sub( /^.*[.:]/, "", port );
					SERVICES[ substr( Service[ 1 ], 1, 3 ) "/" port ] = "-";

				    } else if ( Service[ 1 ] == "udp" && Service[ 5 ] == "*.*" &&	\
						( Service[ 4 ] ~ /[*][.][0-9]+/ || Service[ 4 ] ~ /[0-9]+[.][0-9]+[.][0-9]+[.][0-9]+[:.][0-9]+/ ) ) {
					port = Service[ 4 ];
					sub( /^.*[.:]/, "", port );
					SERVICES[ substr( Service[ 1 ], 1, 3 ) "/" port ] = "-";

				    } else if ( DEBUG != "" && DEBUG != "0" && DEBUG != 0 ) {
					print i > LOGFILE;
				    }
			    }
			close( CMD );
		    }

		if ( DEBUG != "" && DEBUG != "0" && DEBUG != 0 ) {
			print CMD > LOGFILE;
			for ( i in SERVICES )
				print i > LOGFILE;
			printf( "\n" ) > LOGFILE;
		    }
	    }

	# is stdin to be processed?
	if ( ARGC == 1 ) {
		if ( DEBUG != "" && DEBUG != "0" && DEBUG != 0 ) {
			print "No commandline-arguments are provided." > LOGFILE;
		    }

		if (( "LC_ALL=C tty" | getline STDIN ) > 0 && STDIN ~ /\// ) {
			# STDIN is a tty, no conntrack-data is to be read from it

			close( "LC_ALL=C tty" );
			if ( DEBUG != "" && DEBUG != "0" && DEBUG != 0 ) {
				print "STDIN: " STDIN > LOGFILE;
			    }

			if ( OS == "Linux" ) {
				# autodetect wether /proc/net/nf_conntrack or "old" /proc/net/ip_conntrack can be read
				if (( getline i < "/proc/net/nf_conntrack" ) > 0 ) {
					ARGV[ ARGC++ ] = "/proc/net/nf_conntrack";
					if ( DEBUG != "" && DEBUG != "0" && DEBUG != 0 ) {
						print "Autodetect input-file: /proc/net/nf_conntrack exists and is readable." > LOGFILE;
					    }
					close ( "/proc/net/nf_conntrack" );

				    } else if (( getline i < "/proc/net/ip_conntrack" ) > 0 ) {
					ARGV[ ARGC++ ] = "/proc/net/ip_conntrack";
					if ( DEBUG != "" && DEBUG != "0" && DEBUG != 0 ) {
						print "Autodetect input-file: /proc/net/ip_conntrack exists and is readable." > LOGFILE;
					    }
					close ( "/proc/net/ip_conntrack" );

				    } else {
					# check priviledge because /proc/net/nf_conntrack and /proc/net/ip_conntrack are only readable to root
					if (( "id -u 2>/dev/null" | getline UID ) > 0 && UID > 0 ) {
						print "ERROR: Skript must be run as root for reading /proc/net/*_conntrack!\n" > LOGFILE;
						if ( DEBUG != "" && DEBUG != "0" && DEBUG != 0 ) {
						    } else
							exit ERROR = 1;
					    } else {
						print "ERROR: Cannot read any conntrack-files!\n   Please modprobe depending on kernel-version either nf_conntrack or ip_conntrack!\n" > LOGFILE;
						if ( DEBUG != "" && DEBUG != "0" && DEBUG != 0 ) {
						    } else
							exit ERROR = 1;
					    }
					close( "id -u 2>/dev/null" );
				    }
			    } else if ( OS == "SunOS" || OS == "HP-UX" ) {
				# FixMe: is there a way to read-in netstat-data
			    }
		    } else {
			# STDIN is not a tty, conntrack-data can be tried to be read from it

			close( "LC_ALL=C tty" );
			if ( DEBUG != "" && DEBUG != "0" && DEBUG != 0 ) {
				print "STDIN: " STDIN > LOGFILE;
			    }
		    }
	    } else
		if ( DEBUG != "" && DEBUG != "0" && DEBUG != 0 ) {
			print ARGC -1 > LOGFILE;
		    }

	# check for readability of commandline-arguments
	for ( i in ARGV ) {
		# ARGV[0] == $0;
		if ( i == 0 )
			continue;

		if ( DEBUG != "" && DEBUG != "0" && DEBUG != 0 ) {
			print i "/" ARGC -1 ": " ARGV[i] > LOGFILE;
		    }

		# at least something was provided on commandline
		# check input-files for readability
		if ( ARGV[i] ~ /^[a-zA-Z_][a-zA-Z0-9_]*=.*/ || ARGV[i] ~ /^-/ || ARGV[i] == "/dev/stdin") {
			NoFileArgs++;
			printf( "ERROR: Unhandled argument!\n   '%s' doesn't look like a file!\n"i, ARGV[i]) > LOGFILE;
			if ( DEBUG != "" && DEBUG != "0" && DEBUG != 0 ) {
			    } else
				exit ERROR = 1;
		    } else if ( ARGV[i] ~ /\dev\/fd\// ) {
			# input-redirection <( command ) was used
		    } else if ( !( ( getline junk < ARGV[i] ) > 0 ) ) {
			++WARNINGS[ i "/" ARGC-1 ": " ARGV[i] " unreadable!\n   Skipping..." ];
			close( ARGV[i] );
			delete ARGV[i];
			UnreadableFiles++;
			ARGC--;
		    } else {
			if ( DEBUG != "" && DEBUG != "0" && DEBUG != 0 ) {
				printf( "Checking for file-rights: '%s' looks like a readable file.\n", ARGV[i] ) > LOGFILE;
			    }
			close( ARGV[i] );
		    }
	    }

	if ( NoFileArgs + UnreadableFiles > ARGC - 1 || ( ARGC == 1 && STDIN ~ /\// ) ) {
		print "ERROR: Cannot read any files listed on commandline!\n   Please check arguments!" > LOGFILE;
		exit ERROR = 1;
	    } else if ( DEBUG != "" && DEBUG != "0" && DEBUG != 0 ) {
		print "Trying to read " ARGC - NoFileArgs - UnreadableFiles - 1 " files." > LOGFILE;
	    }
    }


#main()
{
	if ( DEBUG != "" && DEBUG != "0" && DEBUG != 0 ) {
		print $0 > LOGFILE;
	    }
	LINEWIDTH = split( $0, LINE );
	split( "", CONNTRACK );


	if ( OS == "SunOS" && LINE[ 1 ] ~ /[0-9]+[.][0-9]+[.][0-9]+[.][0-9]+[:.][0-9]+/ && LINE[ 2 ] ~ /[0-9]+[.][0-9]+[.][0-9]+[.][0-9]+[:.][0-9]+/ && LINE[ 3 ] ~ /[0-9]+/ && LINE[ 4 ] ~ /[0-9]+/ && LINE[ 5 ] ~ /[0-9]+/ && LINE[ 6 ] ~ /[0-9]+/ ) {
		if ( DEBUG != "" && DEBUG != "0" && DEBUG != 0 ) {
			++WARNINGS[ "Apparently output from netstat on Solaris v10." ];
		    }
		CONNTRACK[ "l3proto" ] = "ipv4";
		CONNTRACK[ "l4proto" ] = "tcp";

		if ( tolower( LINE[ LINEWIDTH ] ) == "established"  )
			CONNTRACK[ "persistence" ] = 61;
		    else
			CONNTRACK[ "persistence" ] = 59;

		CONNTRACK[ "localPort" ] = LINE[ 1 ];
		# cleanup "^IP:"
		sub( /^.*[.:]/, "", CONNTRACK[ "localPort" ] );
		CONNTRACK[ "sport" ] = CONNTRACK[ "localPort" ];

		CONNTRACK[ "remotePort" ] = LINE[ 2 ];
		# cleanup "^IP:"
		sub( /^.*[.:]/, "", CONNTRACK[ "remotePort" ] );
		CONNTRACK[ "dport" ] = CONNTRACK[ "remotePort" ];

		CONNTRACK[ "remoteIP" ] = LINE[ 2 ];
		# cleanup ":port$"
		sub( /[.:][0-9]+$/, "", CONNTRACK[ "remoteIP" ] );
		CONNTRACK[ "dst" ] = CONNTRACK[ "remoteIP" ];

		CONNTRACK[ "localIP" ] = LINE[ 1 ];
		# cleanup ":port$"
		sub( /[.:][0-9]+$/, "", CONNTRACK[ "localIP" ] );
		CONNTRACK[ "src" ] = CONNTRACK[ "localIP" ];


	    } else if ( OS == "Linux" && LINE[ 1 ] ~ /^ipv[46]$/ && LINE[ 3 ] in L4PROTOCOLS ) {
		# normalize Line wether /proc/net/nf_conntrack or /proc/net/ip_conntrack was read

		if ( DEBUG != "" && DEBUG != "0" && DEBUG != 0 ) {
			++WARNINGS[ "Apparently nf_conntrack..." ];
		    }
		CONNTRACK[ "l3proto" ] = LINE[ 1 ];
		CONNTRACK[ "l4proto" ] = LINE[ 3 ];
		CONNTRACK[ "persistence" ] = LINE[ 5 ];

		for ( i=6; i<LINEWIDTH; i++ ) {
			if ( LINE[i] ~ /\=/ ) {
				split( LINE[i], ENTRY, "=" );
				if (! ( ENTRY[ 1 ] in CONNTRACK ))
					CONNTRACK[ ENTRY[ 1 ] ] = ENTRY[ 2 ];
				    else
					break;
			    }
		    }

	    } else if ( OS == "Linux" && LINE[ 5 ] ~ /\=/ &&  LINE[ 6 ] ~ /\=/ && LINE[ 1 ] in L4PROTOCOLS ) {

		if ( DEBUG != "" && DEBUG != "0" && DEBUG != 0 ) {
			++WARNINGS[ "Apparently ip_conntrack..." ];
		    }
		CONNTRACK[ "l3proto" ] = "ipv4";
		CONNTRACK[ "l4proto" ] = LINE[ 1 ];
		CONNTRACK[ "persistence" ] = LINE[ 3 ];

		for ( i=4; i<LINEWIDTH; i++ ) {
			if ( LINE[i] !~ /=/ )
				continue;
			    else {
				split( LINE[i], ENTRY, "=" );
				if (! ( ENTRY[ 1 ] in CONNTRACK ))
					CONNTRACK[ ENTRY[ 1 ] ] = ENTRY[ 2 ];
				else
					break;
			    }
		    }

	    } else if (	LINE[ 4 ] ~ /[0-9]+[.][0-9]+[.][0-9]+[.][0-9]+[:.][0-9]+/ &&	\
			LINE[ 5 ] ~ /[0-9]+[.][0-9]+[.][0-9]+[.][0-9]+[:.][0-9]+/ &&	\
			LINE[ 1 ] in L4PROTOCOLS &&	\
			tolower( LINE[ 6 ] ) !~ /^listen$/ ) {
		## Linux
		#$ netstat -tune --notrim | head
		#Active Internet connections (w/o servers)
		#Proto Recv-Q Send-Q Local Address               Foreign Address             State       User       Inode
		#tcp        0      0 10.110.7.244:2049           10.110.6.35:606             ESTABLISHED 65534      2915692474
		# 
		## HPUX:
		#$ netstat -an -f inet | grep -v LISTEN | head
		#Active Internet connections (including servers)
		#Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)
		#tcp        0      0  10.91.27.26.63905      10.91.27.26.1521        ESTABLISHED
		#tcp        0      0  10.91.27.26.59648      10.118.63.82.1521       ESTABLISHED
		# 

		if ( DEBUG != "" && DEBUG != "0" && DEBUG != 0 ) {
			++WARNINGS[ "Apparently output from netstat on Linux or HP-UX..." ];
		    }
		if ( LINE[ 1 ] !~ /6$/ )
			CONNTRACK[ "l3proto" ] = "ipv4";
		    else
			CONNTRACK[ "l3proto" ] = "ipv6";
		CONNTRACK[ "l4proto" ] = LINE[ 1 ];

		CONNTRACK[ "localPort" ] = LINE[ 4 ];
		# cleanup "^IP:"
		sub( /^.*[.:]/, "", CONNTRACK[ "localPort" ] );
		CONNTRACK[ "sport" ] = CONNTRACK[ "localPort" ];

		CONNTRACK[ "remotePort" ] = LINE[ 5 ];
		# cleanup "^IP:"
		sub( /^.*[.:]/, "", CONNTRACK[ "remotePort" ] );
		CONNTRACK[ "dport" ] = CONNTRACK[ "remotePort" ];

		CONNTRACK[ "remoteIP" ] = LINE[ 5 ];
		# cleanup ":port$"
		sub( /[.:][0-9]+$/, "", CONNTRACK[ "remoteIP" ] );
		CONNTRACK[ "dst" ] = CONNTRACK[ "remoteIP" ];

		CONNTRACK[ "localIP" ] = LINE[ 4 ];
		# cleanup ":port$"
		sub( /[.:][0-9]+$/, "", CONNTRACK[ "localIP" ] );
		# correct truncation of localIP and remoteIP related to fixed-width of netstat-ouput on old Linux
		if ( OS == "Linux" && !( CONNTRACK[ "localIP" ] in localIPs ) && CONNTRACK[ "localIP" ] ~ /:/ ) {

			# cleanup IPv6-Prefix "^::ffff:"
			sub( /^[:f]+:/, "", CONNTRACK[ "localIP" ] );
			sub( /^[:f]+:/, "", CONNTRACK[ "remoteIP" ] );
			sub( /6$/, "", CONNTRACK[ "l4proto" ] );

			for ( i in localIPs )
				if ( CONNTRACK[ "localIP" ] ~ ( "^" localIPs[ i ] ) ) {
					sub( /\.[0-9]*$/, ".", CONNTRACK[ "remoteIP" ] );
					CONNTRACK[ "dst" ] = CONNTRACK[ "remoteIP" ];
					# trying to repair at least localIP
					CONNTRACK[ "localIP" ] = i;
					break;
				    }
		    }
		CONNTRACK[ "src" ] = CONNTRACK[ "localIP" ];

		if ( tolower( LINE[ 6 ] ) ~ /established/ )
			CONNTRACK[ "persistence" ] = 61;
		    else
			CONNTRACK[ "persistence" ] = 59;


	    } else if ( DEBUG != "" && DEBUG != "0" && DEBUG != 0 ) {
		printf( "%s \n", $0 ) > LOGFILE;
		next;
	    } else
		next;

	# map localIP and remoteIP site
	if ( ( CONNTRACK[ "src" ] in localIPs && CONNTRACK[ "dst" ] in localIPs ) ) {
		CONNTRACK[ "direction" ] = "local";
	    } else if ( CONNTRACK[ "src" ] in localIPs ) {
		CONNTRACK[ "localIP" ] = CONNTRACK[ "src" ];
		CONNTRACK[ "localPort" ] = CONNTRACK[ "sport" ];
		CONNTRACK[ "remoteIP" ] = CONNTRACK[ "dst" ];
		CONNTRACK[ "remotePort" ] = CONNTRACK[ "dport" ];
	    } else if ( CONNTRACK[ "dst" ] in localIPs ) {
		CONNTRACK[ "localIP" ] = CONNTRACK[ "dst" ];
		CONNTRACK[ "localPort" ] = CONNTRACK[ "dport" ];
		CONNTRACK[ "remoteIP" ] = CONNTRACK[ "src" ];
		CONNTRACK[ "remotePort" ] = CONNTRACK[ "sport" ];
	    } else if (! ( "localIP" in CONNTRACK )) {
		# either both IPs are foreign or blacklisted
		# or some string got shortened
		CONNTRACK[ "direction" ] = "foreign";
	    }


	# conjecture direction
	if ( CONNTRACK[ "direction" ] == "foreign" ) {
		if ( DEBUG != "" && DEBUG != "0" && DEBUG != 0 ) {
			for ( i in CONNTRACK )
				printf( "%s=%s\n", i, CONNTRACK[i] ) > LOGFILE;
			printf( "\n" );
			next;
		    }
	    } else if ( CONNTRACK[ "direction" ] == "local" ) {
		if ( CONNTRACK[ "l4proto" ] "/" CONNTRACK[ "sport" ] in SERVICES ) {
			CONNTRACK[ "remotePort" ] = CONNTRACK[ "sport" ];
		    } else {
			CONNTRACK[ "remotePort" ] = CONNTRACK[ "dport" ];
		    }
		CONNTRACK[ "client" ] = "localhost";
		CONNTRACK[ "localIP" ] = "127.0.0.1";
		CONNTRACK[ "remoteIP" ] = "127.0.0.1";
		CONNTRACK[ "server" ] = "localhost";
		CONNTRACK[ "service" ] = CONNTRACK[ "l4proto" ] "/" CONNTRACK[ "remotePort" ];
		CONNTRACK[ "localPort" ] = 0;
	    } else if ( ( CONNTRACK[ "remotePort" ] < 2**10 && CONNTRACK[ "localPort" ] > CONNTRACK[ "remotePort" ] ) ||	\
		    ! ( CONNTRACK[ "l4proto" ] "/" CONNTRACK[ "localPort" ] in SERVICES )) {
		CONNTRACK[ "direction" ] = "outgoing";
		CONNTRACK[ "client" ] = CONNTRACK[ "localIP" ];
		CONNTRACK[ "server" ] = CONNTRACK[ "remoteIP" ];
		CONNTRACK[ "service" ] = CONNTRACK[ "l4proto" ] "/" CONNTRACK[ "remotePort" ];
		CONNTRACK[ "localPort" ] = 0;
	    } else if ( CONNTRACK[ "localPort" ] == CONNTRACK[ "remotePort" ] ) {
		CONNTRACK[ "direction" ] = "peer2peer";
		CONNTRACK[ "client" ] = CONNTRACK[ "localIP" ];
		CONNTRACK[ "server" ] = CONNTRACK[ "remoteIP" ];
		CONNTRACK[ "service" ] = CONNTRACK[ "l4proto" ] "/" CONNTRACK[ "remotePort" ];
	    } else if ( CONNTRACK[ "l4proto" ] "/" CONNTRACK[ "localPort" ] in SERVICES && CONNTRACK[ "localPort" ] < 2**15 ) {
		CONNTRACK[ "direction" ] = "incoming";
		CONNTRACK[ "client" ] = CONNTRACK[ "remoteIP" ];
		CONNTRACK[ "server" ] = CONNTRACK[ "localIP" ];
		CONNTRACK[ "service" ] = CONNTRACK[ "l4proto" ] "/" CONNTRACK[ "localPort" ];
		CONNTRACK[ "remotePort" ] = 0;
	    } else if ( DEBUG != "" && DEBUG != "0" && DEBUG != 0 ) {
		for ( i in CONNTRACK )
			printf( "%s=%s\n", i, CONNTRACK[i] ) > LOGFILE;
		printf( "\n" );
		next;
	    } else
		next;

	CONNTRACK[ "hostname" ] = HOSTNAME;
	if ( CONNTRACK[ "direction" ] == "outgoing" )
		CONNTRACK[ "daemon" ] = ">";
	    else if ( CONNTRACK[ "service" ] in SERVICES )
		CONNTRACK[ "daemon" ] = SERVICES[ CONNTRACK[ "service" ] ];
	    else
		CONNTRACK[ "daemon" ] = "?";

	if (! ( CONNTRACK[ "direction" ] == "local"	|| CONNTRACK[ "direction"  ] == "foreign"		|| \
	    CONNTRACK[ "localPort" ] in PORTBLACKLIST	|| CONNTRACK[ "remotePort" ] in PORTBLACKLIST	|| \
	    CONNTRACK[ "localIP"   ] in IPBLACKLIST	|| CONNTRACK[ "remoteIP"   ] in IPBLACKLIST ) ) {

		CONNINDEX = CONNTRACK[ OUTPUTFORMAT[ 1 ] ];
		for ( i=2; OUTPUTFORMAT[ i+1 ] != ""; i++ )
			CONNINDEX = CONNINDEX SUBSEP CONNTRACK[ OUTPUTFORMAT[i] ];
		++CONNECTIONS[ CONNINDEX ];

	    } else if ( DEBUG != "" && DEBUG != "0" && DEBUG != 0 ) {
		CONNINDEX = CONNTRACK[ OUTPUTFORMAT[ 1 ] ];
		for ( i=2; OUTPUTFORMAT[ i+1 ] != ""; i++ )
			CONNINDEX = CONNINDEX SUBSEP CONNTRACK[ OUTPUTFORMAT[i] ];
		++CONNECTIONS[ CONNINDEX ];
		next;
	    } else

		next;
    }

END{
	if ( ERROR != 0 || ERROR != "" )
		exit ERROR;

	# predefine Index as Headline
	INDEX = OUTPUTFORMAT[ 1 ];
	for ( i=2; OUTPUTFORMAT[i] != ""; i++ )
		INDEX = INDEX SUBSEP OUTPUTFORMAT[i];

	printf( "#%s\n", INDEX ) > STATEFILE;
	for ( i in SAVEDCONNECTIONS )
		if ( !( i in CONNECTIONS ) )
			printf( "%s,%s\n", i, SAVEDCONNECTIONS[i] ) > STATEFILE; 
		
	for ( i in CONNECTIONS )
		printf( "%s,%s\n", i, ( CONNECTIONS[i] > SAVEDCONNECTIONS[i] ? CONNECTIONS[i] : SAVEDCONNECTIONS[i] ) ) > STATEFILE; 
	close( STATEFILE );

	if ( NOWARNINGS != "" && NOWARNINGS != "0" && NOWARNINGS != 0 ) {
	    } else
		for ( i in WARNINGS )
			print i > LOGFILE;
	if ( DEBUG != "" && DEBUG != "0" && DEBUG != 0 ) {
		printf( "#%s\n", INDEX ) > LOGFILE;
		for ( i in CONNECTIONS )
			printf( "%s,%d,%d\n", i, CONNECTIONS[i], SAVEDCONNECTIONS[i] ) > LOGFILE;
	    }
	close( LOGFILE );

	if ( DEBUG != "" && DEBUG != "0" && DEBUG != 0 )
		system("ps -o ppid= -p $$ | xargs lsof -p >> " LOGFILE );

#	# FixMe: print help if sensible
#	if ( ARGC < 2 && NR < 1 )
#		print HELP;

    }
