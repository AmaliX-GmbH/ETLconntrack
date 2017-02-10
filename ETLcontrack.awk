#!/usr/bin/awk -f
# 
# 
# ETLconntrack.awk: log data of current connections for defining communication-matrices
# 
# HowTo Use:
# on Linux:	# see http://www.iptables.info/en/connection-state.html
#	modprobe nf_conntrack_ipv4 || modprobe ip_conntrack
#	./bin/ETLcontrack.awk 
#   or on RHEL[5,6] and compatible systems
#	netstat -tune --notrim	| awk -f ETLconntrack.awk
#   or on Debian and compatible systems
#	netstat -tune --wide	| awk -f ETLconntrack.awk
# 
# on SunOS:
#	netstat -n -f inet -f inet6 | /usr/xpg4/bin/awk -f ETLconntrack.awk
#   or
#	netstat -n -f inet -f inet6 | /usr/local/bin/gawk -f ETLconntrack.awk
#   or on ancient versions like Solaris v8:
#	( netstat -n -f inet; netstat -n -f inet6 ) |	\
#	> /usr/xpg4/bin/awk -f ETLconntrack.awk
# 
# on AIX or HP-UX:
#	netstat -an -f inet | awk -f ETLconntrack.awk
# 
# on Windows:
#	netstat -an | awk -f ETLconntrack.awk
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
# -v NOSLEEP=1
# -v LOGFILE=$PATH/$FILE.log
# 
# 
# v2.99 - Copyright (C) 2016,2017 - Henning Rohde (HeRo@amalix.de)
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

function IPhex( IP,     quad ){
	split( IP, quad, "[/.]" );
	return sprintf( "%#010x", quad[ 1 ] * 2^24 + quad[ 2 ] * 2^16 + quad[ 3 ] * 2^8 + quad[ 4 ]);
    }
function replace( SEARCH, REPLACEMENT, TARGET ){
	gsub( SEARCH, REPLACEMENT, TARGET );
	return TARGET;
    }

BEGIN{
	SUBSEP = ",";
	# print ERROR > /dev/stderr" is not portable for HP-UX!
	if ( LOGFILE == "" && ( "find /dev/stderr 2>/dev/null" | getline i ) > 0 )
		LOGFILE = "/dev/stderr";
	    else if ( LOGFILE == "" )
		LOGFILE = "/dev/tty";
	close( "find /dev/stderr 2>/dev/null" );

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
		    } else if ( !( NOSLEEP != "" && NOSLEEP != "0" && NOSLEEP != 0 ) ) {
			if (( "echo $$" | getline SEED ) > 0 && SEED > 0 ) {
				srand( SEED % 32767 );
				system( "sleep " int( 1 + rand() * 4 ) );
			    }
			close( "echo $$" );
		    }

		while (( getline CONNECTION < STATEFILE ) > 0 )
			if ( CONNECTION !~ /^#/ ) {
				split( CONNECTION, LINE, SUBSEP );
				CONNINDEX = LINE[ 1 ];
				for ( i=2; OUTPUTFORMAT[ i+1 ] != ""; i++ )
					CONNINDEX = CONNINDEX SUBSEP LINE[i];
				COUNTER = LINE[i];
				# cap maxcount at some arbitrary number as e.g. 1440
				SAVEDCONNECTIONS[ CONNINDEX ] = ( int( COUNTER ) > 24*60 ? 24*60 : COUNTER );
				if ( DEBUG != "" && DEBUG != "0" && DEBUG != 0 ) {
					printf( "%s = %s\n", CONNINDEX, SAVEDCONNECTIONS[ CONNINDEX ] ) > LOGFILE;
				    }
			    }
		close( STATEFILE );
		if ( DEBUG != "" && DEBUG != "0" && DEBUG != 0 ) {
			printf( "\n" ) > LOGFILE;
		    }
	    } else {
		if ( ( "find /dev/stdout 2>/dev/null" | getline i ) > 0 )
			STATEFILE = "/dev/stdout";
		    else
			STATEFILE = "/dev/tty";
		close( "find /dev/stdout 2>/dev/null" );
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
		if ( ( "uname -n" | getline HOSTNAME ) > 0 &&	\
		    ( HOSTNAME == "localhost" || tolower( HOSTNAME ) ~ /^[^a-z0-9]/ ) ) {
			print "ERROR: Hostname unknown or apparently illegal!\n   Please provide Hostname with parameter '-v HOSTNAME=[...]'\n" > LOGFILE;
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
	if (( OS == "" ) && ( "uname -s" | getline OS ) > 0 && ( OS != "Linux" && OS != "SunOS" && OS != "HP-UX" && OS != "AIX" && OS != "windows32" )) {
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
					print "Command to figure out IPs: " CMD > LOGFILE;
				    }
			    } else if (( "find /sbin/ifconfig 2>/dev/null" | getline Path2IP ) > 0) {
				# $ /sbin/ifconfig -a
				# eth0      Link encap:Ethernet  HWaddr 00:02:A5:48:08:48
				#           inet addr:10.193.17.105  Bcast:10.198.17.255  Mask:255.255.255.0
				# [...]

				CMD = "/sbin/ifconfig -a | awk '{ if ( $1 ~ /^inet$/ ) { if ( $2 ~ /:/ ) print substr( $2, index( $2, \":\" ) +1 ); else print $2; }}'"
				if ( DEBUG != "" && DEBUG != "0" && DEBUG != 0 ) {
					print "Command to figure out IPs: " CMD > LOGFILE;
				    }
			    } else {
				print "ERROR: Neither ip nor ifconfig found!\n   Please provide relevant IP-addresses with parameter '-v IPlist=[...]'\n" > LOGFILE;
				if ( DEBUG != "" && DEBUG != "0" && DEBUG != 0 ) { 
				    } else
					exit ERROR = 1;
			    }
			close( "type ip 2>/dev/null" );
			close( "find /sbin/ifconfig 2>/dev/null" );

			while ( ( CMD | getline i ) > 0 )
				++localIPs[i];
			close( CMD );

		    } else if ( OS == "AIX" || OS == "HP-UX" || OS == "SunOS" ) {
			if (( "type netstat 2>/dev/null" | getline NETSTAT ) > 0) {
				#$ netstat -ni
				#Name      Mtu  Network	 Address	 Ipkts	      Ierrs Opkts	      Oerrs Coll
				#lan1:1    1500 10.91.176.0     10.91.176.156   1366	       0     0		  0     0
				#lan1      1500 10.91.176.0     10.91.176.153   3487569	    0     3693219	    0     0

				CMD = "netstat -ni | awk '{ if ( $1 ~ /[0-9]$/ ) print $4;}'"
				if ( DEBUG != "" && DEBUG != "0" && DEBUG != 0 ) {
					print "Command to figure out IPs: " CMD > LOGFILE;
				    }
			    } else {
				print "ERROR: netstat not found!\n   Please provide relevant IP-addresses with parameter '-v IPlist=[...]'\n" > LOGFILE;
				if ( DEBUG != "" && DEBUG != "0" && DEBUG != 0 ) {
				    } else
					exit ERROR = 1;
			    }
			close( "type netstat 2>/dev/null" );

			while ( ( CMD | getline i ) > 0 )
				++localIPs[i];
			close( CMD );

		    } else if ( OS == "windows32" ) {
			CMD = "ipconfig /all"
			if ( DEBUG != "" && DEBUG != "0" && DEBUG != 0 ) {
				print "Command to figure out IPs: " CMD > LOGFILE;
			    }
			while ( ( CMD | getline i ) > 0 ) {
				if ( tolower( i ) ~ /ipv4-ad/ ) {
					IP = substr( i, 2 + index( i, ": " ) );
					sub( /[^0-9.]*$/, "", IP );
					++localIPs[ IP ];
				}
			    }
			close( CMD );
		    }

		if ( DEBUG != "" && DEBUG != "0" && DEBUG != 0 ) {
			for ( i in localIPs )
				print "localIP: " i > LOGFILE;
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
		++L4PROTOCOLS[ "tcp4" ];
		++L4PROTOCOLS[ "tcp6" ];
		++L4PROTOCOLS[ "udp" ];
		++L4PROTOCOLS[ "udp4" ];
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
			if ( ( getline i < "/proc/sys/net/ipv4/ip_local_port_range" ) > 0 )
				split( i, Portrange );
                        close( "/proc/sys/net/ipv4/ip_local_port_range" );

			CMD = "netstat -tulpn 2>/dev/null";
			while (( CMD | getline i) > 0) {
				if ( i ~ /^tcp/ || i ~ /^udp/ ) {
					lastColumn = split( i, Service );
					port = replace( "^.*[.:]", "", Service[ 4 ] );

					if ( i ~ /\// ) {
						daemon = replace( "^.*/", "", i );
						sub( / *$/, "", daemon );
						if ( daemon ~ /^[0-9]$/ ) {
							if ( DEBUG != "" && DEBUG != "0" && DEBUG != 0 ) {
								print "Daemon named as a digit: " i > LOGFILE;
							    }
							continue;
						    } else
							sub( /:.*$/, "", daemon );

					    } else
						daemon = "-";

					SERVICES[ replace( "[46]$", "", Service[ 1 ] ) "/" port ] = daemon;

					# explicit casting as integer via int() to avoid string-comparison
					if ( int( port ) >= ( int( Portrange[ 1 ] ) > 0 ? int( Portrange[ 1 ] ) : 32768 ) &&	\
					    int( port ) <= ( int( Portrange[ 2 ] ) > 0 ? int( Portrange[ 2 ] ) : 65536 ) ) {
						if ( DEBUG != "" && DEBUG != "0" && DEBUG != 0 )
							print "Service on a high port (" port ">" ( int( Portrange[ 1 ] ) > 0 ? int( Portrange[ 1 ] ) : 32768 ) "): " i > LOGFILE;
					    }
				    }
			    }
			close( CMD );


		    } else if ( OS == "SunOS" ) {
			# combined command "netstat -f inet -f inet6 -P ..." is not supported by Solaris < v10
			CMD = "netstat -f inet -P tcp -an 2>/dev/null; netstat -f inet6 -P tcp -an 2>/dev/null"
			while (( CMD | getline i ) > 0)
				if ( i ~ /LISTEN/ ) {
					lastColumn = split( i, Service );
					port = replace( "^.*[.:]", "", Service[ 1 ] );
					SERVICES[ "tcp/" port ] = ( daemon != "" ? daemon : "-" );
				    }
			close( CMD );

			CMD = "netstat -f inet -P udp -an 2>/dev/null; netstat -f inet6 -P udp -an 2>/dev/null"
			while (( CMD | getline i ) > 0)
				if ( i ~ /IDLE/ ) {
					lastColumn = split( i, Service );
					port = replace( "^.*[.:]", "", Service[ 1 ] );
					SERVICES[ "udp/" port ] = ( daemon != "" ? daemon : "-" );
				    }
			close( CMD );

		    } else if ( OS == "AIX" || OS == "HP-UX" ) {
			CMD = "netstat -an -f inet 2>/dev/null; netstat -an -f inet6 2>/dev/null";
			while (( CMD | getline i) > 0) {
				if ( i ~ /^tcp/ || i ~ /^udp/ ) {
					lastColumn = split( i, Service );
					if ( Service[ 1 ] ~ /^tcp/ && tolower( Service[ lastColumn ] ) == "listen") {
						port = replace( "^.*[.:]", "", Service[ 4 ] );
						SERVICES[ replace( "[46]$", "", Service[ 1 ] ) "/" port ] = ( daemon != "" ? daemon : "-" );

					    } else if ( Service[ 1 ] ~ /^udp/ && Service[ 5 ] == "*.*" ) {
#						&& ( Service[ 4 ] ~ /[*][.:][0-9]+/ || Service[ 4 ] ~ /[0-9]+[.][0-9]+[.][0-9]+[.][0-9]+[.:][0-9]+/ ) ) 
						port = replace( "^.*[.:]", "", Service[ 4 ] );
						SERVICES[ replace( "[46]$", "", Service[ 1 ] ) "/" port ] = ( daemon != "" ? daemon : "-" );
					    }
				    }
			    }
			close( CMD );

		    } else if ( OS == "windows32" ) {
		    	CMD = "netstat -an";
			while (( CMD | getline i) > 0) {
				if ( i ~ /^[ ]*TCP/ || i ~ /^[ ]*UDP/ ) {
					lastColumn = split( i, Service );
					if ( Service[ 1 ] ~ /^TCP/ && Service[ 3 ] ~ /:0$/ ) {
						port = replace( "^.*[.:]", "", Service[ 2 ] );
						SERVICES[ replace( "[46]$", "", tolower( Service[ 1 ] ) ) "/" port ] = ( daemon != "" ? daemon : "-" );

					    } else if ( Service[ 1 ] ~ /^[ ]*UDP/ && Service[ 3 ] == "*:*" ) {
						port = replace( "^.*[.:]", "", Service[ 2 ] );
						SERVICES[ replace( "[46]$", "", tolower( Service[ 1 ] ) ) "/" port ] = ( daemon != "" ? daemon : "-" );
					    }
				    }
			    }
			close( CMD );
		    }

		if ( DEBUG != "" && DEBUG != "0" && DEBUG != 0 ) {
			print "Command to figure out services: " CMD > LOGFILE;
			for ( i in SERVICES )
				printf("%s: \t%s\n", i, SERVICES[ i ] ) > LOGFILE;
			printf( "\n" ) > LOGFILE;
		    }
	    }

	# is stdin to be processed?
	if ( ARGC == 1 ) {
		if ( DEBUG != "" && DEBUG != "0" && DEBUG != 0 ) {
			print "No commandline-arguments are provided." > LOGFILE;
		    }

		CMD = ( OS != "windows32" ? "LC_ALL=C tty" : "tty" );
		if (( CMD | getline STDIN ) > 0 && STDIN ~ /\// ) {
			# STDIN is a tty, no conntrack-data is to be read from it

			close( CMD );
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
						print "ERROR: Cannot read any conntrack-files!\n   Please modprobe depending on kernel-version either nf_conntrack_ipv4 or ip_conntrack!\n" > LOGFILE;
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

			close( CMD );
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
			print i "/" ARGC-1 ": " ARGV[i] " unreadable!\n   Skipping..." > LOGFILE;
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
	LINEWIDTH = split( $0, LINE );
	split( "", CONNTRACK );

	 if ( OS == "Linux" && LINE[ 1 ] ~ /^ipv[46]$/ && LINE[ 3 ] in L4PROTOCOLS ) {

		++NOTICE[ "Input apparently nf_conntrack on contemporary Linux..." ];

		if ( tolower( $0 ) ~ /unreplied/ )
			next;

		# normalize Line wether /proc/net/nf_conntrack or /proc/net/ip_conntrack was read
		CONNTRACK[ "l3proto" ] = LINE[ 1 ];
		CONNTRACK[ "l4proto" ] = replace( "[46]$", "", LINE[ 3 ] );
		CONNTRACK[ "persistence" ] = LINE[ 5 ];

		for ( i=6; i<LINEWIDTH; i++ ) {
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

	    } else if ( OS == "Linux" && LINE[ 5 ] ~ /\=/ &&  LINE[ 6 ] ~ /\=/ && LINE[ 1 ] in L4PROTOCOLS ) {

		++NOTICE[ "Input apparently ip_conntrack on outdated Linux..." ];

		if ( tolower( $0 ) ~ /unreplied/ )
			next;

		# normalize Line wether /proc/net/nf_conntrack or /proc/net/ip_conntrack was read
		CONNTRACK[ "l3proto" ] = "ipv4";
		CONNTRACK[ "l4proto" ] = replace( "[46]$", "", LINE[ 1 ] );
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

	    } else if ( OS == "SunOS" &&	\
		LINE[ 1 ] ~ /[0-9]+[.][0-9]+[.][0-9]+[.][0-9]+[:.][0-9]+/ &&	\
		LINE[ 2 ] ~ /[0-9]+[.][0-9]+[.][0-9]+[.][0-9]+[:.][0-9]+/ &&	\
		LINE[ 3 ] ~ /[0-9]+/ && LINE[ 4 ] ~ /[0-9]+/ && LINE[ 5 ] ~ /[0-9]+/ && LINE[ 6 ] ~ /[0-9]+/ ) {

		++NOTICE[ "Input apparently from netstat on Solaris v10." ];

		CONNTRACK[ "l3proto" ] = "ipv4";
		CONNTRACK[ "l4proto" ] = "tcp";

		if ( tolower( LINE[ LINEWIDTH ] ) == "established"  )
			CONNTRACK[ "persistence" ] = 61;
		    else
			CONNTRACK[ "persistence" ] = 59;

		CONNTRACK[ "sport" ] = replace( "^.*[.:]", "", LINE[ 1 ] );
		CONNTRACK[ "src" ] = replace( "[.:][0-9]+$", "", LINE[ 1 ] );

		CONNTRACK[ "dport" ] = replace( "^.*[.:]", "", LINE[ 2 ] );
		CONNTRACK[ "dst" ] = replace( "[.:][0-9]+$", "", LINE[ 2 ] );

	    } else if (	LINE[ 4 ] ~ /[0-9]+[.][0-9]+[.][0-9]+[.][0-9]+[:.][0-9]+/ &&	\
			LINE[ 5 ] ~ /[0-9]+[.][0-9]+[.][0-9]+[.][0-9]+[:.][0-9]+/ &&	\
			LINE[ 1 ] in L4PROTOCOLS ) {
		## Linux
		#$ netstat -tune --notrim || netstat -tune --wide
		#Active Internet connections (w/o servers)
		#Proto Recv-Q Send-Q Local Address               Foreign Address             State       User       Inode
		#tcp        0      0 10.110.7.244:2049           10.110.6.35:606             ESTABLISHED 65534      2915692474
		# 
		## HPUX:
		#$ netstat -an -f inet | grep -v LISTEN
		#Active Internet connections (including servers)
		#Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)
		#tcp        0      0  10.91.27.26.59648      10.118.63.82.1521       ESTABLISHED
		# 

		++NOTICE[ "Input apparently from netstat on Linux or HP-UX..." ];

		if ( tolower( LINE[ 6 ] ) ~ /established/ )
			CONNTRACK[ "persistence" ] = 61;
		    else if ( tolower( LINE[ 6 ] ) ~ /wait/ )
			CONNTRACK[ "persistence" ] = 59;
		    else
			next;

		if ( LINE[ 1 ] !~ /6$/ )
			CONNTRACK[ "l3proto" ] = "ipv4";
		    else
			CONNTRACK[ "l3proto" ] = "ipv6";
		CONNTRACK[ "l4proto" ] = replace( "[46]$", "", LINE[ 1 ] );

		CONNTRACK[ "localPort" ] = replace( "^.*[.:]", "", LINE[ 4 ] );
		CONNTRACK[ "sport" ] = CONNTRACK[ "localPort" ]

		CONNTRACK[ "remotePort" ] = replace( "^.*[.:]", "", LINE[ 5 ] );
		CONNTRACK[ "dport" ] = CONNTRACK[ "remotePort" ]

		CONNTRACK[ "remoteIP" ] = replace( "[.:][0-9]+$", "", LINE[ 5 ] );
		CONNTRACK[ "dst" ] = CONNTRACK[ "remoteIP" ];

		CONNTRACK[ "localIP" ] = replace( "[.:][0-9]+$", "", LINE[ 4 ] );
		CONNTRACK[ "src" ] = CONNTRACK[ "localIP" ];

		# correct truncation of localIP and remoteIP related to fixed-width of netstat-ouput on old Linux or if netstat-parameters [--notrim||--wide] were not used
		if ( OS == "Linux" && !( CONNTRACK[ "localIP" ] in localIPs ) && CONNTRACK[ "localIP" ] ~ /:/ ) {

			# cleanup IPv6-Prefix "^::ffff:"
			sub( /^[:f]+:/, "", CONNTRACK[ "localIP" ] );

			for ( i in localIPs )
				if ( CONNTRACK[ "localIP" ] ~ ( "^" localIPs[ i ] ) ) {
					# trying to repair at least localIP
					CONNTRACK[ "localIP" ] = i;
					++NOTICE[ "Apparently truncated localIP " CONNTRACK[ "localIP" ] " got substituted by " i ];
					break;
				    }
			if ( !( CONNTRACK[ "localIP" ] in localIPs ) ) {
				sub( /\.[0-9]*$/, "/24", CONNTRACK[ "localIP" ] );
				++WARNINGS[ "Because apparently truncated localIP " CONNTRACK[ "src" ] " could not be recognized as any local IP, it got substitued by " CONNTRACK[ "localIP" ] ];
			    }

			# cleanup IPv6-Prefix "^::ffff:"
			sub( /^[:f]+:/, "", CONNTRACK[ "remoteIP" ] );

			# probably the remoteIP was also truncated, but for sure not when the last quarter is >= 100. 
			split( CONNTRACK[ "remoteIP" ], quad, "." );
			if ( int( quad[ 4 ] ) < 100 ) {
				# remoteIP could possibly also be a local one
				for ( i in localIPs )
					if ( CONNTRACK[ "remoteIP" ] ~ ( "^" localIPs[ i ] ) ) {
						CONNTRACK[ "remoteIP" ] = i;
						++NOTICE[ "Apparently truncated remoteIP " CONNTRACK[ "remoteIP" ] " got substituted by " i ];
						break;
					    }
				if ( !( CONNTRACK[ "remoteIP" ] in localIPs ) ) {
					sub( /\.[0-9]*$/, ".", CONNTRACK[ "remoteIP" ] );
					++WARNINGS[ "Probably truncated remoteIP " CONNTRACK[ "dst" ] " substituted by " CONNTRACK[ "remoteIP" ] ];
				    }
			    }

			CONNTRACK[ "src" ] = CONNTRACK[ "localIP" ];
			CONNTRACK[ "dst" ] = CONNTRACK[ "remoteIP" ];
		    }

	    } else if (	LINE[ 2 ] ~ /[0-9]+[.][0-9]+[.][0-9]+[.][0-9]+[:.][0-9]+/ &&	\
			LINE[ 3 ] ~ /[0-9]+[.][0-9]+[.][0-9]+[.][0-9]+[:.][0-9]+/ &&	\
			tolower( LINE[ 1 ] ) in L4PROTOCOLS ) {

		## windows32
		#C:\Documents and Settings\administrator> netstat -an
		#Active Connections
		#  Proto  Local Address          Foreign Address        State
		#  TCP    10.198.0.143:1811      10.193.9.211:2049      ESTABLISHED
		#  TCP    10.198.0.143:1816      10.193.9.210:2049      ESTABLISHED
		#  TCP    10.198.0.143:3389      10.119.105.211:50651   ESTABLISHED

		++NOTICE[ "Input apparently from netstat on Windows..." ];

		if ( tolower( LINE[ 4 ] ) ~ /established/ || tolower( LINE[ 4 ] ) ~ /hergestellt/ )
			CONNTRACK[ "persistence" ] = 61;
		    else if ( tolower( LINE[ 4 ] ) ~ /wait/ || tolower( LINE[ 4 ] ) ~ /wartend/ )
			CONNTRACK[ "persistence" ] = 59;
		    else
			next;

		if ( LINE[ 2 ] !~ /\[[0-9a-f:]*\]:/ )
			CONNTRACK[ "l3proto" ] = "ipv4";
		    else
			CONNTRACK[ "l3proto" ] = "ipv6";
		CONNTRACK[ "l4proto" ] = replace( "[46]$", "", tolower( LINE[ 1 ] ) );

		CONNTRACK[ "localPort" ] = replace( "^.*[.:]", "", LINE[ 2 ] );
		CONNTRACK[ "sport" ] = CONNTRACK[ "localPort" ]

		CONNTRACK[ "remotePort" ] = replace( "^.*[.:]", "", LINE[ 3 ] );
		CONNTRACK[ "dport" ] = CONNTRACK[ "remotePort" ]

		CONNTRACK[ "remoteIP" ] = replace( "[.:][0-9]+$", "", LINE[ 3 ] );
		CONNTRACK[ "dst" ] = CONNTRACK[ "remoteIP" ];

		CONNTRACK[ "localIP" ] = replace( "[.:][0-9]+$", "", LINE[ 2 ] );
		CONNTRACK[ "src" ] = CONNTRACK[ "localIP" ];

	    } else {
		if ( $0 !~ /BOUND/ && $0 !~ /IDLE/ && $0 !~ /LISTEN/ && LINE[ 3 ] !~ /:0$/ && LINE[ 3 ] != "*:*" && LINE[ 5 ] != "*.*" )
			++NOTICE[ "input line ignored: " $0 ];
		next;
	    }


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
		# or some string got shortened beyond reconizability
		if ( DEBUG != "" && DEBUG != "0" && DEBUG != 0 ) {
			++WARNINGS[ "foreign connection: " $0 ];
		    }

		# FIXME: do something better about this!
		next;
	    }


	# conjecture direction
	if ( CONNTRACK[ "direction" ] == "local" ) {
		if ( CONNTRACK[ "l4proto" ] "/" CONNTRACK[ "sport" ] in SERVICES ) {
			CONNTRACK[ "remotePort" ] = CONNTRACK[ "sport" ];
			CONNTRACK[ "localIP" ] = CONNTRACK[ "dst" ];
			CONNTRACK[ "remoteIP" ] = CONNTRACK[ "src" ];
			CONNTRACK[ "client" ] = CONNTRACK[ "localIP" ];
			CONNTRACK[ "server" ] = CONNTRACK[ "remoteIP" ];
		    } else {
			CONNTRACK[ "remotePort" ] = CONNTRACK[ "dport" ];
			CONNTRACK[ "localIP" ] = CONNTRACK[ "src" ];
			CONNTRACK[ "remoteIP" ] = CONNTRACK[ "dst" ];
			CONNTRACK[ "client" ] = CONNTRACK[ "remoteIP" ];
			CONNTRACK[ "server" ] = CONNTRACK[ "localIP" ];
		    }
		CONNTRACK[ "client" ] = "localhost";
		CONNTRACK[ "server" ] = "localhost";
		CONNTRACK[ "service" ] = CONNTRACK[ "l4proto" ] "/" CONNTRACK[ "remotePort" ];
		CONNTRACK[ "localPort" ] = 0;

	    # explicit casting as integer via int() to avoid string-comparison
	    } else if ( ( int( CONNTRACK[ "remotePort" ] ) < 1024 &&	\
			int( CONNTRACK[ "localPort" ] ) > ( int( Portrange[ 1 ] ) > 0 ? int( Portrange[ 1 ] ) : int( CONNTRACK[ "remotePort" ] ) ) ) ||	\
		    ! ( CONNTRACK[ "l4proto" ] "/" CONNTRACK[ "localPort" ] in SERVICES )) {
		CONNTRACK[ "direction" ] = "outgoing";
		CONNTRACK[ "client" ] = CONNTRACK[ "localIP" ];
		CONNTRACK[ "server" ] = CONNTRACK[ "remoteIP" ];
		CONNTRACK[ "service" ] = CONNTRACK[ "l4proto" ] "/" CONNTRACK[ "remotePort" ];
		CONNTRACK[ "localPort" ] = 0;

		if ( int( CONNTRACK[ "localPort" ] ) > ( int( Portrange[ 1 ] ) > 0 ? int( Portrange[ 1 ] ) : int( CONNTRACK[ "remotePort" ] ) ) ) {
			++NOTICE[ "highport-connection: " $0 ];
		    }

	    } else if ( CONNTRACK[ "localPort" ] == CONNTRACK[ "remotePort" ] ) {
		CONNTRACK[ "direction" ] = "peer2peer";
		CONNTRACK[ "client" ] = CONNTRACK[ "localIP" ];
		CONNTRACK[ "server" ] = CONNTRACK[ "remoteIP" ];
		CONNTRACK[ "service" ] = CONNTRACK[ "l4proto" ] "/" CONNTRACK[ "remotePort" ];

	    # explicit casting as integer via int() to avoid string-comparison
	    } else if ( CONNTRACK[ "l4proto" ] "/" CONNTRACK[ "localPort" ] in SERVICES &&	\
		    int( CONNTRACK[ "localPort" ] ) < ( int( Portrange[ 1 ] ) > 0 ? int( Portrange[ 1 ] ) : 32768 ) ) {
		CONNTRACK[ "direction" ] = "incoming";
		CONNTRACK[ "client" ] = CONNTRACK[ "remoteIP" ];
		CONNTRACK[ "server" ] = CONNTRACK[ "localIP" ];
		CONNTRACK[ "service" ] = CONNTRACK[ "l4proto" ] "/" CONNTRACK[ "localPort" ];
		CONNTRACK[ "remotePort" ] = 0;

	    } else {
		if ( DEBUG != "" && DEBUG != "0" && DEBUG != 0 ) {
			++WARNINGS[ "unrecognized direction: " $0 ];
		    }

		# FIXME: do something better about this!
		next;
	    }

	CONNTRACK[ "hostname" ] = HOSTNAME;
	if ( CONNTRACK[ "direction" ] == "outgoing" )
		CONNTRACK[ "daemon" ] = ">";
	    else if ( CONNTRACK[ "service" ] in SERVICES )
		CONNTRACK[ "daemon" ] = SERVICES[ CONNTRACK[ "service" ] ];
	    else {
		if ( !( CONNTRACK[ "localIP" ] in IPBLACKLIST || CONNTRACK[ "remoteIP" ] in IPBLACKLIST ) )
			++WARNINGS[ "unrecognized service: " $0 ];
			CONNTRACK[ "daemon" ] = "?";
	    }


	if (! ( CONNTRACK[ "direction" ] == "local"	|| CONNTRACK[ "direction"  ] == "foreign"		|| \
	    CONNTRACK[ "localPort" ] in PORTBLACKLIST	|| CONNTRACK[ "remotePort" ] in PORTBLACKLIST	|| \
	    CONNTRACK[ "localIP"   ] in IPBLACKLIST	|| CONNTRACK[ "remoteIP"   ] in IPBLACKLIST ) ) {

		CONNINDEX = CONNTRACK[ OUTPUTFORMAT[ 1 ] ];
		for ( i=2; OUTPUTFORMAT[ i+1 ] != ""; i++ )
			CONNINDEX = CONNINDEX SUBSEP CONNTRACK[ OUTPUTFORMAT[i] ];
		++CONNECTIONS[ CONNINDEX ];

	    } else
		if ( DEBUG != "" && DEBUG != "0" && DEBUG != 0 ) {
			CONNINDEX = CONNTRACK[ OUTPUTFORMAT[ 1 ] ];
			for ( i=2; OUTPUTFORMAT[ i+1 ] != ""; i++ )
				CONNINDEX = CONNINDEX SUBSEP CONNTRACK[ OUTPUTFORMAT[i] ];
			++CONNECTIONS[ CONNINDEX ];
		    }
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
		for ( i in NOTICE )
			print i > LOGFILE;
		printf( "\n#%s\n", INDEX ) > LOGFILE;
		for ( i in CONNECTIONS )
			printf( "%s,%d,%d\n", i, CONNECTIONS[i], SAVEDCONNECTIONS[i] ) > LOGFILE;
	    }
	close( LOGFILE );

	if ( DEBUG != "" && DEBUG != "0" && DEBUG != 0 )
		system("ps -o ppid= -p $$ 2>/dev/null | xargs lsof -p 2>/dev/null >>" LOGFILE );

#	# FixMe: print help if sensible
#	if ( ARGC < 2 && NR < 1 )
#		print HELP;

    }
