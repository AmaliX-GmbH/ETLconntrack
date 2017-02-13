#!/usr/bin/awk -f
#
# see http://www.iptables.info/en/connection-state.html
# 
# ./bin/ETLcontrack.awk 
# 
# accepted parameters:
# -v OutputFormat="service,direction,localIP,remoteIP,counter"
# -v STATEFILE=$PATH/$FILE.csv 
# -v LOGFILE=$PATH/$FILE.log
# -v IPblacklist="127.0.0.1 192.168.49.1"
# -v IPwhitelist="10.119.146.19 10.110.7.244"
# -v PORTblacklist="22 111 2048 2049"
# -v Services="udp/123"	NOT to be used beyond special circumstances!
# -v HOSTNAME="myname"	NOT to be used beyond special circumstances!
# *_conntrack-file	if another file beyond /proc/net/ip_conntrack or /proc/net/nf_conntrack is to be read
# 
# (C) 2016 by Henning Rohde, hero@amalix.de
# feel free to ask for further customization
# 
# FixMe: No IPv6 yet
# FixMe: runs only on modern Linux >v2.4
# 

BEGIN {
	SUBSEP=",";
	if ( LOGFILE == "" ) LOGFILE="/dev/stderr";

	# Define fields in Output and StateFile
	if ( OutputFormat != "" ) {
		if ( OutputFormat ~ SUBSEP )
			FORMATWIDTH = split( OutputFormat, OUTPUTFORMAT, SUBSEP );
		    else
			FORMATWIDTH = split( OutputFormat, OUTPUTFORMAT );
	    } else {
		FORMATWIDTH = split( "hostname,service,direction,localIP,localPort,remoteIP,remotePort,daemon,counter", OUTPUTFORMAT, "," );
#		FORMATWIDTH = split( "l4proto,localIP,localPort,remoteIP,remotePort,counter", OUTPUTFORMAT, "," );
#		FORMATWIDTH = split( "service,direction,localIP,remoteIP,counter", OUTPUTFORMAT, "," );
#		FORMATWIDTH = split( "service,client,server,counter", OUTPUTFORMAT, "," );
	    }

	# predefine Index as Headline
	INDEX=OUTPUTFORMAT[1];
	for ( i=2; OUTPUTFORMAT[i] != ""; i++ )
		INDEX = INDEX SUBSEP OUTPUTFORMAT[i];

	# read StateFile
	if ( STATEFILE != "" ) {
		while (( getline CONNECTION < STATEFILE ) > 0 )
			if ( CONNECTION !~ /^#/ ) {
				split( CONNECTION, LINE, SUBSEP );
				CONNINDEX = LINE[1];
				for ( i=2; OUTPUTFORMAT[ i+1] != ""; i++ )
					CONNINDEX = CONNINDEX SUBSEP LINE[i];
				COUNTER = LINE[i];
				# cap maxcount at some arbitrary number as e.g. 1440
				CONNECTIONS[ CONNINDEX ] = ( COUNTER > 24*60 ? 24*60 : COUNTER );
				if ( DEBUG != 0 || DEBUG != "" )
					printf( "%s = %s\n", CONNINDEX, CONNECTIONS[ CONNINDEX ] ) > LOGFILE;
			    }
		close( STATEFILE );
		if ( DEBUG != 0 || DEBUG != "" )
			printf("\n") > LOGFILE;
	    }

	# blacklist local or remote IPs
	if ( IPblacklist != "" ) {
		if ( IPblacklist ~ SUBSEP )
			split( IPblacklist, IPBLACKLIST, SUBSEP );
		    else
			split( IPblacklist, IPBLACKLIST );
		# transponate values to indices for easier searching
		for ( i in IPBLACKLIST ) {
			IPBLACKLIST[IPBLACKLIST[i]]=i;
			delete IPBLACKLIST[i];
		    }
	    } else if ( DEBUG != 0 || DEBUG != "" ) {
		split( "", IPBLACKLIST );
	    } else {
		++IPBLACKLIST["127.0.0.1"];
		IPBLACKLIST["10.110.7.244"]	= "denth7xr007";
		IPBLACKLIST["10.110.11.251"]	= "denth7xr007";
		IPBLACKLIST["10.119.146.19"]	= "denth7xr007";
		IPBLACKLIST["10.110.9.245"]	= "denth7xr011";
		IPBLACKLIST["10.110.13.251"]	= "denth7xr011";
		IPBLACKLIST["10.119.163.15"]	= "denth7xr011";
		IPBLACKLIST["10.193.22.9"]	= "ship01";
		IPBLACKLIST["10.193.22.10"]	= "ship01";
		IPBLACKLIST["10.193.22.11"]	= "ship01";
		IPBLACKLIST["10.198.0.100"]	= "wasm01";
#		IPBLACKLIST[""]	= "";
	    }

	# blacklist local or remote Ports
	if ( PORTblacklist != "" ) {
		if ( PORTblacklist ~ SUBSEP )
			split( PORTblacklist, PORTBLACKLIST, SUBSEP );
		    else
			split( PORTblacklist, PORTBLACKLIST );
		# transponate values to indices for easier searching
		for ( i in PORTBLACKLIST ) {
			PORTBLACKLIST[PORTBLACKLIST[i]]=i;
			delete PORTBLACKLIST[i];
		    }
	    } else if ( DEBUG != 0 || DEBUG != "" ) {
		    split( "", PORTBLACKLIST );
	    } else {
		PORTBLACKLIST["53"] = "DNS";
		PORTBLACKLIST["123"] = "NTP";
		PORTBLACKLIST["1984"] = "XyMon / BigBrother / Hobbit";
		PORTBLACKLIST["3181"] = "Patrol";
	    }

	# 
	if ( HOSTNAME == "" || HOSTNAME == "localhost" ) {
		if (( "uname -n" | getline HOSTNAME ) > 0 && HOSTNAME=="localhost" ) {
			print "\n  Hostname unknown!\n  Please provide Hostname with parameter '-v HOSTNAME=[...]'\n" > LOGFILE;
			if (! ( DEBUG != 0 || DEBUG != "" ))
				exit ERROR=1;
		    }
		close( "uname -n" );
	    }
	sub(/[^A-Za-z0-9-].*$/,"",HOSTNAME)

	#
	if (( "uname -s" | getline OS ) >0 && ( OS != "Linux" )) {
		print "\n  Unknown OS \"" OS "\"!\n  Please gather netstat-data manually and run skript on supported awk-version.\n" > LOGFILE;
		if (! ( DEBUG != 0 || DEBUG != "" ))
			exit ERROR=1;
	    }
	close( "uname -s" );

	#
	if ( IPwhitelist != "" ) {
		# only specific local IPs are to be analyzed
		if ( IPwhitelist ~ SUBSEP )
			split( IPwhitelist, IPWHITELIST, SUBSEP );
		    else
			split( IPwhitelist, IPWHITELIST );
		# transponate values to indices for easier searching
		for ( i in IPWHITELIST ) {
			delete IPBLACKLIST[IPWHITELIST[i]];
			IPWHITELIST[IPWHITELIST[i]]=i;
			delete IPWHITELIST[i];
		    }
	    } else {
		# any local IP is to be analyzed
		if (( "type ip 2>/dev/null" | getline junk ) > 0) {
			CMD=" ip -4 -o a s 2>/dev/null | awk '{ print $4}' | cut -d '/' -f 1 ";
		    } else if (( "find /sbin/ifconfig 2>/dev/null" | getline junk ) > 0) {
			CMD=" /sbin/ifconfig -a | awk '{if ( $1 ~ /^inet$/ ) { if ($2 ~ /:/) print substr( $2, index($2,\":\")+1); else print $2;}}'"
		    } else {
			print "\n  Neither ip nor ifconfig found!\n  Please provide relevant IP-adresses with parameter '-v IPwhitelist=[...]'\n" > LOGFILE;
			if (! ( DEBUG != 0 || DEBUG != "" ))
				exit ERROR=1;
		    }
		close( "type ip 2>/dev/null" );
		close( "type ifconfig 2>/dev/null" );

		while ( ( CMD | getline i ) > 0 && junk != "" )
			++IPWHITELIST[i];
		close( CMD );

		if ( DEBUG != 0 || DEBUG != "" ) {
			print CMD > LOGFILE;
			for ( i in IPWHITELIST )
				print i > LOGFILE;
			printf("\n") > LOGFILE;
		    }
	    }

	# 
	if ( L4Protocols != "" ) {
		if ( L4Protocols ~ SUBSEP )
			split( L4Protocols, L4PROTOCOLS, SUBSEP );
		    else
			split( L4Protocols, L4PROTOCOLS );

		# transponate values to indices for easier searching
		for ( i in L4PROTOCOLS ) {
			L4PROTOCOLS[L4PROTOCOLS[i]]=i;
			delete L4PROTOCOLS[i];
		    }
#	    } else if ( DEBUG != 0 || DEBUG != "" ) {
#		# FixMe: autogenerate List from /proc/net/protocols
	    } else {
		++L4PROTOCOLS["tcp"];
		++L4PROTOCOLS["tcp6"];
		++L4PROTOCOLS["udp"];
		++L4PROTOCOLS["udp6"];
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
			SERVICES[SERVICES[i]]="!";
			delete SERVICES[i];
		    }
	    } else {

		CMD=" netstat -tulpn 2>/dev/null ";
		while (( CMD | getline i) > 0) {

			gsub( /[ ]+/, SUBSEP, i );
			lastColumn=split( i, Service, SUBSEP );

			if ( Service[1] in L4PROTOCOLS ) {
				port = Service[4];
				sub( /^.*[.:]/, "", port );
				daemon = Service[ lastColumn -1 ];
				sub( /[0-9]*\//, "", daemon );
				SERVICES[ substr( Service[1], 1, 3 ) "/" port ] = ( daemon != "" ? daemon : "-" );

			    } else if ( DEBUG != 0 || DEBUG != "" ) {
				print i > LOGFILE;
			    }
		    }
		close( CMD );
	    }

	# if /dev/stdin != /dev/pts/1: nothing is to be read from STDIN
	CMD=" LC_ALL=C stat -c '%F' -L /dev/stdin ";
	if (( CMD | getline STDIN ) > 0 && STDIN == "character special file" ) {
		close( CMD );
		if ( DEBUG != 0 || DEBUG != "" )
			print STDIN > LOGFILE;

		if ( ARGC==1 ) {
			# not any input-files was provided on commandline

			# check priviledge because /proc/net/ip_conntrack and /proc/net/nf_conntrack are only readable to root
			if (( "id -u" | getline UID ) > 0 && UID>0 ) {
				print "\n  Skript must be run as root for reading /proc/net/*_conntrack!\n" > LOGFILE;
				if (! ( DEBUG != 0 || DEBUG != "" ))
					exit ERROR=1;
			    }
			close( "id -u" );

			# autodetect wethter /proc/net/ip_conntrack or /proc/net/nf_conntrack is to be read
			if (( getline i < "/proc/net/ip_conntrack" ) > 0 ) {
				ARGC++;
				ARGV[1]="/proc/net/ip_conntrack";
				close ("/proc/net/ip_conntrack");
			    } else if (( getline i < "/proc/net/nf_conntrack" ) > 0 ) {
				ARGC++;
				ARGV[1]="/proc/net/nf_conntrack";
				close ("/proc/net/nf_conntrack");
			    } else {
				print "\n  Cannot read any conntrack-files!\n  Please modprobe depending on kernel-version either ip_conntrack or nf_conntrack!\n" > LOGFILE;
				if (! ( DEBUG != 0 || DEBUG != "" ))
					exit ERROR=1;
			    }

		    } else for (i = 1; i < ARGC; i++) {
			if ( DEBUG != 0 || DEBUG != "" )
				print i "/" ARGC-1 ":" ARGV[i];

			# at least something was provided on commandline
			# check input-files for readability
			if (ARGV[i] ~ /^[a-zA-Z_][a-zA-Z0-9_]*=.*/ || ARGV[i] ~ /^-/ || ARGV[i] == "/dev/stdin") {
				NoFileArgs++;
				continue    # assignment or standard input
			    } else if ((getline junk < ARGV[i]) < 0) {
				printf("%s/%s: %s unreadable!\n",i,ARGC-1,ARGV[i]) > LOGFILE;
				close(ARGV[i]);
				delete ARGV[i];
				UnreadableFiles++;
			    } else
				close(ARGV[i]);
		    }

		if ( NoFileArgs + UnreadableFiles >= ARGC - 1 ) {
			print "\n  Cannot read any files listed on commandline!\n  Please check arguments!" > LOGFILE;
			exit ERROR=1;
		    }
	    } else {
		close( CMD );
		if ( DEBUG != 0 || DEBUG != "" )
			print STDIN > LOGFILE;
	    }
    }


#main()
{
	split( $0, LINE );
	split( "", CONNTRACK );


	# normalize Line wether /proc/net/ip_conntrack or /proc/net/nf_conntrack was read
	if ( LINE[1] ~ /^ipv[46]$/ && LINE[3] in L4PROTOCOLS ) {

	# looks like nf_conntrack
		CONNTRACK[ "l3proto" ] = LINE[1];
		CONNTRACK[ "l4proto" ] = LINE[3];
		CONNTRACK[ "persistence" ] = LINE[5];

		for ( i=6; i<=12; i++ ) {
			if ( LINE[i] ~ /=/ ) {
				split(LINE[i],ENTRY,"=");
				if (! ( ENTRY[1] in CONNTRACK ))
					CONNTRACK[ENTRY[1]]=ENTRY[2]
				if ( ENTRY[1] == "dport" )
					break;
			    }
		    }

	    } else if ( LINE[5] ~ /=/ &&  LINE[6] ~ /=/ && LINE[1] in L4PROTOCOLS ) {

	# looks like ip_conntrack
		CONNTRACK[ "l3proto" ] = "ipv4";
		CONNTRACK[ "l4proto" ] = LINE[1];
		CONNTRACK[ "persistence" ] = LINE[3];

		for ( i=4; i<=10; i++ ) {
			if ( LINE[i] !~ /=/ )
				continue;
			    else {
				split(LINE[i],ENTRY,"=");
				if (! ( ENTRY[1] in CONNTRACK ))
					CONNTRACK[ENTRY[1]]=ENTRY[2]
				if ( ENTRY[1] == "dport" )
					break;
			    }
		    }

	    } else if ( LINE[4] ~ /:/ && LINE[5] ~ /:/ && LINE[1] in L4PROTOCOLS ) {

	# looks like Linux-netstat
		if ( LINE[1] !~ /6$/ )
			CONNTRACK[ "l3proto" ] = "ipv4";
		    else
			CONNTRACK[ "l3proto" ] = "ipv6";
		CONNTRACK[ "l4proto" ] = substr( LINE[1], 1, 3);

		CONNTRACK[ "localIP" ] = LINE[4];
		sub( /[.:][0-9]+$/, "", CONNTRACK[ "localIP" ] );
		sub( /.*:/, "", CONNTRACK[ "localIP" ] );
		CONNTRACK["src"] = CONNTRACK["localIP"];

		CONNTRACK[ "localPort" ] = LINE[4];
		sub( /^.*[.:]/, "", CONNTRACK[ "localPort" ] );
		CONNTRACK["sport"] = CONNTRACK["localPort"];

		CONNTRACK[ "remoteIP" ] = LINE[5];
		sub( /[.:][0-9]+$/, "", CONNTRACK[ "remoteIP" ] );
		sub( /^.*:/, "", CONNTRACK[ "remoteIP" ] );
		CONNTRACK["dst"] = CONNTRACK["remoteIP"];

		CONNTRACK[ "remotePort" ] = LINE[5];
		sub( /^.*[.:]/, "", CONNTRACK[ "remotePort" ] );
		CONNTRACK["dport"] = CONNTRACK["remotePort"];

		if ( LINE[6]=="ESTABLISHED" )
			CONNTRACK[ "persistence" ] = 61;
		    else
			CONNTRACK[ "persistence" ] = 59;

	    } else if ( DEBUG != 0 || DEBUG != "" ) {
		printf("%s \n", $0) > LOGFILE;
		next;
	    } else
		next;

	# map localIP and remoteIP site
	if ( ( CONNTRACK["src"] in IPWHITELIST && CONNTRACK["dst"] in IPWHITELIST ) ) {
		CONNTRACK["direction"] = "local";
	    } else if ( CONNTRACK["src"] in IPWHITELIST ) {
		CONNTRACK["localIP"] = CONNTRACK["src"];
		CONNTRACK["localPort"] = CONNTRACK["sport"];
		CONNTRACK["remoteIP"] = CONNTRACK["dst"];
		CONNTRACK["remotePort"] = CONNTRACK["dport"];
	    } else if ( CONNTRACK["dst"] in IPWHITELIST ) {
		CONNTRACK["localIP"] = CONNTRACK["dst"];
		CONNTRACK["localPort"] = CONNTRACK["dport"];
		CONNTRACK["remoteIP"] = CONNTRACK["src"];
		CONNTRACK["remotePort"] = CONNTRACK["sport"];
	    } else if (! ( "localIP" in CONNTRACK )) {
		# either both IPs are foreign or blacklisted
		# or some string got shortened
		CONNTRACK["direction"] = "foreign";
	    }


	# conjecture direction
	if ( CONNTRACK["direction"] == "foreign" ) {
		# FixMe: do something
	    } else if ( CONNTRACK["direction"] == "local" ) {
		if ( CONNTRACK["l4proto"] "/" CONNTRACK["sport"] in SERVICES ) {
			CONNTRACK["remotePort"] = CONNTRACK["sport"];
		    } else {
			CONNTRACK["remotePort"] = CONNTRACK["dport"];
		    }
		CONNTRACK["client"] = "localhost";
		CONNTRACK["localIP"] = "127.0.0.1";
		CONNTRACK["remoteIP"] = "127.0.0.1";
		CONNTRACK["server"] = "localhost";
		CONNTRACK["service"] = CONNTRACK["l4proto"] "/" CONNTRACK["remotePort"];
		CONNTRACK["localPort"] = 0;
	    } else if (! ( CONNTRACK["l4proto"] "/" CONNTRACK["localPort"] in SERVICES )) {
		CONNTRACK["direction"] = "outgoing";
		CONNTRACK["client"] = CONNTRACK["localIP"];
		CONNTRACK["server"] = CONNTRACK["remoteIP"];
		CONNTRACK["service"] = CONNTRACK["l4proto"] "/" CONNTRACK["remotePort"];
		CONNTRACK["localPort"] = 0;
	    } else if ( CONNTRACK["localPort"] == CONNTRACK["remotePort"] ) {
		CONNTRACK["direction"] = "peer2peer";
		CONNTRACK["client"] = CONNTRACK["localIP"];
		CONNTRACK["server"] = CONNTRACK["remoteIP"];
		CONNTRACK["service"] = CONNTRACK["l4proto"] "/" CONNTRACK["remotePort"];
	    } else if ( CONNTRACK["l4proto"] "/" CONNTRACK["localPort"] in SERVICES ) {
		CONNTRACK["direction"] = "incoming";
		CONNTRACK["client"] = CONNTRACK["remoteIP"];
		CONNTRACK["server"] = CONNTRACK["localIP"];
		CONNTRACK["service"] = CONNTRACK["l4proto"] "/" CONNTRACK["localPort"];
		CONNTRACK["remotePort"] = 0;
	    } else if ( DEBUG != 0 || DEBUG != "" ) {
		for (i in CONNTRACK)
			printf("%s=%s\n",i,CONNTRACK[i]) > LOGFILE;
		printf("\n");
		next;
	    } else
		next;

	CONNTRACK[ "hostname" ] = HOSTNAME;
	if ( CONNTRACK["direction"] == "outgoing" )
		CONNTRACK[ "daemon" ] = ">";
	    else if ( CONNTRACK["service"] in SERVICES )
		CONNTRACK[ "daemon" ] = SERVICES[ CONNTRACK["service"] ];
	    else
		CONNTRACK[ "daemon" ] = "?";

	if (! ( CONNTRACK["direction"] == "local"	|| CONNTRACK["direction"] == "foreign"		|| \
	    CONNTRACK["localPort"] in PORTBLACKLIST	|| CONNTRACK["remotePort"] in PORTBLACKLIST	|| \
	    CONNTRACK["localIP"] in IPBLACKLIST		|| CONNTRACK["remoteIP"] in IPBLACKLIST ) ) {
		CONNINDEX=CONNTRACK[ OUTPUTFORMAT[1] ];
		for ( i=2; OUTPUTFORMAT[ i+1 ] != ""; i++ )
			CONNINDEX = CONNINDEX SUBSEP CONNTRACK[ OUTPUTFORMAT[i]];
		if ( CONNTRACK["persistence"]<60 || (! ( CONNINDEX in CONNECTIONS )) )
			++CONNECTIONS[ CONNINDEX ];
	    } else if ( DEBUG != 0 || DEBUG != "" ) {
		CONNINDEX=CONNTRACK[ OUTPUTFORMAT[1] ];
		for ( i=2; OUTPUTFORMAT[ i+1 ] != ""; i++ )
			CONNINDEX = CONNINDEX SUBSEP CONNTRACK[ OUTPUTFORMAT[i]];
		if ( CONNTRACK["persistence"]<60 || (! ( CONNINDEX in CONNECTIONS )) )
			++CONNECTIONS[ CONNINDEX ];
		next;
	    } else
		next;
    }

END {
	if ( ERROR != 0 || ERROR != "" )
		exit ERROR;
	if ( STATEFILE != "" ) {
		printf( "#%s\n", INDEX ) > STATEFILE;
		for (i in CONNECTIONS)
			printf("%s,%s\n",i,CONNECTIONS[i]) > STATEFILE; 

		if ( DEBUG != 0 || DEBUG != "" ) {
			printf( "#%s\n", INDEX ) > LOGFILE;
			for (i in CONNECTIONS)
				printf("%s,%s\n",i,CONNECTIONS[i]) > LOGFILE;
		    }
	    } else {
		printf( "#%s\n", INDEX );
		for (i in CONNECTIONS)
			printf("%s,%s\n",i,CONNECTIONS[i]);
	    }

#	# FixMe: print help if sensible
#	if ( ARGC<2 && NR<1 )
#		print HELP;
    }
