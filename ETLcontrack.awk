#!/bin/awk -f
# see http://www.iptables.info/en/connection-state.html
# 
# ./bin/ETLcontrack.awk 
# 
# accepted parameters:
# -v OutputFormat="l4proto,service,direction,localIP,remoteIP,counter"
# -v STATEFILE=$PATH/$FILE.csv 
# -v IPblacklist="127.0.0.1 192.168.49.1"
# -v IPwhitelist="10.119.146.19 10.110.7.244"
# -v PORTblacklist="22 111 2048 2049"
# -v L4Ports="udp/123"	NOT to be used beyond special circumstances!
# -v HOSTNAME="myname"	NOT to be used beyond special circumstances!
# *_conntrack-file	if another file beyond /proc/net/ip_conntrack or /proc/net/nf_conntrack is to be read
# 

BEGIN {
	SUBSEP=",";

	# Define fields in Output and StateFile
	if ( OutputFormat != "" ) {
		if ( OutputFormat ~ /,/ )
			FORMATWIDTH = split( OutputFormat, OUTPUTFORMAT, SUBSEP );
		    else
			FORMATWIDTH = split( OutputFormat, OUTPUTFORMAT );
	    } else
		FORMATWIDTH = split( "hostname,service,direction,localIP,localPort,remoteIP,remotePort,daemon,counter", OUTPUTFORMAT, "," );
#		FORMATWIDTH = split( "l4proto,localIP,localPort,remoteIP,remotePort,counter", OUTPUTFORMAT, "," );
#		FORMATWIDTH = split( "service,direction,localIP,remoteIP,counter", OUTPUTFORMAT, "," );
#		FORMATWIDTH = split( "service,client,server,counter", OUTPUTFORMAT, "," );
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
					printf( "%s = %s\n", CONNINDEX, CONNECTIONS[ CONNINDEX ] ) > "/dev/stderr";
			    }
		close( STATEFILE );
		if ( DEBUG != 0 || DEBUG != "" )
			printf("\n") > "/dev/stderr";
	    }

	# blacklist local or remote IPs
	if ( IPblacklist != "" ) {
		if ( IPblacklist ~ /,/ )
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
	    }

	# blacklist local or remote Ports
	if ( PORTblacklist != "" ) {
		if ( PORTblacklist ~ /,/ )
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
			print "\n  Hostname unknown!\n  Please provide Hostname with parameter '-v HOSTNAME=[...]'\n" > "/dev/stderr";
			if (! ( DEBUG != 0 || DEBUG != "" ))
				exit ERROR=1;
		    }
		close( "uname -n" );
	    }
	sub(/[^A-Za-z0-9-].*$/,"",HOSTNAME)

	#
	if ( IPwhitelist != "" ) {
		# only specific IPWHITELIST are to be analyzed
		if ( IPwhitelist ~ /,/ )
			split( IPwhitelist, IPWHITELIST, SUBSEP );
		    else
			split( IPwhitelist, IPWHITELIST );
		# transponate values to indices for easier searching
		for ( i in IPWHITELIST ) {
			IPWHITELIST[IPWHITELIST[i]]=i;
			delete IPBLACKLIST[IPWHITELIST[i]];
			delete IPWHITELIST[i];
		    }
	    } else {
		# any of localIP and remoteIP IPWHITELIST are to be analyzed
		if (( "type ip 2>/dev/null" | getline junk ) > 0) {
			CMD=" ip -4 -o a s 2>/dev/null | awk '{ print $4}' | cut -d '/' -f 1 ";
		    } else if (( "type ifconfig 2>/dev/null" | getline junk ) > 0) {
			CMD=" ifconfig -a | awk 'sub(/inet addr:/,\"\"){print $1}' ";
		    } else {
			print "\n  Neither ip nor ifconfig found!\n  Please provide relevant IP-adresses with parameter '-v IPwhitelist=[...]'\n" > "/dev/stderr";
			if (! ( DEBUG != 0 || DEBUG != "" ))
				exit ERROR=1;
		    }
		close( "type ip 2>/dev/null" );
		close( "type ifconfig 2>/dev/null" );

		while ( ( CMD | getline i ) > 0 && junk != "" )
			++IPWHITELIST[i];
		close( CMD );

		if ( DEBUG != 0 || DEBUG != "" ) {
			for ( i in IPWHITELIST ) print i;
			printf("\n");
		    }
	    }

	# 
	if ( L4Protocols != "" ) {
		if ( L4Protocols ~ /,/ )
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
	if ( L4Ports != "" ) {
		# manually provide list of listening l4proto/ports
		# e.g. to process remotely gathered data
		if ( L4Protocols ~ /,/ )
			split( L4Ports, L4PORTS, SUBSEP );
		    else
			split( L4Ports, L4PORTS );

		# transponate values to indices for easier searching
		for ( i in L4PORTS ) {
			L4PORTS[L4PORTS[i]]=i;
			delete L4PORTS[i];
		    }
	    } else {
		CMD=" netstat -tulpen 2>/dev/null ";
		while (( CMD | getline i) > 0) {
			if ( substr( i, 1, 3) in L4PROTOCOLS ) {
				port = i;
				sub( /^.[^ ]+[ ]+[^ ]+[ ]+[^ ]+[ ]+/, "", port );
				sub( /[ ].*$/, "", port );
				sub( /^.*[.:]/, "", port );
				daemon = i;
				sub( /^.*[-\/]/, "", daemon );
				sub( /[ ].*$/, "", daemon );
				L4PORTS[ substr( i, 1, 3) "/" port ] = ( daemon != "" ? daemon : "-" );
			    }
		    }
		close( CMD );
	    }

	# if input-stream is not to be read from STDIN
	if (( "file -L /dev/stdin" | getline STDIN ) > 0 && ( STDIN !~ /fifo/ && STDIN !~ /pipe/ ) ) {
		if ( ARGC==1 ) {
			# not any input-files was provided on commandline

			# check priviledge because /proc/net/ip_conntrack and /proc/net/nf_conntrack are only readable to root
			if (( "id -u" | getline UID ) > 0 && UID>0 ) {
				print "\n  Skript must be run as root for reading /proc/net/*_conntrack!\n" > "/dev/stderr";
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
				print "\n  Cannot read any conntrack-files!\n  Please modprobe depending on kernel-version either ip_conntrack or nf_conntrack!\n" > "/dev/stderr";
				if (! ( DEBUG != 0 || DEBUG != "" ))
					exit ERROR=1;
			    }

		    } else for (i = 1; i < ARGC; i++) {
			# at least something was provided on commandline
			# check input-files for readability
			if (ARGV[i] ~ /^[a-zA-Z_][a-zA-Z0-9_]*=.*/ || ARGV[i] ~ /^-/ || ARGV[i] == "/dev/stdin") {
				NoFileArgs++;
				continue    # assignment or standard input
			    } else if ((getline junk < ARGV[i]) < 0) {
				printf("%s/%s: %s unreadable!\n",i,ARGC-1,ARGV[i]) > "/dev/stderr";
				close(ARGV[i]);
				delete ARGV[i];
				UnreadableFiles++;
			    } else
				close(ARGV[i]);
		    }
		if ( NoFileArgs + UnreadableFiles >= ARGC - 1 ) {
			print "\n  Cannot read any files listed on commandline!\n  Please check arguments!" > "/dev/stderr";
			exit ERROR=1;
		    }
	    }
	close( "file -L /dev/stdin" );
    }


#main()
{
	split( $0, LINE );
	split( "", CONNTRACK );


	# normalize Line wether /proc/net/ip_conntrack or /proc/net/nf_conntrack was read
	if ( LINE[1] in L4PROTOCOLS ) {
		LINE[0]="l3proto=ipv4";
		delete LINE[2];
		LINE[1]="l4proto=" LINE[1];
		LINE[3]="persistence=" LINE[3];
	    } else if ( LINE[3] in L4PROTOCOLS ) {
		LINE[1]="l3proto=" LINE[1];
		delete LINE[2];
		delete LINE[4];
		LINE[3]="l4proto=" LINE[3];
		LINE[5]="persistence=" LINE[5];
	    } else if ( DEBUG != 0 || DEBUG != "" ) {
		printf("%s \n", $0)
		next;
	    } else
		next;


	# transponate values to indices for easier searching
	for (i in LINE) {
		if ( i==2 || i==4 )
			continue;
		if ( LINE[i] ~ /=/ ) {
			split(LINE[i],ENTRY,"=");
			if (! ( ENTRY[1] in CONNTRACK ))
				CONNTRACK[ENTRY[1]]=ENTRY[2]
		    } else
			CONNTRACK[LINE[i]]=i;
		delete LINE[i];
	    }


	# clean superfluus data
	delete CONNTRACK["mark"];
	delete CONNTRACK["secmark"];
	delete CONNTRACK["use"];


	# map localIP and remoteIP site
	if ( ( CONNTRACK["src"] in IPWHITELIST ) && ( CONNTRACK["dst"] in IPWHITELIST ) ) {
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
	    } else {
		# Both IPs are foreign or blacklisted
		CONNTRACK["direction"] = "foreign";
	    }


	# conjecture direction
	if ( CONNTRACK["direction"] == "foreign" ) {
		# FixMe: do something
	    } else if ( CONNTRACK["direction"] == "local" ) {
		if ( CONNTRACK["l4proto"] "/" CONNTRACK["sport"] in L4PORTS ) {
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
	    } else if (! ( CONNTRACK["l4proto"] "/" CONNTRACK["localPort"] in L4PORTS )) {
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
	    } else if ( CONNTRACK["l4proto"] "/" CONNTRACK["localPort"] in L4PORTS ) {
		CONNTRACK["direction"] = "incoming";
		CONNTRACK["client"] = CONNTRACK["remoteIP"];
		CONNTRACK["server"] = CONNTRACK["localIP"];
		CONNTRACK["service"] = CONNTRACK["l4proto"] "/" CONNTRACK["localPort"];
		CONNTRACK["remotePort"] = 0;
	    } else if ( DEBUG != 0 || DEBUG != "" ) {
		for (i in CONNTRACK)
			printf("%s=%s\n",i,CONNTRACK[i]);
		printf("\n");
		next;
	    } else
		next;

	CONNTRACK[ "hostname" ] = HOSTNAME;
	CONNTRACK[ "daemon" ] = ( CONNTRACK["service"] in L4PORTS ? L4PORTS[ CONNTRACK["service"] ] : ">" );

	if (! ( CONNTRACK["direction"] == "local" || CONNTRACK["direction"] == "foreign" || \
	    CONNTRACK["localPort"] in PORTBLACKLIST || CONNTRACK["remotePort"] in PORTBLACKLIST ) ) {
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
			printf( "#%s\n", INDEX ) > "/dev/stderr";
			for (i in CONNECTIONS)
				printf("%s,%s\n",i,CONNECTIONS[i]) > "/dev/stderr";
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
