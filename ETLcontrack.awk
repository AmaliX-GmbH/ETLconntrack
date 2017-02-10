#!/bin/awk -f
# see http://www.iptables.info/en/connection-state.html
# 
# ./bin/ETLcontrack.awk 
# 
# accepted parameters:
# -v STATEFILE=$PATH/$FILE.csv 
# -v IPblacklist="127.0.0.1 192.168.49.1"
# -v IPwhitelist="10.119.146.19 10.110.7.244"
# -v HOSTNAME="myhostname"
# -v PORTblacklist="22 111 2048 2049"
# -v TCPports="80 443"	NOT to be used beyond special circumstances!
# -v UDPports="123"	NOT to be used beyond special circumstances!
# *_conntrack-file	if another file beyond /proc/net/ip_conntrack or /proc/net/nf_conntrack is to be read
# 

BEGIN {
	SUBSEP=",";

	# Define fields in StateFile
	if ( FileFormat != "" ) {
		if ( FileFormat ~ /,/ )
			split( FileFormat, FILEFORMAT, "," );
		    else
			split( FileFormat, FILEFORMAT );
	    } else
		split( "hostname,direction,l4proto,localIP,localPort,remoteIP,remotePort,counter", FILEFORMAT, "," );
	# predefine Index as Headline
	INDEX=FILEFORMAT[1];
	for ( i=2; FILEFORMAT[i] != ""; i++ )
		INDEX = INDEX SUBSEP FILEFORMAT[i];

	# read StateFile
	if ( STATEFILE != "" ) {
		while (( getline i < STATEFILE ) > 0 )
			if ( i !~ /^#/ ) {
				WIDTH=split( i, DBROW, SUBSEP );
				# cap maxcount at some arbitrary number as e.g. 1440
				COUNTER=( DBROW[WIDTH] > 24*60 ? 24*60 : DBROW[WIDTH] );
				delete DBROW[WIDTH];
				# FixMe: dynamic Index
				CONNECTIONS[DBROW[1],DBROW[2],DBROW[3],DBROW[4],DBROW[5],DBROW[6],DBROW[7]]=COUNTER;
				if ( DEBUG != 0 || DEBUG != "" )
					printf( "%s\n", i ) > "/dev/stderr";
			    }
		close( STATEFILE );
		if ( DEBUG != 0 || DEBUG != "" )
			printf("\n") > "/dev/stderr";
	    }

	# blacklist localIP or remoteIP IPWHITELIST
	if ( IPblacklist != "" ) {
		if ( IPblacklist ~ /,/ )
			split( IPblacklist, IPBLACKLIST, "," );
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

	# blacklist localIP or remoteIP Ports
	if ( PORTblacklist != "" ) {
		if ( PORTblacklist ~ /,/ )
			split( PORTblacklist, PORTBLACKLIST, "," );
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
		++PORTBLACKLIST["53"]
		++PORTBLACKLIST["123"]
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
	gsub(/[^A-Za-z0-9-].*$/,"",HOSTNAME)

	#
	if ( IPwhitelist != "" ) {
		# only specific IPWHITELIST are to be analyzed
		if ( IPwhitelist ~ /,/ )
			split( IPwhitelist, IPWHITELIST, "," );
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
			print "\n  Neither ip nor ifconfig found!\n  Please provide IPWHITELIST with parameter '-v IPwhitelist=[...]'\n" > "/dev/stderr";
			if (! ( DEBUG != 0 || DEBUG != "" ))
				exit ERROR=1;
		    }
		while ( ( CMD | getline i ) > 0 && junk != "" )
			++IPWHITELIST[i];
		close( CMD );
		close( "type ip 2>/dev/null" );
		close( "type ifconfig 2>/dev/null" );

		if ( DEBUG != 0 || DEBUG != "" ) {
			for ( i in IPWHITELIST ) print i;
			printf("\n");
		    }
	    }

	# 
	if ( L4Protocols != "" ) {
		if ( L4Protocols ~ /,/ )
			split( L4Protocols, L4PROTOCOLS, "," );
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
	if ( TCPports != "" ) {
		# manually provide list of listening tcpports
		# e.g. to process remotely gathered data
		if ( TCPports ~ /,/ )
			split( TCPports, TCPPORTS, "," );
		    else
			split( TCPports, TCPPORTS );
		# transponate values to indices for easier searching
		for ( i in TCPPORTS ) {
			TCPPORTS[TCPPORTS[i]]=i;
			delete TCPPORTS[i];
		    }
	    } else {
		# autogenerate list of listening tcpports
		CMD=" netstat -tln | awk '$1~/^tcp/ {print $4}' | awk -F '[.:]' '{print $NF}' ";
		while (( CMD | getline i ) > 0)
			++TCPPORTS[i];
		close( CMD );
	    }

	if ( UDPports != "" ) {
		# manually provide list of listening udpports
		# e.g. to process remotely gathered data
		if ( UDPports ~ /,/ )
			split( UDPports, UDPPORTS, "," );
		    else
			split( UDPports, UDPPORTS );
		# transponate values to indices for easier searching
		for ( i in UDPPORTS ) {
			UDPPORTS[UDPPORTS[i]]=i;
			delete UDPPORTS[i];
		    }
	    } else {
		# autogenerate list of listening udpports
		CMD=" netstat -uln | awk '$1~/^udp/ {print $4}' | awk -F '[.:]' '{print $NF}' ";
		while (( CMD | getline i ) > 0)
			++UDPPORTS[i];
		close( CMD );
	    }


	# if input-stream is not to be read from STDIN
	CMD="file -L /dev/stdin";
	if (( CMD | getline STDIN ) > 0 && ( STDIN !~ /fifo/ && STDIN !~ /pipe/ ) ) {
		if ( ARGC==1 ) {
			if (( "id -u" | getline UID ) > 0 && UID>0 ) {
				print "\n  Skript must be run as root!\n" > "/dev/stderr";
				if (! ( DEBUG != 0 || DEBUG != "" ))
					exit ERROR=1;
			    }
			close( "id -u" );

			# not any input-files was provided on commandline
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
				print "\n  Cannot read any conntrack-files!\n  Please modprobe depending on kernel-version either ip_conntrack or nf_conntrack!\n  Press <CTRL>+<c> to cancel command!\n" > "/dev/stderr"
				if (! ( DEBUG != 0 || DEBUG != "" ))
					exit ERROR=1;
			    }
		    } else for (i = 1; i < ARGC; i++) {
			# at least something was provided on commandline
			# check input-files for readability
			if (ARGV[i] ~ /^[a-zA-Z_][a-zA-Z0-9_]*=.*/ || ARGV[i] ~ /^-/ || ARGV[i] == "/dev/stdin")
				continue    # assignment or standard input
			    else if ((getline junk < ARGV[i]) < 0) {
				printf("%s/%s: %s unreadable!\n",i,ARGC-1,ARGV[i]) > "/dev/stderr"
				close(ARGV[i])
				delete ARGV[i]
			    } else
				close(ARGV[i])
			# MISSING FEATURE: exit with error if none of the input-files is readable
		    }
	    }
	close( CMD );
    }


#main()
{
	split($0,LINE);
	split("",CONNTRACK);

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
	if ( CONNTRACK["src"] in IPBLACKLIST || CONNTRACK["dst"] in IPBLACKLIST ) {
		next;
	    } else if ( ( CONNTRACK["src"] in IPWHITELIST ) && ( CONNTRACK["dst"] in IPWHITELIST ) ) {
		if ( DEBUG != 0 || DEBUG != "" ) {
			CONNTRACK["direction"]="localIP";
			CONNTRACK["localIP"]=CONNTRACK["dst"];
			CONNTRACK["localPort"]=CONNTRACK["sport"];
			CONNTRACK["remoteIP"]=CONNTRACK["dst"];
			CONNTRACK["remotePort"]=CONNTRACK["dport"];
		    } else
			next;
	    } else if ( ( CONNTRACK["src"] in IPWHITELIST ) && (! ( CONNTRACK["dst"] in IPWHITELIST )) ) {
		CONNTRACK["localIP"]=CONNTRACK["src"];
		CONNTRACK["localPort"]=CONNTRACK["sport"];
		CONNTRACK["remoteIP"]=CONNTRACK["dst"];
		CONNTRACK["remotePort"]=CONNTRACK["dport"];
	    } else if ( ( CONNTRACK["dst"] in IPWHITELIST ) && (! ( CONNTRACK["src"] in IPWHITELIST )) ) {
		CONNTRACK["localIP"]=CONNTRACK["dst"];
		CONNTRACK["localPort"]=CONNTRACK["dport"];
		CONNTRACK["remoteIP"]=CONNTRACK["src"];
		CONNTRACK["remotePort"]=CONNTRACK["sport"];
	    } else if ( DEBUG != 0 || DEBUG != "" ) {
		for (i in CONNTRACK)
			printf("%s=%s\n",i,CONNTRACK[i]);
		printf("\n");
		next;
	    } else
		next;

	# conjecture direction
	if ( CONNTRACK["localPort"] in PORTBLACKLIST || CONNTRACK["remotePort"] in PORTBLACKLIST )
		next;
	    else if ( CONNTRACK["l4proto"] ~ /^tcp/ ) {
		if (! ( CONNTRACK["localPort"] in TCPPORTS )) {
			if (! ( "direction" in CONNTRACK ))
				CONNTRACK["direction"]="outgoing";
			delete CONNTRACK["localPort"];
		    } else if ( CONNTRACK["localPort"]==CONNTRACK["remotePort"] ) {
			if (! ( "direction" in CONNTRACK ))
				CONNTRACK["direction"]="bidirectional";
		    } else if ( CONNTRACK["localPort"] in TCPPORTS ) {
			if (! ( "direction" in CONNTRACK ))
				CONNTRACK["direction"]="incoming";
			delete CONNTRACK["remotePort"];
		    } else
			next;
	    } else if ( CONNTRACK["l4proto"] ~ /^udp/ ) {
		if (! ( CONNTRACK["localPort"] in UDPPORTS )) {
			if (! ( "direction" in CONNTRACK ))
				CONNTRACK["direction"]="outgoing";
			delete CONNTRACK["localPort"];
		    } else if ( CONNTRACK["localPort"]==CONNTRACK["remotePort"] ) {
			if (! ( "direction" in CONNTRACK ))
				CONNTRACK["direction"]="bidirectional";
		    } else if ( CONNTRACK["localPort"] in UDPPORTS ) {
			if (! ( "direction" in CONNTRACK ))
				CONNTRACK["direction"]="incoming";
			delete CONNTRACK["remotePort"];
		    } else
			next;
	    } else if ( DEBUG != 0 || DEBUG != "" ) {
		for (i in CONNTRACK)
			printf("%s=%s\n",i,CONNTRACK[i])
		printf("\n")
		next;
	    } else
		next;

	CONNTRACK[ "hostname" ]=HOSTNAME;

	if ( CONNTRACK["l4proto"] in L4PROTOCOLS ) {
		CONNINDEX=CONNTRACK[ FILEFORMAT[1] ];
		for ( i=2; FILEFORMAT[i+1] != ""; i++ )
			CONNINDEX = CONNINDEX SUBSEP CONNTRACK[ FILEFORMAT[i]];
		if ( CONNTRACK["persistence"]<60 || (! ( CONNINDEX in CONNECTIONS )) )
			++CONNECTIONS[ CONNINDEX ];
	    } else if ( DEBUG != 0 || DEBUG != "" ) {
		for (i in CONNTRACK)
			printf("%s=%s\n",i,CONNTRACK[i])
		printf("\n")
		next;
	    }
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
