#!/bin/awk -f
# see http://www.iptables.info/en/connection-state.html
# 
# ./bin/ETLcontrack.awk 
# 
# accepted parameters:
# -v STATEFILE=$PATH/$FILE.csv 
# -v IPblacklist="127.0.0.1 192.168.49.1"
# -v IPwhitelist="10.119.146.19 10.110.7.244"
# -v PORTblacklist="22 111 2048 2049"
# -v TCPlisten="80 443"	NOT to be used beyond special circumstances!
# -v UDPlisten="123"	NOT to be used beyond special circumstances!
# *_conntrack-file	if another file beyond /proc/net/ip_conntrack or /proc/net/nf_conntrack is to be read
# 

BEGIN {
	SUBSEP=",";

	# read StateFile
	if ( STATEFILE != "" ) {
		while (( getline i < STATEFILE ) > 0 )
			if ( i !~ /^#/ ) {
				split( i, DBROW, SUBSEP );
				# cap maxcount at some arbitrary number as e.g. 1440
				CONNECTIONS[DBROW[1],DBROW[2],DBROW[3],DBROW[4],DBROW[5],DBROW[6]]=( DBROW[7] > 24*60 ? 24*60 : DBROW[7] );
				if ( DEBUG != 0 || DEBUG != "" )
					printf( "%s\n", i );
			    }
		close( STATEFILE );
		if ( DEBUG != 0 || DEBUG != "" )
			printf("\n");
	    }

	# blacklist local or remote IPs
	if ( IPblacklist != "" ) {
		if ( IPblacklist ~ /,/ )
			split( IPblacklist, blackIPs, "," );
		    else
			split( IPblacklist, blackIPs );
		# transponate values to indices for easier searching
		for ( i in blackIPs ) {
			blackIPs[blackIPs[i]]=i;
			delete blackIPs[i];
		    }
	    } else if ( DEBUG != 0 || DEBUG != "" ) {
		    split( "", blackIPs );
	    } else {
		++blackIPs["127.0.0.1"];
	    }

	# blacklist local or remote Ports
	if ( PORTblacklist != "" ) {
		if ( PORTblacklist ~ /,/ )
			split( PORTblacklist, blackPORTs, "," );
		    else
			split( PORTblacklist, blackPORTs );
		# transponate values to indices for easier searching
		for ( i in blackPORTs ) {
			blackPORTs[blackPORTs[i]]=i;
			delete blackPORTs[i];
		    }
	    } else if ( DEBUG != 0 || DEBUG != "" ) {
		    split( "", blackPORTs );
	    } else {
		++blackPORTs["53"]
		++blackPORTs["123"]
	    }

	CMD=" id -u ";
	if (( CMD | getline UID ) > 0 && UID>0 ) {
		print "\n  Skript must be run as root!\n" > "/dev/stderr";
		if (! ( DEBUG != 0 || DEBUG != "" ))
			exit EXIT=1;
	    }
	close( CMD );

	if ( IPwhitelist != "" ) {
		# only specific IPs are to be analyzed
		if ( IPwhitelist ~ /,/ )
			split( IPwhitelist, IPs, "," );
		    else
			split( IPwhitelist, IPs );
		# transponate values to indices for easier searching
		for ( i in IPs ) {
			IPs[IPs[i]]=i;
			delete blackIPs[IPs[i]];
			delete IPs[i];
		    }
	    } else {
		# any of local and remote IPs are to be analyzed
		if (( "type ip 2>/dev/null" | getline junk ) > 0) {
			CMD=" ip -4 -o a s 2>/dev/null | awk '{ print $4}' | cut -d '/' -f 1 ";
		    } else if (( "type ifconfig 2>/dev/null" | getline junk ) > 0) {
			CMD=" ifconfig -a | awk 'sub(/inet addr:/,\"\"){print $1}' ";
		    } else {
			print "\n  Neither ip nor ifconfig found!\n  Please provide IPs with parameter '-v IPwhitelist=[...]'\n" > "/dev/stderr";
			if (! ( DEBUG != 0 || DEBUG != "" ))
				exit EXIT=1;
		    }
		while ( ( CMD | getline i ) > 0 && junk != "" )
			++IPs[i];
		close( CMD );
		close( "type ip 2>/dev/null" );
		close( "type ifconfig 2>/dev/null" );

		if ( DEBUG != 0 || DEBUG != "" ) {
			for ( i in IPs ) print i;
			printf("\n");
		    }
	    }

	# 
	if ( TCPlisten != "" ) {
		# manually provide list of listening tcpports
		# e.g. to process remotely gathered data
		if ( TCPlisten ~ /,/ )
			split( TCPlisten, TCPPORTS, "," );
		    else
			split( TCPlisten, TCPPORTS );
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

	if ( UDPlisten != "" ) {
		# manually provide list of listening udpports
		# e.g. to process remotely gathered data
		if ( UDPlisten ~ /,/ )
			split( UDPlisten, UDPPORTS, "," );
		    else
			split( UDPlisten, UDPPORTS );
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
					exit EXIT=1;
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
	if ( LINE[1]=="tcp" || LINE[1]=="udp" ) {
		LINE[2]="ipv4";
		CONNTRACK["persistence"]=LINE[3];
		delete LINE[3];
	    } else if ( LINE[3]=="tcp" || LINE[3]=="udp" ) {
		delete LINE[2];
		delete LINE[4];
		CONNTRACK["persistence"]=LINE[5];
		delete LINE[5];
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


	# superflouus data
	delete CONNTRACK["mark"];
	delete CONNTRACK["secmark"];
	delete CONNTRACK["use"];


	# map local and remote site
	if ( CONNTRACK["src"] in blackIPs || CONNTRACK["dst"] in blackIPs )
		next;
	    else if ( ( CONNTRACK["src"] in IPs ) && ( CONNTRACK["dst"] in IPs ) )
		if ( DEBUG != 0 || DEBUG != "" ) {
			CONNTRACK["direction"]="local";
			CONNTRACK["local"]=CONNTRACK["dst"];
			CONNTRACK["lport"]=CONNTRACK["sport"];
			CONNTRACK["remote"]=CONNTRACK["dst"];
			CONNTRACK["rport"]=CONNTRACK["dport"];
		    } else
			next;
	    else if ( ( CONNTRACK["src"] in IPs ) && (! ( CONNTRACK["dst"] in IPs )) ) {
		CONNTRACK["local"]=CONNTRACK["src"];
		CONNTRACK["lport"]=CONNTRACK["sport"];
		CONNTRACK["remote"]=CONNTRACK["dst"];
		CONNTRACK["rport"]=CONNTRACK["dport"];
	    } else if ( ( CONNTRACK["dst"] in IPs ) && (! ( CONNTRACK["src"] in IPs )) ) {
		CONNTRACK["local"]=CONNTRACK["dst"];
		CONNTRACK["lport"]=CONNTRACK["dport"];
		CONNTRACK["remote"]=CONNTRACK["src"];
		CONNTRACK["rport"]=CONNTRACK["sport"];
	    } else if ( DEBUG != 0 || DEBUG != "" ) {
		for (i in CONNTRACK)
			printf("%s=%s\n",i,CONNTRACK[i])
		printf("\n")
		next;
	    } else
		next;
	delete CONNTRACK["src"];
	delete CONNTRACK["sport"];
	delete CONNTRACK["dst"];
	delete CONNTRACK["dport"];


	# conjecture direction
	if ( CONNTRACK["lport"] in blackPORTs || CONNTRACK["rport"] in blackPORTs )
		next;
	    else if ( "tcp" in CONNTRACK ) {
		if (! ( CONNTRACK["lport"] in TCPPORTS )) {
			if (! ( "direction" in CONNTRACK ))
				CONNTRACK["direction"]="outgoing";
			delete CONNTRACK["lport"];
		    } else if ( CONNTRACK["lport"]==CONNTRACK["rport"] ) {
			if (! ( "direction" in CONNTRACK ))
				CONNTRACK["direction"]="bidirectional";
		    } else if ( CONNTRACK["lport"] in TCPPORTS ) {
			if (! ( "direction" in CONNTRACK ))
				CONNTRACK["direction"]="incoming";
			delete CONNTRACK["rport"];
		    } else
			next;
	    } else if ( "udp" in CONNTRACK ) {
		if (! ( CONNTRACK["lport"] in UDPPORTS )) {
			if (! ( "direction" in CONNTRACK ))
				CONNTRACK["direction"]="outgoing";
			delete CONNTRACK["lport"];
		    } else if ( CONNTRACK["lport"]==CONNTRACK["rport"] ) {
			if (! ( "direction" in CONNTRACK ))
				CONNTRACK["direction"]="bidirectional";
		    } else if ( CONNTRACK["lport"] in UDPPORTS ) {
			if (! ( "direction" in CONNTRACK ))
				CONNTRACK["direction"]="incoming";
			delete CONNTRACK["rport"];
		    } else
			next;
	    } else if ( DEBUG != 0 || DEBUG != "" ) {
		for (i in CONNTRACK)
			printf("%s=%s\n",i,CONNTRACK[i])
		printf("\n")
		next;
	    } else
		next;

	if ( "tcp" in CONNTRACK ) {
		if ( CONNTRACK["persistence"]<60 || CONNECTIONS[CONNTRACK["direction"],"tcp",CONNTRACK["local"],CONNTRACK["lport"],CONNTRACK["remote"],CONNTRACK["rport"]] == 0 )
			++CONNECTIONS[CONNTRACK["direction"],"tcp",CONNTRACK["local"],CONNTRACK["lport"],CONNTRACK["remote"],CONNTRACK["rport"]];
	    } else if ( "udp" in CONNTRACK ) {
		if ( CONNTRACK["persistence"]<60 || CONNECTIONS[CONNTRACK["direction"],"udp",CONNTRACK["local"],CONNTRACK["lport"],CONNTRACK["remote"],CONNTRACK["rport"]] == 0 )
			++CONNECTIONS[CONNTRACK["direction"],"udp",CONNTRACK["local"],CONNTRACK["lport"],CONNTRACK["remote"],CONNTRACK["rport"]];
	    } else if ( DEBUG != 0 || DEBUG != "" ) {
		for (i in CONNTRACK)
			printf("%s=%s\n",i,CONNTRACK[i])
		printf("\n")
		next;
	    }
    }

END {
	if ( STATEFILE != "" ) {
		if (! ( EXIT != 0 || EXIT != "" ))
			printf("#%s,%s,%s,%s,%s,%s,%s\n","direction","protocol","localIP","localPort","remoteIP","remotePort","counter") > STATEFILE; 
		for (i in CONNECTIONS)
			if ( CONNECTIONS[i] > 0 )
				printf("%s,%s\n",i,CONNECTIONS[i]) > STATEFILE; 
	    } else {
		if (! ( EXIT != 0 || EXIT != "" ))
			printf("#%s,%s,%s,%s,%s,%s,%s\n","direction","protocol","localIP","localPort","remoteIP","remotePort","counter")
		for (i in CONNECTIONS)
			if ( CONNECTIONS[i] > 0 )
				printf("%s,%s\n",i,CONNECTIONS[i]);
	    }
#	if ( ARGC<2 && NR<1 )
#		print HELP;
    }
