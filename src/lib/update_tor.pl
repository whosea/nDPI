#!/usr/bin/env perl
#
#

open(F,"wget -q -4 -Y off -O - https://torstatus.rueckgr.at/ip_list_all.php/Tor_ip_list_ALL.csv|") || die "wget";

my @IP;
while(<F>) {
	if(!/^([0-9]+\.){3}([0-9]+)$/) {
		print STDERR "BAD $_";
		next;
	}
	chomp;
	push @IP,$_;
}
close(F);
print "TOR:
	source:
	  - Tor
	  - https://torstatus.rueckgr.at/ip_list_all.php/Tor_ip_list_ALL.csv
	  - From 09.09.2019
	  -
	  - https://panwdbl.appspot.com/lists/ettor.txt
	  -
	  - Use utils/toripaddr2list.py to convert them
	ip:
	  - ",join("/32\n	  - ",@IP),"/32\n";
