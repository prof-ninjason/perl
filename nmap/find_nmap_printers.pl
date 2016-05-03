#!/usr/bin/perl

 # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
#    Jason C. Rochon                                                                    #
#    Dec 2, 2014                                                                        #
#                                                                                       #
#    Notes:                                                                             #
#                                                                                       #
#        1.) Prints IP's of devices that are printers                                   #
#                                                                                       #
#        2.) Used to prevent Nmap from activating a print job on HP JetDirects          #
#                                                                                       #
 # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

#use strict;
#use warnings;
#use diagnostics;
#use Data::Dumper::Simple;
#use Data::Dump::Streamer;
use Nmap::Parser;

 # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
#    Declare Vars                                                                       #
 # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

my $np     = new Nmap::Parser;
my $infile = $ARGV[0];

#  80 : HTTP port for web printers
# 443 : HTTPS port for web printers
# 515 : LPR/LPD port, for most printers, as well as older print-servers
# 631 : IPP port, for most modern printers, and CUPS-based print-server
# 7627: HTTP config port
# 9100: JetDirect port
my @myPorts = qw( 80 443 515 631 7627 9100 );

 # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Parse File                                                                            #
 # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

$np->parsefile($infile);

 # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Session Data                                                                          #
 # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

for my $host ( $np->all_hosts ) {
    my $type     = $host->os_sig->type;
    my $vendor   = $host->os_sig->vendor;
    my $hostname = $host->hostname;

    if ( $type =~ /printer/ ) {
        print(    $host->ipv4_addr . "\t# "
                . $hostname . " "
                . $vendor . " "
                . $type
                . "\n" )
            if ( defined( $host->ipv4_addr ) );
    }
}

 # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
#   Exit Routine                                                                        #
 # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

exit;
