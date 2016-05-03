#!/usr/bin/perl

 # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
#    Jason C. Rochon                                                                    #
#    Dec 2, 2014                                                                        #
#                                                                                       #
#    Notes:                                                                             #
#                                                                                       #
#        1.) Prints IP's of devices that are not related to Microsoft Windows           #
#                                                                                       #
#        2.) Reduces Nmap scan time by excluding these non-Windows IP's                 #
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

 # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Parse File                                                                            #
 # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

$np->parsefile($infile);

 # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Session Data                                                                          #
 # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

for my $host ( $np->all_hosts )
{
  my $os       = $host->os_sig->osfamily;
  my $hostname = $host->hostname;

  if ( $os !~ /Windows|^$/ )
  {
    print( $host->ipv4_addr . "\t# " . $hostname . " " . $os . "\n" )
      if ( defined( $host->ipv4_addr ) );
  }
}

 # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
#   Exit Routine                                                                        #
 # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

exit;
