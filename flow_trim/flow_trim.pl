#!/usr/bin/perl

 # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
#                                                                            #
#    Jason C. Rochon                                                         #
#    Mar 24, 2016                                                            #
#                                                                            #
#    Trims out the flows relevant to the AA complaint cases.                 #
#                                                                            #
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

use Getopt::Std;
getopts('hxyz');    # widen the search on timestamp

if ($opt_h) {
    print "\nflow_trim (options) [netid]
    \n<options>
    \t-x: search for hh:mm
    \t-y: search for hh:mm:s
    \t-z: search for hh:mm:s[-/+1s]
    \n<default>\n\tsearch for hh:mm:ss\n\n";
    exit;
}

 # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
#   Declare Variables                                                        #
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

my ( $datetime, $line, $searchdatetime );

 # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
#   Parse Input                                                              #
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

if ( $ARGV[0] ) {
    $netid = $ARGV[0];
} else {
    print "Enter suspended netid: ";
    chomp( my $netid = <STDIN> );
}

open( my $suslog, '<', '/mnt/global/security/suspend/' . $netid ) or die $!;

print "Enter the timestamp to find: ";
chomp( $datetime = <STDIN> );

my ( $mm, $dd, $hhmm, $s1, $s2 ) =
    ( $datetime =~ /\d{4}\-(\d{2})\-(\d{2}) (\d\d:\d\d:)(\d)(\d)/ );

my $bs = $s2 - 1;
my $fs = $s2 + 1;

( $bs = 0 ) if ( $bs <= 0 );
( $fs = 9 ) if ( $fs >= 9 );

if ($opt_x) {
    $searchdatetime = $mm . $dd . '\.' . $hhmm;
} elsif ($opt_y) {
    $searchdatetime = $mm . $dd . '\.' . $hhmm . $s1;
} elsif ($opt_z) {
    $searchdatetime =
        $mm . $dd . '\.' . $hhmm . $s1 . '[' . $bs . $s2 . $fs . ']';
} else {
        $searchdatetime = $mm . $dd . '\.' . $hhmm . $s1 . $s2;
}

while ( my $line = <$suslog> ) {
    if ( $line =~ /$searchdatetime/ ) {
        print $line;
    }
}