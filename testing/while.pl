#!/usr/bin/perl

#use strict;
#use warnings;
#use utf8;
use 5.008005;
our $VERSION = 1.1.1;
use Data::Dumper::Simple;

my @flows = "Foo";
push @flows, "Bar";
push @flows, "Baz";

while ( scalar(@out) < 20 ) {

	#while ( scalar(@out) < $#out ) {
	push @out, grep { /a/ } @flows;
}

$string .= join( "\n", @out[ 0 .. 20 ] );
#$string .= join( "\n", @out[ 0 .. $#out ] );

print "\nend = [$#out]";

print "\nstring = [$string]";
__END__

#my @slog = "0310.00:32:51.552\n";
#   push @slog,"0310.00:32:52.552\n";
#   push @slog,"0310.00:32:53.552\n";
#print "LOG [\n @slog]\n";
