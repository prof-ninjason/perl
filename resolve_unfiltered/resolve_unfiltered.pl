#!/usr/bin/perl

 # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
#   Jason C. Rochon                                                                  #
#   May 02, 2016                                                                     #
#                                                                                    #
#   Notes:                                                                           #
#                                                                                    #
#      1.) cron job:                resolve_unfiltered -r                            #
#      2.) log tickets only, do not resolve:    resolve_unfiltered -l                #
#      3.) full report:             resolve_unfiltered -f                            #
#      4.) options r or f , actvates option l because log file is mandatory          #
#                                                                                    #
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

use Socket;
use Net::Nslookup;
use Error qw(:try);
use RT::Client::REST;
use RT::Client::REST::Ticket;
use RT::Client::REST::Exception;
use DBI;
use UIC::Paw;
use Getopt::Std;
our %hash = ();
our %opt  = ();

 # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
#   Usage: Resolves tickets where the devices have been unfiltered, but the ticket   #
#          has not been resolved. Prints a report log to resolve_unfiltered.log      #
#                                                                                    #
#   Options: -h   Help      displays help topic                                      #
#            -f   Full      displays full report of tickets and devices filtered     #
#            -l   Log       log output to file "resolve_unfiltered.log"              #
#            -m   Menu      displays a menu to process after each ticket             #
#            -r   Resolve   resolves tickets automatically                           #
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

getopts( 'hflmr', \%opt );    # values in %opts{hflmr}

if ( $opt{f} || $opt{r} ) {
    $opt{l} = 1;              # write to log file
}

 # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
#   Print Help                                                                       #
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

if ( $opt{h} ) {
    print
        "\n  Usage:\n\tresolve_unfiltered.pl \t reports unresolved tickets for unfiltered devices\n\n"
        . "Options:\n"
        . "\t-h \t Help \t\t displays help topic \n\n"
        . "\t-f \t Full \t\t displays full report of tickets and devices filtered \n\n"
        . "\t-l \t Log  \t\t log output to file \"resolve_unfiltered.log\" \n\n"
        . "\t-m \t Menu \t\t displays a menu to process each ticket \n\n"
        . "\t-r \t Resolve \t resolves tickets automatically \n\n";
    exit;
}

 # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
#   Log File                                                                         #
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

open( STDERR, ">>", "/usr/local/flowtools/resolve_unfiltered/scripts.log" );
open( $logFile, ">",
    "/usr/local/flowtools/resolve_unfiltered/resolve_unfiltered.log" )
    or die $!;

if ( $opt{l} ) {
    select $logFile;
}

 # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
#   Account Credentials                                                              #
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

$user = 'secgrp';
$pass = UIC::Paw::get("$user\@rt");

 # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
#   Connection to RT Tickets                                                         #
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

my $rt = RT::Client::REST->new(
    server  => 'http://accc.helpdesk.uic.edu/',
    timeout => 300,
);

#$rt->login( username => $user, password => $pass );

try { $rt->login( username => $user, password => $pass ); }
catch Exception::Class::Base
    with { die "problem logging in: ", shift->message; };

 # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
#   Database Connection                                                              #
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

our $dbh = DBI->connect( 'dbi:mysql:arp:world.cc.uic.edu',
    "filter", 'd*****e', { AutoCommit => 0 } )
    or die "Couldn't connect to database: " . DBI->errstr;

 # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
#   SQL IP Query                                                                     #
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

our $siq = $dbh->prepare(
    "select ip 
  from arp.ipfilters 
  where ip = ? 
  order by ip"
) or die "Couldn't prepare statement: " . $dbh->errstr;

 # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
#   SQL MAC Query                                                                    #
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

our $smq = $dbh->prepare(
    "select mac 
  from arp.macfilters 
  where mac = ? 
  order by mac"
) or die "Couldn't prepare statement: " . $dbh->errstr;

 # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
#   MAC Unfiltered Tickets Query                                                     #
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

print "\n"
    . " # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #\n"
    . "#                   Machines that are Unfiltered with Unresolved Tickets            #\n"
    . " # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #\n";

our @ids = $rt->search(
    type  => 'ticket',
    query => "Queue = 'filtered'
           AND
           Status != 'resolved' 
           AND 
           Subject LIKE 'mac filtered'",
);

&proc_mac_ids;

 # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
#   Process MAC IDs                                                                  #
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

sub proc_mac_ids {
    for our $id (@ids) {
        my ( $ip, $mac );
        our $ticket = $rt->show( type => 'ticket', id => $id );
        our $resolve_ticket =
            RT::Client::REST::Ticket->new( rt => $rt, id => $id )->retrieve;

      # # # Trying to match one of two patterns and store into variables # # #
        if ( $ticket->{Subject}
            =~ /(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/
            )
        {
            $ip = "$&";
        }

        if ( $ticket->{Subject}
            =~ /(([0-9A-Fa-f]{2}[-:]){5}[0-9A-Fa-f]{2})|(([0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4})/
            )
        {
            $mac = "$&";
            $hash{$mac} = $id;
        }

        if ($mac) {
            &macfilter_query( $mac, $ip );
        } else {
            &ipfilter_query($ip);
        }
    }
}

 # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
#   Query arp.macfilter                                                              #
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

sub macfilter_query {
    my $mac = shift;
    my $ip  = shift;

    $smq->execute($mac)
        or die "Couldn't execute statement: " . $smq->errstr;

    if ( $smq->rows == 0 ) {
        &print_subjects;
        &print_nslookup($ip);
        &menu_resolve;
    }
    $smq->finish;
}

 # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
#   IP Unfiltered Tickets Query                                                      #
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

@ids = $rt->search(
    type  => 'ticket',
    query => "Queue = 'filtered' 
           AND 
           Status != 'resolved'
           AND 
           (Subject LIKE 'now filtered'
            OR
            Subject LIKE '( ) is now Mac filtered')",
);

&proc_ip_ids;

 # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
#   Process IP IDs                                                                   #
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

sub proc_ip_ids {
    for our $id (@ids) {
        my ( $ip, $mac );
        our $ticket = $rt->show( type => 'ticket', id => $id );
        our $resolve_ticket =
            RT::Client::REST::Ticket->new( rt => $rt, id => $id )->retrieve;

        if ( $ticket->{Subject}
            =~ /(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/
            )
        {
            $ip = "$&";
        }

        if ( $ticket->{Subject}
            =~ /(([0-9A-Fa-f]{2}[-:]){5}[0-9A-Fa-f]{2})|(([0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4})/
            )
        {
            $mac = "$&";
        }

        &ipfilter_query($ip) unless ($mac);

    }
}

 # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
#   Query arp.filter                                                                 #
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

sub ipfilter_query {
    my $ip = shift;

    $siq->execute($ip)    # Execute the query
        or die "Couldn't execute statement: " . $siq->errstr;

    if ( $siq->rows == 0 ) {
        &print_subjects;
        &print_nslookup($ip);
        &menu_resolve;
    }

    $siq->finish();
}

 # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
#   Print RT Subject                                                                 #
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

sub print_subjects {
    print
        "\n- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -\n";

    unless ( $opt{l} ) {
        print STDOUT "\n\t          RT: \t $id "
            . "\n\t     Subject: \t $ticket->{Subject} "
            . "\n\t     Created: \t $ticket->{Created} "
            . "\n\t      Status: \t $ticket->{Status} ";
    } else {
        print "\nRT $id - $ticket->{Subject} - $ticket->{Created}";
    }
}

 # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
#   NSLookup for hostname                                                            #
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

sub print_nslookup {
    my $ip = shift;

    #	unless ( my $hostname = gethostbyaddr( inet_aton("$ip"), AF_INET ) ) {
    unless ( my $hostname = nslookup( host => $ip, type => "PTR" ) ) {
        print "\nHostname:   Is not registered";
    } else {
        print "\nHostname:   $hostname";
    }
}

 # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
#   MENU                                                                             #
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

sub menu_resolve {
    if ( $opt{r} ) {
        $resolve_ticket->status("resolved");
        $resolve_ticket->store();
        print "\nRT $id has been updated and resolved\n";
    }

    if ( $opt{m} ) {
        select STDOUT;
        print "\n\n\nWould you like to Resolve this Ticket?\n\n"
            . "R . . . . . . . . . . Resolve Ticket\n"
            . "S . . . . . . . . . . Skip this Ticket\n"
            . "X . . . . . . . . . . Exit Program\n";

        # process input from user, chop spaces,
        # and convert to lower case
        $ans = <STDIN>;
        chop($ans);
        $ans = lc $ans;

        while ( $ans eq "" && $ans ne "r" && $ans ne "s" && $ans ne "x" ) {
            print "Invalid answer or blank line\n";
            $ans = <STDIN>;
            chop($ans);
        }

        if ( $ans eq "r" ) {
            $resolve_ticket->status("resolved");
            $resolve_ticket->store();

            if ( $opt{l} ) { select $logFile }

            print "\nRT $id has been updated and resolved\n"
                . "\n- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -\n";
        }

        if ( $ans eq "x" ) {
            print
                "\n\n> > > > > > > > > > > > > > > > > > > > > > > End of Tickets < < < < < < < < < < < < < < < < < < < < < < <\n\n";
            close($logFile);
            close(STDERR);
            exit;
        }
    }
}

 # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
#   Print Filtered Macs                                                              #
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

if ( $opt{f} ) {
    my $stha = $dbh->prepare(
        "select distinct mac 
                          from arp.macfilters 
                          order by mac"
    ) or die "Couldn't prepare statement: " . $dbh->errstr;

    $stha->execute();

    my $sthb = $dbh->prepare(
        "select distinct mac, comment 
                          from arp.filter
                          where mac = ? 
                          order by mac"
    ) or die "Couldn't prepare statement: " . $dbh->errstr;

    $macDbArray = $stha->fetchall_arrayref();

    print "\n"
        . " # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #\n"
        . "#                   MACs that are Filtered with\/without Tickets                     #\n"
        . " # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #\n";

    foreach (@$macDbArray) {
        my ($macDb) = @$_;

        if ( grep $macDb, keys %hash ) {
            if ( !defined( $hash{$macDb} ) ) {
                push( @nullArrTicks, $macDb );
                print "\nRT Ticket: NULL";
            } else {
                push( @ArryTicks, $macDb );
                print "\nRT Ticket: $hash{$macDb}";
            }
            $sthb->execute($macDb);

            my $ret = $sthb->fetch();

            foreach my $row (@$ret) {
                print "\n$row";
            }
        }

        $sthb->finish();
        print
            "\n- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -\n";
    }

    print "\n\n        MACs filtered without tickets: "
        . scalar(@nullArrTicks)
        . "\nMACs filtered with unresolved tickets: "
        . scalar(@ArryTicks) . "\n";

    $stha->finish();
    $dbh->disconnect;

    select STDOUT;
} else {
    $dbh->disconnect;
}

print
    "\n\n> > > > > > > > > > > > > > > > > > > > > > > End of Tickets < < < < < < < < < < < < < < < < < < < < < < <\n\n";

close($logFile) if ( $opt{l} );
close(STDERR);
