#!/usr/bin/perl

use lib '/usr/local/flowtools/lib';
use asa_cur;

#use asa;
use findNetid;
use Encode 'decode_utf8';
use DBI;
use Date::Calc qw(:all);
use UIC::Paw;
use Socket;
use Error qw(:try);
use RT::Client::REST;
use RT::Client::REST::Ticket;
use Getopt::Std;
use Mail::Mailer;
use DateTime;
use Data::Dumper;
use File::Copy;

getopts('fdtno:');

if   ($opt_o) { $minoffset = $opt_o; }
else          { $minoffset = 0; }

$a = `/bin/ls -ld ~`;
($uname) = ( $a =~ (/.*\/(.*)$/) );

#
# Options:
#   -n : search using text...i.e. do Not try XML
#   -d : debug
#   -t : "flip" daylight savings time. Useful when time changes to process reports from previous daylight savings time setting
#   -o : offset (in minutes) to apply to timestamp to correct for arp data problems
#   -f : do not check flow logs...useful when debugging
#
# Create some vars
#
$num_flows_to_print = 5;
my $macnetid_table    = "wireless.macmap";
my $vpn_table         = "nocsec.vpn_session";
my $world_priv_table  = "arp.fw_arp";
my $current_arp_table = "arp.current_mac_ip";
my $world_table       = "arp.router_arp";
my $arp_table         = "wireless.arppoe";
my $guest_table       = "wireless.gauth";
my $resnet_table      = "resnet.fwinfo";
my $unlim_table       = "wireless.unlim_bandwidth";
$suspend_dir    = "/homes/homefarm/edzsu/testoutput/suspend/";
$suspend_dir    = "/mnt/global/security/suspend/";
$autofilter_dir = "/homes/homefarm/edzsu/testoutput/uic/";
$autofilter_dir = "/mnt/global/flowlogs/uic/";
$logfile        = "/mnt/global/flowlogs/dmca_suspend.log";
$cnt            = 0;
$id             = $ARGV[0];
$INTERVAL_MIN = 10;                # +/- interval in MINutes for flow analysis
$INTERVAL_NEG = 0 - $INTERVAL_MIN;
my $datetime;
my %passed_quiz;
my $unix_datetime;
my $semester;
my ( $ip, $ipaddress );
#
# PAT address variables
#
my @pat =
    qw( 128.248.182.254 128.248.249.254 128.248.98.254 131.193.17.93 131.193.253.254 131.193.254.254 131.193.255.254 131.193.251.254 );
our $pat = join( ' ', @pat );

#
# Helpdesk account credentials
#
$user = 'secgrp';
$pass = UIC::Paw::get("$user\@rt");

#
# Look for a ~/.dmcasig file to sign the request. This shows who processed the
# RT ticket for reference purposes. If this file does not exist, prompt for the
# info
#
load_sig_file();

#
# Use RT::Client::REST library to get ticket info and search through the "attachments" to the ticket
# for required info
#
# NOTE that the ticket structure varies depending on how the mail was sent, so we use a kludge to
# look for the main complaint (i.e. we look for the word "Dear". This may need to be changed if it
# fails too frequently
#
my $rt = RT::Client::REST->new(
    server  => 'http://accc.helpdesk.uic.edu/',
    timeout => 30,
);

$rt->login( username => $user, password => $pass );

my $ticket = RT::Client::REST::Ticket->new( rt => $rt, id => $id )->retrieve;

### check if ticket has been resolved
$status = $ticket->status;
if ( $status eq 'resolved' ) {
    print "\nWARN: this ticket is currently resolved\n";
}

$subject = $ticket->subject;

if ( !$opt_n ) { getRTInfoUsingXML(); }
else {
    getRTInfoUsingText();
}

#
# Re-assign some vars as I included some pre-existing code (i.e. previous 'dmca' command that didn't
# look up RT ticket info.
#
$datetime = $timestamp;
$ip       = $ipaddress;
if ( !$ip || !$datetime ) {
    print
        "Unable to retrieve info using XML tags -- re-scanning in text mode\n";
    getRTInfoUsingText();
    $datetime = $timestamp;
    $ip       = $ipaddress;
}

#
# Normalize the date/time data as we receive it in several different formats
# This also adjusts for time zone shifts
#
$datetime = fix_date_time($datetime);

#$datetime2 = offsetdatetime($datetime);

#
# Now that we have the correct date/time and IP and port, check the flows for corroborating data
#
# Note that if this comes up empty, it doesn't mean that the ticket is invalid. The search probably
# needs to be widened manually. Doing it here would cause the command to take a long time and we
# don't want that.
#
if ( $TIMESTAMP && $IPADDRESS && $PORT && !$opt_f ) {
    check_flows_for_port( $ip, $datetime, $port );
} elsif ($opt_f) {
    print "Skipping flow log check\n\n";
} elsif ( !$PORT ) {
    $flow_out =
        "\nPort information not found in ticket: not checking flow logs\n";
    print $flow_out;
}

print
    "\n\n\n\n\n.................................................................................................\n\n";
print "Timestamp from ticket is: $timestamp\n";
$hname = gethostbyaddr( inet_aton($ip), AF_INET );
if ( $hname eq "" )    { $hname   = "unregistered"; }
if ( $hname =~ /vpn/ ) { $VPNHOST = 1; }

$searching_string =
    "\n*** Searching for $hname( $ip ) on date/time $datetime ***\n";
print $searching_string;

#
# Set up sql connections to world and rtsql so that we can check for auth data
#
$dbh = DBI->connect(
    'dbi:mysql:wireless:mysql-security1-master-1.data.cc.uic.edu',
    "db_wireless",
    UIC::Paw::get('db_wireless@mysql-security1-master-1.priv'),
    { AutoCommit => 0 }
);
unless ($dbh) {
    logit( "LOG",
        "connection to db_wireless\@mysql-security1-master-1.priv.data.cc.uic.edu failed"
    );
    exit;
}
$world = DBI->connect( 'dbi:mysql:arp:world.cc.uic.edu',
    "filter", 'darlene', { AutoCommit => 0 } );
unless ($world) {
    logit( "LOG", "connection to world failed" );
    exit;
}
$res = DBI->connect(
    'dbi:mysql:resnet:mysql-security1-master-1.data.cc.uic.edu',
    "db_resnet",
    UIC::Paw::get('db_resnet@mysql-security1-master-1.priv'),
    { AutoCommit => 0 }
);
unless ($world) {
    logit( "LOG", "connection to resnet db failed" );
    exit;
}

print "\n";
prepare_sql();

### ASA Lookup
$get_asa_data =
    "***********************\nFrom ASA data:\n***********************\n\n";
my $asa = proc_ip_yan( $ip, $datetime );
if ( $asa->{'warn'} ) {
    $get_asa_data .= "$asa->{'warn'}\n\n";
} else {
    $get_asa_data .= "$asa->{'pre'}\n$asa->{'nail'}\n$asa->{'post'}\n\n";

# NAIL - 2014-06-29 22:24:01 - 2014-06-29 23:54:01 - 131.193.237.53 - 10.44.216.140 - 6817.29db.f0fb - 0
    if ( $asa->{'nail'} ) {
        @asa_nail = split( " - ", $asa->{'nail'} );
        $mac = $asa_nail[5];
        $get_asa_data .= "likely $mac\n\n";
    }
}
print $get_asa_data;

print "***********************\n";
print "From $vpn_table:\n";
print "***********************\n\n";
$get_vpn_table_info_results =
    "***********************\nFrom $vpn_table:\n***********************\n\n";
if ( !in_vpn_table($ip) ) {
    print "\t$ip is not in $vpn_table...\n\n";
    $get_vpn_table_info_results .= "\t$ip is not in $vpn_table...\n\n";
} else {
    $IN_VPN_TABLE = 1;
    get_vpn_table_info( $ip, $datetime2 );
}

print "***********************\n";
print "From $world_priv_table:\n";
print "***********************\n\n";
$get_fw_table_info_results =
    "***********************\nFrom $world_priv_table:\n***********************\n\n";
if ( !in_fw_table() ) {
    print "\t$ip is not in $world_priv_table...\n\n";
    $get_fw_table_info_results .= "\t$ip is not in $world_priv_table...\n\n";
} else {
    $IN_FW_TABLE = 1;
    get_fw_table_info();
}

print "***********************\n";
print "From $world_table:\n";
print "***********************\n\n";
$get_router_table_info_results =
    "***********************\nFrom $world_table:\n***********************\n\n";
if ( !in_router_table() ) {
    print "\t$ip is not in $world_table...\n\n";
    $get_router_table_info_results .= "\t$ip is not in $world_table...\n\n";
} else {
    $IN_ROUTER_TABLE = 1;
    get_router_table_info();
}

print "***************************\n";
print "Wireless macmap table:\n";
print "***************************\n\n";
$get_macmap_info_results =
    "***************************\nWireless macmap table:\n***************************\n\n";
if ( !in_macmap() ) {
    print "\t$ip is not in $world_table...\n\n";
    $get_macmap_info_results .= "\t$ip is not in $world_table...\n\n";
} else {
    $IN_MACMAP = 1;
    get_macmap_info();
}

# in case asa does not have mac, arppoe should be used independently
#if ($INMACMAP) {
print "**********************\n";
print "Wireless arppoe table:\n";
print "**********************\n\n";
$get_wireless_info_results =
    "**********************\nWireless arppoe table:\n**********************\n\n";
get_wireless_info();

#}

print "***************************\n";
print "Guest WIFI table:\n";
print "***************************\n\n";
$get_guest_info_results =
    "***************************\nGuest table:\n***************************\n\n";

#if (!in_resnet()) {
#	print "$ip is not in $resnet_table ...\n\n";
#	$get_resnet_info_results .= "$ip is not in $resnet_table ...\n\n";
#	}
#else {
get_guest_info();

#	}

print "***************************\n";
print "Resnet fwinfo table:\n";
print "***************************\n\n";
$get_resnet_info_results =
    "***************************\nResnet fwinfo table:\n***************************\n\n";
if ( !in_resnet() ) {
    print "$ip is not in $resnet_table ...\n\n";
    $get_resnet_info_results .= "$ip is not in $resnet_table ...\n\n";
} else {
    get_resnet_info();
}

#
# Cycle through list of possible_netids and look to see if they already have sus files
#

foreach $a ( keys %possible_netids ) {
    if ( $a eq "" ) { delete $possible_netids{$a}; next; }
    $listofnetids .= lc($a) . "(" . $mac_for_netid{$a} . ") ";
    $listcnt++;
}

print "\n*************************\n";
print "Unlimited bandwidth table\n";
print "*************************\n\n";

$bw_info_out =
      "\n*************************\n"
    . "Unlimited bandwidth table\n"
    . "*************************\n\n";

printf "\n";
printf "%15s %22s %22s %22s %15s\n", 'Netid', 'DMCA Suspend Date',
    'Last DMCA Date', 'Quiz Passed Date', 'Lifetime';
$output = sprintf(
    "%15s %22s %22s %22s %15s\n",
    'Netid',
    'DMCA Suspend Date',
    'Last DMCA Date',
    'Quiz Passed Date',
    'Lifetime'
);
$bw_info_out .= $output;
printf "%15s %22s %22s %22s %15s\n", '---------------',
    '----------------------', '---------------------',
    '---------------------',
    '--------------';
$output = sprintf(
    "%15s %22s %22s %22s %15s\n",
    '---------------',       '----------------------',
    '---------------------', '---------------------',
    '--------------'
);
$bw_info_out .= $output;

foreach $a ( keys %possible_netids ) {
    lc $a;
    if ( $a eq "" ) { next; }
    get_bw_info( $a, 1 );
}

$bw_info_out .= "\n\n";

print "\n\n******************************************************\n";
print "Checking suspend files for all possible netids ...\n";
print "******************************************************\n\n";
foreach $a ( keys %possible_netids ) {
    lc $a;
    if ( $a eq "" ) { next; }
    $testfn = $suspend_dir . $a;
    if ( !-e $testfn ) {
        print "$testfn does not exist\n";
    } else {
        $ooutput = `/bin/ls -l $testfn`;
        $possible_netids{$a} = 'e';
        chop($ooutput);
        print "$ooutput\n";
    }
}

#
# Check unlimited bandwidth table here and print out results
#

print
    ".................................................................................................\n";
print "\n\n";
$SOMEDONOTEXIST = $SOMEEXIST = $ALLEXIST = 0;

print "It looks like the list of possible netids is: $listofnetids\n\n";

foreach $a ( keys %possible_netids ) {
    if   ( $possible_netids{$a} eq "e" ) { $SOMEEXIST      = 1; }
    else                                 { $SOMEDONOTEXIST = 1; }
}

if ( $SOMEEXIST && ( !$SOMEDONOTEXIST ) ) { $ALLEXIST = 1; }

if ($ALLEXIST) {
    print
        "ALL of these netid(s) already have suspend files -- most likely repeat offender(s)!\n\n";
} elsif ($SOMEEXIST) {
    print
        "SOME of these netids already have suspend files -- most likely repeat offender(s)!\n\n";
} else {
    print "NONE of these netids already have suspend files\n\n";
}

&disconnect_dbs;

### check if ticket has been resolved
my $c2ticket =
    RT::Client::REST::Ticket->new( rt => $rt, id => $id )->retrieve;
$status = $c2ticket->status;
if ( $status eq 'resolved' ) {
    print "\nWARN: this ticket is currently resolved!\n";
}

print "What would you like to do for RT $id?\n\n";
print
    "a .................... accept -  i.e. info is correct (create netid in suspend dir and autofilter record)\n";
print "x .................... nothing (exit)\n";
print
    "filename  ............ Type any filename to create the output in that filename in the suspend dir\n";
print
    "netid 'tag_netid' .... A list of netids is displayed, but only tag 'tag_netid', and enter 'tag_netid:mac' for different mac\n";
print
    "append 'netid' ....... Use this option to add a dmca complaint to an existing file for someone that is still filtered\n";
print
    "mac 'mac address' .... Create file in suspend dir named 'mac address' and create a manual filter event for the machine\n\n";

$ans = <STDIN>;
chop($ans);
while ( $ans eq "" ) {
    print "Invalid answer (blank line)\n";
    $ans = <STDIN>;
    chop($ans);
}

### check if ticket has been resolved
my $c3ticket =
    RT::Client::REST::Ticket->new( rt => $rt, id => $id )->retrieve;
$status = $c3ticket->status;
if ( $status eq 'resolved' ) {
    print
        "\nWARN: this ticket is currently resolved!\nHit enter to continue or Control-c to quit.";
    my $continue = <STDIN>;
}

$ans = lc $ans;
if ( $ans eq "x" ) {
    exit;
}

if ( $ans eq "a" ) {
    my $output;
    foreach $a ( keys %possible_netids ) {
        $lfn = $suspend_dir . $a;
        if ( -e $lfn ) {
            $output .= prepend_suspend_file( $a, 1 );
            sendEmail($a);
        } else {
            $output .= create_suspend_file( $a, $a, 0 );
        }
        update_bw_info($a);
    }
#
# Since we have chosen to automatically suspend this person, the info is accurate and we will
# add a comment to the ticket
#
    $ticket->comment( message => $output );
    $ticket->status("resolved");
    $ticket->store();
    print "\nTicket # $id has been updated and resolved\n";
    exit;
}

if ( $ans =~ /^netid / ) {
    my $output;
    ($tagged_netid) = ( $ans =~ (/^netid\s+(.*)$/) );
    if ( $tagged_netid =~ /:/ ) {
        ( $tagged_netid, $mac ) = ( $ans =~ (/netid\s+(.*)\:(.*)$/) );
        if ( $mac eq "" ) { $mac = "ukno.wnad.dres"; }
        $mac_for_netid{$tagged_netid} = $mac;
    }
    update_bw_info($tagged_netid);
    $lfn = $suspend_dir . $tagged_netid;
    if ( -e $lfn ) {
        $output = prepend_suspend_file( $tagged_netid, 1 );
        sendEmail($tagged_netid);
    } else {
        $output = create_suspend_file( $tagged_netid, $tagged_netid, 0 );
    }

#update_bw_info($tagged_netid);
#
# Since we have chosen to automatically suspend this person, the info is accurate and we will
# add a comment to the ticket
#
    $ticket->comment( message => $output );
    $ticket->status("resolved");
    $ticket->store();
    print "\nTicket # $id has been updated and resolved\n";
    exit;
}

if ( $ans =~ /^append / ) {
    ($tagged_netid) = ( $ans =~ (/^append\s+(.*)$/) );
    if ( $tagged_netid =~ /:/ ) {
        ( $tagged_netid, $mac ) = ( $ans =~ (/netid\s+(.*)\:(.*)$/) );
        if ( $mac eq "" ) { $mac = "ukno.wnad.dres"; }
        $mac_for_netid{$tagged_netid} = $mac;
    }
    $lfn = $suspend_dir . $tagged_netid;
    if ( -e $lfn ) {
        append_suspend_file( $tagged_netid, 0 );
    } else {
        die "append specified, but file $lfn does not exist!";
    }
#
# Since we have chosen to automatically suspend this person, the info is accurate and we will
# add a comment to the ticket
#
    $ticket->comment( message => $output );
    $ticket->status("resolved");
    $ticket->store();
    print "\nTicket # $id has been updated and resolved\n";
    exit;
}

if ( $ans =~ /^mac / ) {
    $MAC = 1;
    ($tagged) = ( $ans =~ (/^mac\s+(.*)$/) );
    my $output;

    ### look up netid from entered mac
    my $netid = find_netid( $tstamp, $ip, $tagged );
    $find_netid_results = "$netid last used $tagged\n\n";
    print $find_netid_results;
    if ( $netid ne 'Unknown' ) {
        $mac                   = $tagged;
        $tagged                = $netid;
        $mac_for_netid{$netid} = $mac;
        get_bw_info( $netid, 1 );
        $MAC = 0;
    }

    if ( -e $lfn ) {
        $output = prepend_suspend_file( $tagged, 1 );
        sendEmail($tagged);
    } else {
        $output = create_suspend_file( $tagged, $tagged, 0 );
    }

#
# Since we have chosen to automatically suspend this person, the info is accurate and we will
# add a comment to the ticket
#
    $ticket->comment( message => $output );
    $ticket->status("resolved");
    $ticket->store();
    print "\nTicket # $id has been updated and resolved\n";
    exit;

}

############## LEFT OFF HERE
#
# If we get here, then a new filename was entered
#
# create a list of possible netids to insert into the output file
#
$FILENAME = 1;
foreach $a ( keys %possible_netids ) { $poss_netids .= lc($a) . " "; }
my $output = create_suspend_file( $poss_netids, $ans, 0 );

#
# Since we have chosen to automatically suspend this person, the info is accurate and we will
# add a comment to the ticket
#
$ticket->comment( message => $output );
$ticket->status("resolved");
$ticket->store();
print "\nTicket # $id has been updated and resolved\n";

exit;

sub in_vpn_table {

    my ($ip) = @_;

    $in_vpn->bind_param( 1, $ip );
    $in_vpn->execute();
    @row = $in_vpn->fetchrow_array();
    $in_vpn->finish;
    if   ( $row[0] == 0 ) { $result = 0; }
    else                  { $result = 1; }
    return $result;
}

sub in_fw_table {

    $fw_ip->bind_param( 1, $ip );
    $fw_ip->execute();
    @row = $fw_ip->fetchrow_array();
    $fw_ip->finish;
    if   ( $row[0] == 0 ) { $result = 0; }
    else                  { $result = 1; }
    return $result;
}

sub in_router_table {

    $router_ip->bind_param( 1, $ip );
    $router_ip->execute();
    @row = $router_ip->fetchrow_array();
    $router_ip->finish;
    if   ( $row[0] == 0 ) { $result = 0; }
    else                  { $result = 1; }
    return $result;
}

sub get_router_table_info {

    print "$ip found in $world_table:\n";
    $get_router_table_info_results .= "$ip found in $world_table:\n";
    $router_before->bind_param( 1, $ip );
    $router_before->bind_param( 2, $datetime );
    $router_before->execute();
    @row = $router_before->fetchrow_array();
    $router_before->finish;
    $mac = $row[1];
    print "before: @row\n";
    $get_router_table_info_results .= "before: @row\n";

    $router_after->bind_param( 1, $ip );
    $router_after->bind_param( 2, $datetime );
    $router_after->execute();
    @row = $router_after->fetchrow_array();
    $router_after->finish;
    $mac2 = $row[1];
    print "after : @row\n";
    $get_router_table_info_results .= "after : @row\n";
    if ( $mac ne $mac2 ) {
        print
            "Data oddity detected before and after mac addresses do not match! $mac != $mac2  !!\n";
    }
}

sub get_fw_table_info {

    $fw_before->bind_param( 1, $ip );
    $fw_before->bind_param( 2, $datetime );
    $fw_before->execute();
    @row = $fw_before->fetchrow_array();
    $fw_before->finish;
    $mac    = $row[1];
    $row[4] = lc $row[4];
    $netid  = $row[4];
    print "before: @row\n";
    $get_fw_table_info_results .= "before: @row\n";

    $fw_after->bind_param( 1, $ip );
    $fw_after->bind_param( 2, $datetime );
    $fw_after->bind_param( 3, $mac );
    $fw_after->execute();
    @row = $fw_after->fetchrow_array();
    $fw_after->finish;
    $mac2 = $row[1];
    $row[4] = lc $row[4];
    if ( $row[4] ne "n/a" ) {

        #		print "Setting possible_netids for *$row[4]*\n";
        $possible_netids{ lc( $row[4] ) } = 1;
    }
    print "after : @row\n\n";
    $get_fw_table_info_results .= "after : @row\n\n";

    if ( $mac ne $mac2 ) {
        print
            "Data oddity detected before and after mac addresses do not match! $mac != $mac2  !!\n";
        $fw_list->execute( $ip, $datetime, $ip, $datetime );
        while ( my @r = $fw_list->fetchrow_array() ) {
            print "@r\n";
        }
    } else {
        $mac_for_netid{ $row[4] } = $mac;

        #		print "In get_fw_table: Setting mac_for_netid{$netid} = $mac\n";
    }

}

sub in_macmap {

    $mac_map_cnt->bind_param( 1, $mac );
    $mac_map_cnt->execute();
    @row = $mac_map_cnt->fetchrow_array();
    $mac_map_cnt->finish;
    if   ( $row[0] == 0 ) { $result = 0; }
    else                  { $result = 1; }

    $INMACMAP = $result;
    return $result;
}

sub in_resnet {
    $resnet_exists->bind_param( 1, $mac );
    $resnet_exists->execute();
    @row = $resnet_exists->fetchrow_array();
    $resnet_exists->finish;
    if   ( $row[0] == 0 ) { $result = 0; }
    else                  { $result = 1; }
    return $result;
}

sub get_vpn_table_info {

    my ( $ip, $tstamp ) = @_;

    $vpn_info->bind_param( 1, $ip );
    $vpn_info->bind_param( 2, $tstamp );
    $vpn_info->bind_param( 3, $tstamp );

    print "$ip, ts = $tstamp\n";

    $vpn_info->execute();

    my @row = $vpn_info->fetchrow_array();

    printf "%8s %18s %18s %20s %20s\n", 'Netid', 'Remote IP', 'VPN IP',
        'Start Time', 'End Time';
    $get_vpn_table_info_results = sprintf( "%8s %18s %18s %20s %20s\n",
        'Netid', 'Remote IP', 'VPN IP', 'Start Time', 'End Time' );
    printf "%8s %18s %18s %20s %20s\n", '--------', '---------------',
        '---------------', '-------------------', '-------------------';
    $get_vpn_table_info_results = sprintf(
        "%8s %18s %18s %20s %20s\n",
        '--------',            '---------------', '---------------',
        '-------------------', '-------------------'
    );
    printf "%8s %18s %18s %20s %20s\n", $row[0], $row[1], $row[2], $row[3],
        $row[4];
    $get_vpn_table_info_results = sprintf( "%8s %18s %18s %20s %20s\n\n\n",
        $row[0], $row[1], $row[2], $row[3], $row[4] );

    if ( $row[0] ne "" ) {
        $possible_netids{ lc( $row[0] ) } = 1;
        $mac_for_netid{ $row[0] } = "Unkn.ownA.ddrs";
    }

    $vpn_info->finish();

    print "\n\n";
}

sub get_macmap_info {

    $mac_map_info->bind_param( 1, $mac );
    $mac_map_info->execute();
    @row = $mac_map_info->fetchrow_array();

    printf "%19s %14s %8s %15s %-60s\n", 'Timestamp', 'MAC Address', 'Netid',
        'Access Point', 'Hostinfo';
    $output = sprintf( "%19s %14s %8s %15s %-60s\n",
        'Timestamp', 'MAC Address', 'Netid', 'Access Point', 'Hostinfo' );
    $get_macmap_info_results .= $output;
    printf "%19s %14s %8s %15s %-60s\n", '-------------------',
        '--------------', '--------', '---------------', '------------';
    $output = sprintf(
        "%19s %14s %8s %15s %-60s\n",
        '-------------------', '--------------', '--------',
        '---------------',     '------------'
    );
    $get_macmap_info_results .= $output;

    while (@row) {
        printf "%19s %14s %8s %15s %-60s\n", $row[0], $row[1], $row[2],
            $row[3], $row[6];
        $output = sprintf( "%19s %14s %8s %15s %-60s\n",
            $row[0], $row[1], $row[2], $row[3], $row[6] );
        $get_macmap_info_results .= $output;
###?		if ($netid eq "") {
        #			print "Setting possible_netids for *$row[2]*\n";
        $possible_netids{ lc( $row[2] ) } = 1;
        $mac_for_netid{ $row[2] } = $row[1];

  #			print "In get_macmap_info: Setting: mac_for_netid{$row[2]} = $row[1]\n";
###?			}
        @row = $mac_map_info->fetchrow_array();
    }
    $mac_map_info->finish;
    print "\n";
    $get_macmap_info_results .= "\n";
}

sub get_resnet_info {

    $resnet_info->bind_param( 1, $mac );
    $resnet_info->bind_param( 2, $datetime );
    $resnet_info->bind_param( 3, $datetime );
    $resnet_info->execute();
    @row = $resnet_info->fetchrow_array();
    $resnet_info->finish;
    printf "%19s %19s %15s %14s %8s %15s %12s %19s\n", 'Auth Time   ',
        'Stop Time    ', 'IP address   ', 'MAC address  ', 'Netid ',
        'Local IP   ', 'Dorm   ', 'H-Info';
    $output = sprintf(
        "%19s %19s %15s %14s %8s %15s %12s %19s\n",
        'Auth Time   ',
        'Stop Time    ',
        'IP address   ',
        'MAC address  ',
        'Netid ',
        'Local IP   ',
        'Dorm   ',
        'H-Info'
    );
    $get_resnet_info_results .= $output;
    printf "%19s %19s %15s %14s %8s %15s %12s %19s\n", '-------------------',
        '-------------------', '---------------', '--------------',
        '--------',
        '---------------', '------------', '-------------------';
    $output = sprintf(
        "%19s %19s %15s %14s %8s %15s %12s %19s\n",
        '-------------------', '-------------------', '---------------',
        '--------------',      '--------',            '---------------',
        '------------',        '-------------------'
    );
    $get_resnet_info_results .= $output;
    printf "%19s %19s %15s %14s %8s %15s %12s %19s\n", $row[0], $row[1],
        $row[6], $row[7], $row[2], $row[5], $row[4], $row[8];
    $output = sprintf(
        "%19s %19s %15s %14s %8s %15s %12s %19s\n",
        $row[0], $row[1], $row[6], $row[7],
        $row[2], $row[5], $row[4], $row[8]
    );
    $get_resnet_info_results .= $output;

    if ( $row[2] ne "" ) {
        print "likely netid = *$row[2]/$row[7]*\n";
        $mac_for_netid{ $row[2] } = $row[7];
###		$likely_netid = $row[2];
    } else {
        return;
    }

    #	print "In get_resnet_info: Setting possible_netids for *$row[2]*\n";
    $possible_netids{ lc( $row[2] ) } = 1;
}

sub get_wireless_info {

    $wireless_info->bind_param( 1, $ip );
    $wireless_info->bind_param( 2, $datetime );
    $wireless_info->bind_param( 3, $datetime );
    $wireless_info->execute();
    @row = $wireless_info->fetchrow_array();
    $wireless_info->finish;

    printf "%19s %14s %14s %8s %15s %19s %19s\n", 'arptime', 'IP address',
        'MAC address', 'netid', 'AP', 'authtime', 'stoptime';
    $output = sprintf(
        "%19s %14s %14s %8s %15s %19s %19s\n",
        'arptime', 'IP address', 'MAC address', 'netid',
        'AP',      'authtime',   'stoptime'
    );
    $get_wireless_info_results .= $output;
    printf "%19s %14s %14s %8s %15s %19s %19s\n", '-------------------',
        '--------------', '--------------', '--------', '---------------',
        '-------------------', '-------------------';
    $output = sprintf(
        "%19s %14s %14s %8s %15s %19s %19s\n",
        '-------------------', '--------------',  '--------------',
        '--------',            '---------------', '-------------------',
        '-------------------'
    );
    $get_wireless_info_results .= $output;

    if ( $row[0] ne "" ) {
        printf "%19s %14s %14s %8s %15s %19s %19s\n\n", $row[2], $row[3],
            $row[4], $row[5], $row[6], $row[7], $row[8], $row[9];
        $output = sprintf(
            "%19s %14s %14s %8s %15s %19s %19s\n\n",
            $row[2], $row[3], $row[4], $row[5],
            $row[6], $row[7], $row[8], $row[9]
        );
        $get_wireless_info_results .= $output;

      #		print "In get_wireless_info: Setting possible_netids for *$row[5]\n";
        $possible_netids{ $row[5] } = 1;

        #		print "Setting possible_netids{lc($row[5])} = 1\n";
        $mac_for_netid{ $row[5] } = $row[4];

  #		print "In get_wireless_info: Setting mac_for_netid{$row[5]} = $row[4]\n";
###		$likely_netid = $row[5];
###		print "likely netid 5 = *$likely_netid*\n";
        return;
    } else {
        print
            "Uh-oh....arppoe does not have record to match - retrieving earlier and later records\n";
        $get_wireless_info_results
            .= "Uh-oh....arppoe does not have record to match - retrieving earlier and later records\n";
    }
    $wireless_before_info->bind_param( 1, $mac );
    $wireless_before_info->bind_param( 2, $datetime );
    $wireless_before_info->execute();
    @row = $wireless_before_info->fetchrow_array();
    $wireless_before_info->finish;
    if ( $row[0] ne "" ) {
        printf "%19s %14s %14s %8s %15s %19s %19s Earlier \n", $row[2],
            $row[3], $row[4], $row[5], $row[6], $row[7], $row[8], $row[9];
        $output = sprintf(
            "%19s %14s %14s %8s %15s %19s %19s Earlier \n",
            $row[2], $row[3], $row[4], $row[5],
            $row[6], $row[7], $row[8], $row[9]
        );
        $get_wireless_info_results .= $output;
    } else {
        print "No earlier record\n";
        $get_wireless_info_results .= "No earlier record\n";
    }
    $wireless_after_info->bind_param( 1, $mac );
    $wireless_after_info->bind_param( 2, $datetime );
    $wireless_after_info->execute();
    @row = $wireless_after_info->fetchrow_array();
    $wireless_after_info->finish;
    if ( $row[0] ne "" ) {
        printf "%19s %14s %14s %8s %15s %19s %19s Later\n", $row[2], $row[3],
            $row[4], $row[5], $row[6], $row[7], $row[8], $row[9];
        $output = sprintf(
            "%19s %14s %14s %8s %15s %19s %19s Later\n",
            $row[2], $row[3], $row[4], $row[5],
            $row[6], $row[7], $row[8], $row[9]
        );
        $get_wireless_info_results .= $output;
    } else {
        print "No later record\n";
        $get_wireless_info_results .= "No later record\n";
    }

    print "\n";
    $get_wireless_info_results .= "\n";
}

sub get_guest_info {

    $guest_info->bind_param( 1, $ip );
    $guest_info->bind_param( 2, $datetime );
    $guest_info->bind_param( 3, $datetime );
    $guest_info->execute();
    @row = $guest_info->fetchrow_array();

    my $authtime = $row[0];
    my $stoptime = $row[2];
    my $ipaddr   = $row[3];
    my $mac      = $row[4];
    my $gnetid   = lc( $row[5] );
    my $apname   = $row[6];
    my $arptime  = $row[1];
    $guest_info->finish;

    printf "%19s %14s %14s %8s %15s %19s %19s\n", 'arptime', 'IP address',
        'MAC address', 'netid', 'AP', 'authtime', 'stoptime';
    $output = sprintf(
        "%19s %14s %14s %8s %15s %19s %19s\n",
        'arptime',  'IP address', 'MAC address', 'netid',
        'Hostname', 'authtime',   'stoptime'
    );
    $get_guest_info_results .= $output;
    printf "%19s %14s %14s %8s %15s %19s %19s\n", '-------------------',
        '--------------', '--------------', '--------', '---------------',
        '-------------------', '-------------------';
    $output = sprintf(
        "%19s %14s %14s %8s %15s %19s %19s\n",
        '-------------------', '--------------',  '--------------',
        '--------',            '---------------', '-------------------',
        '-------------------'
    );
    $get_guest_info_results .= $output;

    if ( $row[0] ne "" ) {
        printf "%19s %14s %14s %8s %15s %19s %19s\n\n", $arptime, $ipaddr,
            $mac, $gnetid, $apname, $authtime, $stoptime;
        $output = sprintf(
            "%19s %14s %14s %8s %15s %19s %19s\n\n",
            $arptime, $ipaddr,   $mac, $gnetid,
            $apname,  $authtime, $stoptime
        );
        $get_guest_info_results .= $output;

        #		print "In get_guest_info: Setting possible_netids for *$row[5]\n";
        $possible_netids{ $row[5] } = 1;

        #		print "Setting possible_netids{$row[5]} = 1\n";
        $mac_for_netid{ $row[5] } = $row[4];

     #		print "In get_guest_info: Setting mac_for_netid{$row[5]} = $row[4]\n";
###		$likely_netid = $row[5];
###		print "likely netid 5 = *$likely_netid*\n";
        return;
    } else {
        print
            "Uh-oh....guest table does not have record to match - retrieving earlier and later records\n";
        $get_guest_info_results
            .= "Uh-oh....guest table does not have record to match - retrieving earlier and later records\n";
    }
    $guest_before_info->bind_param( 1, $mac );
    $guest_before_info->bind_param( 2, $datetime );
    $guest_before_info->execute();
    @row = $guest_before_info->fetchrow_array();
    $guest_before_info->finish;
    if ( $row[0] ne "" ) {
        printf "%19s %14s %14s %8s %15s %19s %19s Earlier \n", $arptime,
            $ipaddr, $mac, $gnetid, $apname, $authtime, $stoptime;
        $output = sprintf(
            "%19s %14s %14s %8s %15s %19s %19s Earlier \n",
            $arptime, $ipaddr,   $mac, $gnetid,
            $apname,  $authtime, $stoptime
        );
        $get_guest_info_results .= $output;
    } else {
        print "No earlier record\n";
        $get_guest_info_results .= "No earlier record\n";
    }
    $guest_after_info->bind_param( 1, $mac );
    $guest_after_info->bind_param( 2, $datetime );
    $guest_after_info->execute();
    @row = $guest_after_info->fetchrow_array();
    $guest_after_info->finish;
    if ( $row[0] ne "" ) {
        printf "%19s %14s %14s %8s %15s %19s %19s Later\n", $arptime,
            $ipaddr, $mac, $gnetid, $apname, $authtime, $stoptime;
        $output = sprintf(
            "%19s %14s %14s %8s %15s %19s %19s Later\n",
            $arptime, $ipaddr,   $mac, $gnetid,
            $apname,  $authtime, $stoptime
        );
        $get_guest_info_results .= $output;
    } else {
        print "No later record\n";
        $get_guest_info_results .= "No later record\n";
    }

    print "\n";
    $get_guest_info_results .= "\n";
}

sub fix_date_time {
    ($dt) = @_;
    print "date need to be fixed=>$dt\n";
    my ( $y, $m, $d, $h, $min, $s ) =
        ( $dt =~ (/(\d+)-(\d+)-(\d+)T(\d+)\:(\d+)\:(\d+).*/) );
    my $dt1 = DateTime->new(
        year      => $y,
        month     => $m,
        day       => $d,
        hour      => $h,
        minute    => $min,
        second    => $s,
        time_zone => 'UTC'
    );

    print "UTC=>$dt1\n";
    $dt2 = $dt1->set_time_zone('America/Chicago');

    #$dt2 = $dt->clone->set_time_zone( 'America/Chicago' );
    my $dt3 = $dt2->strftime("%Y-%m-%d %H:%M:%S");
    print $dt3, "\n";
    ### build semester start date
    my $year = $dt2->year;
    my $mon  = $dt2->month;
    my $day  = $dt2->day;
    my $hour = $dt2->hour;

    if ( $mon < 8 || $mon == 8 && $day < 15 ) {
        $dt2->subtract( years => 1 );
        $semester = $dt2->year . "-08-15";
    } else {

        $semester = $year . "-08-15";
    }

    $flow_begin =
        newtstamp( $year, $mon, $day, $hour, $min, $s, $INTERVAL_NEG );
    $flow_end =
        newtstamp( $year, $mon, $day, $hour, $min, $s, $INTERVAL_MIN );

    $unix_datetime = $dt2->epoch();
    return $dt3;
}

sub fix_date_time1 {

    ($dt) = @_;
    %conv_mon = (
        'Jan' => '01',
        'Feb' => '02',
        'Mar' => '03',
        'Apr' => '04',
        'May' => '05',
        'Jun' => '06',
        'Jul' => '07',
        'Aug' => '08',
        'Sep' => '09',
        'Oct' => '10',
        'Nov' => '11',
        'Dec' => '12',
    );

    ( $byear, $bmonth, $bday, $bhour, $bmin, $bsec, $bdoy, $bdow, $dst ) =
        System_Clock( [$gmt] );
    (   $xbyear, $xbmonth, $xbday, $xbhour, $xbmin,
        $xbsec,  $xbdoy,   $xbdow, $dst
    ) = System_Clock();

#
# -t flag will cause command to process ticket in opposite of current daylight savings time status
#
    if ($opt_t) {
        if   ($dst) { $dst = ""; }
        else        { $dst = 1; }
    }

    # 2009-10-07 09:48:06 PST
    ( $y, $m, $d, $h, $min, $s ) =
        ( $dt =~ (/(\d+)-(\d+)-(\d+)\s+(\d+)\:(\d+)\:(\d+)\s+PST/) );
    if ($d) {
        if   ($dst) { $offset = $offset + 2; }
        else        { $offset = $offset + 2; }
        ( $y, $m, $d, $h, $min, $s ) =
            Add_Delta_DHMS( $y, $m, $d, $h, $min, $s, 0, $offset, 0, 0 );
        if ( $m <= 9 )   { $m   = "0" . $m; }
        if ( $d <= 9 )   { $d   = "0" . $d; }
        if ( $h <= 9 )   { $h   = "0" . $h; }
        if ( $s <= 9 )   { $s   = "0" . $s; }
        if ( $min <= 9 ) { $min = "0" . $min; }
        $flow_begin = newtstamp( $y, $m, $d, $h, $min, $s, $INTERVAL_NEG );
        $flow_end   = newtstamp( $y, $m, $d, $h, $min, $s, $INTERVAL_MIN );

        $newdatetime = "$y-$m-$d $h:$min:$s";
        return $newdatetime;

    }

    ( $d1, $d2 ) = ( $dt =~ (/(\d+\-\d+\-\d+)\s+(\d+\:\d+\:\d+)/) );
    if ( $d1 ne "" ) {

# Already in correct format -- return passed value. But first, create a $INTERVAL_MIN start and
# stop time to look through a larger range of flows
#
        ( $oyear, $omonth, $oday, $ohour, $omin, $osec ) =
            ( $dt =~ (/(\d+)\-(\d+)\-(\d+)\s+(\d+)\:(\d+)\:(\d+)/) );

        # begin time
        $flow_begin = newtstamp( $oyear, $omonth, $oday, $ohour, $omin, $osec,
            $INTERVAL_NEG );
        $flow_end = newtstamp( $oyear, $omonth, $oday, $ohour, $omin, $osec,
            $INTERVAL_MIN );
        return $dt;
    }

    # If we are here, not yet in correct format
    # 13 Sep 2008 14:20:42 EDT (GMT -0400)

    ( $d, $m, $y, $h, $min, $s, $offset ) = (
        $dt =~ (
            /(\d+)\s+(\S+)\s+(\d+)\s+(\d+)\:(\d+)\:(\d+)\s+\S\ST\s+\(GMT\s+\-(\d\d)00/
        )
    );
    if ($d) {
        if   ($dst) { $offset = $offset - 5; }
        else        { $offset = $offset - 6; }
        $m = $conv_mon{$m};
        ( $y, $m, $d, $h, $min, $s ) =
            Add_Delta_DHMS( $y, $m, $d, $h, $min, $s, 0, $offset, 0, 0 );
        if ( $m <= 9 )   { $m   = "0" . $m; }
        if ( $d <= 9 )   { $d   = "0" . $d; }
        if ( $h <= 9 )   { $h   = "0" . $h; }
        if ( $s <= 9 )   { $s   = "0" . $s; }
        if ( $min <= 9 ) { $min = "0" . $min; }
        $flow_begin = newtstamp( $y, $m, $d, $h, $min, $s, $INTERVAL_NEG );
        $flow_end   = newtstamp( $y, $m, $d, $h, $min, $s, $INTERVAL_MIN );

        $newdatetime = "$y-$m-$d $h:$min:$s";
        return $newdatetime;

    }

    # 2012-10-27T11:26:17-04:00

    ( $y, $m, $d, $h, $min, $s, $offset ) =
        ( $dt =~ (/(\d+)-(\d+)-(\d+)T(\d+)\:(\d+)\:(\d+)\-(\d\d)\:\d\d/) );
    if ($d) {
        if   ($dst) { $offset = $offset - 5; }
        else        { $offset = $offset - 6; }
        ( $y, $m, $d, $h, $min, $s ) =
            Add_Delta_DHMS( $y, $m, $d, $h, $min, $s, 0, $offset, 0, 0 );
        if ( $m <= 9 )   { $m   = "0" . $m; }
        if ( $d <= 9 )   { $d   = "0" . $d; }
        if ( $h <= 9 )   { $h   = "0" . $h; }
        if ( $s <= 9 )   { $s   = "0" . $s; }
        if ( $min <= 9 ) { $min = "0" . $min; }
        $flow_begin = newtstamp( $y, $m, $d, $h, $min, $s, $INTERVAL_NEG );
        $flow_end   = newtstamp( $y, $m, $d, $h, $min, $s, $INTERVAL_MIN );

        $newdatetime = "$y-$m-$d $h:$min:$s";
        return $newdatetime;

    }

    # 2008-09-18T18:43:32.03Z

    ( $y, $m, $d, $h, $min, $s ) =
        ( $dt =~ (/(\d+)-(\d+)-(\d+)T(\d+)\:(\d+)\:(\d+)\.\d+Z/) );
    if ( $y eq "" ) {
        ( $y, $m, $d, $h, $min, $s ) =
            ( $dt =~ (/(\d+)-(\d+)-(\d+)T(\d+)\:(\d+)\:(\d+)Z/) );
    }
    if ( $y ne "" ) {

        # ($year,$month,$day, $hour,$min,$sec) =
        #      Add_Delta_DHMS($year,$month,$day, $hour,$min,$sec,
        #                     $Dd,$Dh,$Dm,$Ds);

# The daylight savings time flag ("$dst") will be "-1" if this information is not available on your system,
# "0" for no daylight savings time (i.e., winter time) and "1" when daylight savings time is in effect.

        if   ($dst) { $offset = "-5"; }
        else        { $offset = "-6"; }
        ( $y, $m, $d, $h, $min, $s ) =
            Add_Delta_DHMS( $y, $m, $d, $h, $min, $s, 0, $offset, 0, 0 );
        if ( $m <= 9 )   { $m   = "0" . $m; }
        if ( $d <= 9 )   { $d   = "0" . $d; }
        if ( $h <= 9 )   { $h   = "0" . $h; }
        if ( $s <= 9 )   { $s   = "0" . $s; }
        if ( $min <= 9 ) { $min = "0" . $min; }
        $flow_begin = newtstamp( $y, $m, $d, $h, $min, $s, $INTERVAL_NEG );
        $flow_end   = newtstamp( $y, $m, $d, $h, $min, $s, $INTERVAL_MIN );

        $newdatetime = "$y-$m-$d $h:$min:$s";
        return $newdatetime;
    }

    # 22 Sep 2008 13:34:42 GMT

    ( $d, $m, $y, $h, $min, $s ) =
        ( $dt =~ (/(\d+)\s+(\S+)\s+(\d+)\s+(\d+)\:(\d+)\:(\d+) GMT/) );
    if ($d) {
        if   ($dst) { $offset = "-5"; }
        else        { $offset = "-6"; }
        $m = $conv_mon{$m};
        ( $y, $m, $d, $h, $min, $s ) =
            Add_Delta_DHMS( $y, $m, $d, $h, $min, $s, 0, $offset, 0, 0 );
        if ( $m <= 9 )   { $m   = "0" . $m; }
        if ( $d <= 9 )   { $d   = "0" . $d; }
        if ( $h <= 9 )   { $h   = "0" . $h; }
        if ( $s <= 9 )   { $s   = "0" . $s; }
        if ( $min <= 9 ) { $min = "0" . $min; }
        $flow_begin = newtstamp( $y, $m, $d, $h, $min, $s, $INTERVAL_NEG );
        $flow_end   = newtstamp( $y, $m, $d, $h, $min, $s, $INTERVAL_MIN );
        $newdatetime = "$y-$m-$d $h:$min:$s";
        return $newdatetime;
    }

}

sub prepare_sql {

#
# select count(*) from fw_arp where pub_ip='131.193.239.137';
# select count(*) from router_arp where ip='131.193.239.137';
#
# select * from fw_arp where pub_ip='131.193.239.137' and tstamp < '2008-09-16 22:03:01' order by tstamp desc limit 1;
# select * from fw_arp where pub_ip='131.193.239.137' and tstamp > '2008-09-16 22:03:01' order by tstamp asc limit 1;
#
# select * from router_arp where ip='131.193.239.137' and tstamp < '2008-09-16 22:03:01' order by tstamp desc limit 1;
# select * from router_arp where ip='131.193.239.137' and tstamp > '2008-09-16 22:03:01' order by tstamp asc limit 1;
#

    $fw_ip = $world->prepare(
        "select count(*) from $world_priv_table where pub_ip = ?")
        || print "fw_ip prepare failed\n";
    $in_vpn =
        $dbh->prepare("select count(*) from $vpn_table where vpn_ip = ?")
        || print "fw_ip prepare failed\n";
    $router_ip =
        $world->prepare("select count(*) from $world_table where ip = ?")
        || print "router_ip prepare failed\n";

    $vpn_info = $dbh->prepare(
        "select user, remote_ip, vpn_ip, start_time, end_time from $vpn_table where vpn_ip = ?
				and start_time < ?
				and (end_time > ? or end_time  = 'NULL')"
    ) || print "vpn_info prepare failed\n";

    #$fw_before = $world->prepare("select * from $world_priv_table where
    #				pub_ip = ? and
    #				tstamp < ?
    #				order by tstamp desc limit 1");

    ##
    ##  select * from fw_arp where pub_ip ='131.193.191.124' and tstamp >'2015-11-02 12:57'  limit 2
    ##   union all (select * from fw_arp where pub_ip ='131.193.191.124' and tstamp<'2015-11-02 12:57' order by tstamp desc limit 2);

    $fw_list = $world->prepare(
        "select * from $world_priv_table where
		pub_ip = ? and tstamp > ? limit 2
                UNION ALL  
               (select * from $world_priv_table where
		pub_ip = ? and tstamp < ? order by tstamp desc limit 2)"
    );

    $fw_before = $world->prepare(
        "select * from $world_priv_table where
				pub_ip = ? and
				tstamp < ? and word = '+' 
				order by tstamp desc limit 1"
    );

    #$fw_after = $world->prepare("select * from $world_priv_table where
    #				pub_ip = ? and
    #				tstamp > ?
    #				order by tstamp asc limit 1");

    $fw_after = $world->prepare(
        "select * from $world_priv_table where
				pub_ip = ? and
				tstamp > ? and 
				mac = ? and word = '-' 
				order by tstamp asc limit 1"
    );

    $router_before = $world->prepare(
        "select * from $world_table where
				ip = ? and
				tstamp < ?
				order by tstamp desc limit 1"
    );

    $router_after = $world->prepare(
        "select * from $world_table where
				ip = ? and
				tstamp > ?
				order by tstamp asc limit 1"
    );

    $mac_map_cnt =
        $dbh->prepare("select count(*) from $macnetid_table where mac = ?");
    $resnet_exists =
        $res->prepare("select count(*) from $resnet_table where mac = ?");
    $mac_map_info =
        $dbh->prepare("select * from $macnetid_table where mac = ?");

    $wireless_info = $dbh->prepare(
        "select * from $arp_table where 
				ip = ? and
				authtime < ? and
				((stoptime > ?) or (stoptime = '0000-00-00 00:00:00')) order by authtime desc limit 1"
    );

    $guest_info = $dbh->prepare(
        "select * from $guest_table where 
				ip = ? and
				authtime < ? and
				((stoptime > ?) or (stoptime = '0000-00-00 00:00:00')) order by authtime desc limit 1"
    );

  #$resnet_info2 = $res->prepare("select * from $resnet_table where mac = ?");
    $resnet_info = $res->prepare(
        "select * from $resnet_table where mac = ?
				and authtime < ?
				and ( (stoptime > ?) or (stoptime is NULL)) "
    );

    $wireless_before_info = $dbh->prepare(
        "select * from $arp_table where 
				mac = ? and
				authtime < ? order by authtime desc limit 1"
    );

    $wireless_after_info = $dbh->prepare(
        "select * from $arp_table where 
				mac = ? and
				authtime > ? order by authtime asc limit 1"
    );

    $guest_before_info = $dbh->prepare(
        "select * from $guest_table where 
				mac = ? and
				authtime < ? order by authtime desc limit 1"
    );

    $guest_after_info = $dbh->prepare(
        "select * from $guest_table where 
				mac = ? and
				authtime > ? order by authtime asc limit 1"
    );

    $get_unl_bw_info = $dbh->prepare(
        "select keynum,dmcasus,dmcaprev,passed_quiz,lifetime from $unlim_table where netid = ?"
    );

}

sub convert_colon_mac {

    if ( $mac =~ /:/ ) {

        # Mac is in xx:xx:xx:xx:xx:xx format. Convert it
        @macpieces = split /:/, $mac;
        $mac =
            "$macpieces[0]$macpieces[1].$macpieces[2]$macpieces[3].$macpieces[4]$macpieces[5]";
        print "Mac converted to: $mac\n";
    }
    return $mac;
}

sub append_suspend_file {

    my ($netid) = @_;
    print "Appending to suspend file $lfn for $netid...\n\n";
    my $tstamp = `/bin/date`;
    chop($tstamp);

    my $output = create_output($netid);

    $lfn = $suspend_dir . $netid;
    my $tmp = $suspend_dir . $netid . ".tmp";

    open( SUSIN, '<', $lfn );
    open( SUSOUT, '>', $tmp ) || die "cannot open tmp file for $lfn\n";
    binmode( SUSOUT, ":utf8" );
    print SUSOUT "++ $tstamp";
    print SUSOUT "\n\nMultiple OFFENSES\n\n";
    while (<SUSIN>) {
        print SUSOUT $_;
    }
    print SUSOUT
        "\n\n------------------------------------------------------------------------------\n\n";
    print SUSOUT "++ $tstamp";
    print SUSOUT "$output";
    close(SUSOUT);
    close(SUSIN);
    unlink $lfn;
    move( $tmp, $lfn );

    open( LOG, ">>$logfile" );
    print LOG
        "$tstamp ($uname) $netid already suspended -- RT# $id using $ip $mac -- APPENDING\n";
    close(LOG);
}

sub prepend_suspend_file {

    my ( $netid, $repeat ) = @_;
    print "Appending to suspend file $lfn for $netid...\n\n";
    my $tstamp = `/bin/date`;
    chop($tstamp);

    my $output;

    $output = "++ $tstamp";

    $output .= create_output($netid);

    my $lfn = $suspend_dir . $netid;
    my $tmp = $suspend_dir . $netid . ".tmp";

    open( SUSIN,  '<', $lfn );
    open( SUSOUT, '>', $tmp );
    binmode( SUSOUT, ":utf8" );
    print SUSOUT "++ $tstamp";
    if ($repeat) {
        print SUSOUT "\n\nREPEAT OFFENSE\n\n" if $repeat;
    } else {
        print SUSOUT "\n\nMultiple OFFENSES\n\n";
    }
    print SUSOUT "$output\n";
    print SUSOUT "-------------------------\n\n";
    while (<SUSIN>) {
        print SUSOUT $_;
    }
    close(SUSOUT);
    close(SUSIN);
    unlink $lfn;
    move( $tmp, $lfn );
    open( LOG, ">>$logfile" );
    print LOG
        "$tstamp ($uname) $netid already suspended -- RT# $id using $ip $mac -- APPENDING\n";
    close(LOG);
    create_autofilter_file( $netid, 1 );
    return $output;
}

sub create_autofilter_file {
    my ( $netid, $REPEAT ) = @_;

    if ( !$FILENAME ) {
        $autofilter_fn =
              $autofilter_dir
            . "[$netid]_$ipaddress^$mac_for_netid{$netid}^"
            . $hname
            . "__Account_abuse";
        if ($MAC) {
            $autofilter_fn =
                  $autofilter_dir
                . "[]_$ipaddress^$netid^"
                . $hname
                . "__Received_Notification_of_Copyright_Infringement";
        }
        print "Autofilter fn = $autofilter_fn\n\n";
        open( AUTOF, ">$autofilter_fn" );
        if ($MAC) { print AUTOF "$datetime\n\n"; }
        print AUTOF
            "Suspended per RT https://helpdesk.uic.edu/accc/Ticket/Display.html?id="
            . $id . "\n";
        if ($MAC) { print AUTOF $output . "\n"; }
        close(AUTOF);
    }
    open( LOG, ">>$logfile" );
    if ( ( !$REPEAT ) && ( !$passed_quiz{$netid} ) ) {
        print LOG
            "$tstamp ($uname) $netid suspended per RT# $id using $ip $mac\n";
    } elsif ( $passed_quiz{$netid} ) {
        print LOG
            "$tstamp $netid suspended per RT# $id using $ip $mac -- PASSED UNLIMITED BANDWIDTH QUIZ\n";
    } else {
        print LOG
            "$tstamp $netid suspended per RT# $id using $ip $mac -- REPEAT OFFENSE\n";
    }
    close(LOG);

}

sub create_suspend_file {

    my ( $netid, $filename, $REPEAT ) = @_;

    my $DEBUG = 0;
    $output = "";

#
# If this is a list of netids, then the list will have blank(s) in the middle and/or at the end.
# Remove the blank at the end
#
    if ( $netid =~ / / ) { chop($netid); }

    my $tstamp = `/bin/date`;
    chop($tstamp);

    $lfn = $suspend_dir . $filename;
    print "Creating suspend file $lfn for $netid...\n\n";
    if ($FILENAME) {
        open( SUSOUT, ">>$lfn" );
        binmode( SUSOUT, ":utf8" );

        if ($REPEAT) {
            print SUSOUT "++ $tstamp\n\nREPEAT OFFENSE\n\n";
        }
        print SUSOUT
            "n\n------------------------------------------------------------------------------\n\n";
    } else {
        open( SUSOUT, ">$lfn" );
        print SUSOUT "++ $tstamp\n";
        binmode( SUSOUT, ":utf8" );
        if ($REPEAT) {
            print SUSOUT "\nREPEAT OFFENSE\n\n";
        }
        if ( $passed_quiz{$netid} ) {
            print SUSOUT
                "\nPASSED UNLIMITED BANDWIDTH QUIZ -- $passedquizdate\n\n";
            print
                "++ $tstamp\n\nPASSED UNLIMITED BANDWIDTH QUIZ -- $passedquizdate\n\n";
        }
    }

    my $output;
    $output = create_output($netid);

    print SUSOUT $output;
    if ($DEBUG) { print $output. "\n"; }

    #
    # create autofilter record
    #
    if ( !$FILENAME ) {
        $autofilter_fn =
              $autofilter_dir
            . "[$netid]_$ipaddress^$mac_for_netid{$netid}^"
            . $hname
            . "__Account_abuse";
        if ($MAC) {

#			$autofilter_fn = $autofilter_dir."$ipaddress.".$hname.".__Received_Notification_of_Copyright_Infringement";
            $autofilter_fn =
                  $autofilter_dir
                . "[]_$ipaddress^$netid^"
                . $hname
                . "__Received_Notification_of_Copyright_Infringement";
        }
        print "Autofilter fn = $autofilter_fn\n\n";
        open( AUTOF, ">$autofilter_fn" );
        if ($MAC) { print AUTOF "$datetime\n\n"; }
        print AUTOF
            "Suspended per RT https://helpdesk.uic.edu/accc/Ticket/Display.html?id="
            . $id . "\n";
        if ($MAC) { print AUTOF $output . "\n"; }
        close(AUTOF);
    }
    open( LOG, ">>$logfile" );
    if ( ( !$REPEAT ) && ( !$passed_quiz{$netid} ) ) {
        print LOG
            "$tstamp ($uname) $netid suspended per RT# $id using $ip $mac\n";
    } elsif ( $passed_quiz{$netid} ) {
        print LOG
            "$tstamp $netid suspended per RT# $id using $ip $mac -- PASSED UNLIMITED BANDWIDTH QUIZ\n";
    } else {
        print LOG
            "$tstamp $netid suspended per RT# $id using $ip $mac -- REPEAT OFFENSE\n";
    }
    close(LOG);

    return $output;
}

sub prepend_suspend_file_old {

    print "File already exists .... prepending\n";

    my ( $netid, $filename ) = @_;
    $lfn          = $suspend_dir . $filename;
    $lfn_tempfile = $lfn . ".oldsusfile";
    system("/bin/mv $lfn $lfn_tempfile");
    if ( !-e $lfn_tempfile ) {
        die
            "netid file $lfn was moved to $lfn_tempfile, but it does not exist. Exiting!\n";
    }
    create_suspend_file( $netid, $filename, 1 );
    print SUSOUT
        "\n================================================================================\n\n";
    close(SUSOUT);
    system("cat $lfn_tempfile >> $lfn");
    system("/bin/rm $lfn_tempfile");

}

sub check_flows_for_port {

    my ( $ip, $datetime, $port ) = @_;

    #	$flow_cnt = 0;
    #	return;

    # 2008-12-05 12:54:07
    my ( $yr, $md, $h, $m1, $m2 ) =
        ( $datetime =~ (/(\d+)\-(.*) (\d+)\:(\d)(\d)\:.*/) );

    if   ( ( $m2 >= 0 ) && ( $m2 <= 4 ) ) { $m2 = "0"; }
    else                                  { $m2 = "5"; }

    $mins = $m1 . $m2;

    $today = `/bin/date +%m-%d`;
    chop($today);

    ### warn if PAT address
    if ( $pat =~ m/\Q$ip/ ) {
        print "\n!!! Warning $ipaddress is a PAT address !!!\n";
    }

    if ( $today eq $md ) {
        $flow_file = "/var/flows/ft-v05.$yr-$md.$h$mins" . "00";
    } else {
        $flow_file_mask = "/var/flows/logs/$md/ft-v05.$yr-$md.$h$mins" . "00";
        $flow_file      = `/bin/ls $flow_file_mask`;
        chop($flow_file);
    }
    print
        "\nChecking $flow_file for traffic to/from $ip:$port at $datetime\n";

    $flow_cnt = $printed_flows = 0;
    $flow_out =
        "\nStart             End               Sif   SrcIPaddress    SrcP  DIf   DstIPaddress    DstP    P Fl Pkts       Octets\n";
    print $flow_out;
    if ( -e $flow_file ) {
        open( FIN,
            "/usr/local/bin/flow-print -f 5 < $flow_file | /bin/grep $ip | /bin/grep $port |"
        ) || print "flow-print error\n";
        while (<FIN>) {
            $flows[$flow_cnt] = $_;
            $flow_out .= $_;
            $flow_cnt++;
            if ( $printed_flows < $num_flows_to_print ) {
                if ( $flow_cnt == 1 ) { print "\n"; }
                $printed_flows++;
                print "$_";
            }
        }
        close(FIN);
    } else {
        print "Flow file: $flow_file not found!\n\n";
    }

    if ( $flow_cnt == 0 ) {

#		print "No flows were found. Would you like to check +/- $INTERVAL_MIN range?\n";
#		$ans = <STDIN>;
#		lc($ans);chop($ans);
#		if ($ans eq "y") { check_flow_range($ip,$port); }
#		else {
#			$flow_out .= "\nNo flows were found \n\n";
#			print "\nNo flows were found \n\n";
#			}
        check_flow_range( $ip, $port );
    } else {
        print
            "\n\nPrinted $printed_flows out of $flow_cnt flows that match ip/port pair\n\n";
        $flow_out .= "\n\n";
    }
}

sub load_sig_file {
#
# Look for a ~/.dmcasig file to sign the request. This shows who processed the
# RT ticket for reference purposes. If this file does not exist, prompt for the
# info
#
    $sigfn = $ENV{'HOME'} . "/.dmca_sig";
    if ( !-e $sigfn ) {
        print
            "$sigfn not found: Please enter your information to include in this suspend record (e.g. Name/netid)\n";
        print
            "If you would like to avoid this in the future, create the file $sigfn\n";
        $info = <STDIN>;
        chop($info);
        if ( $info eq "" ) {
            die "Must specify info for suspend record....exiting\n";
        }
        $sig = $info;
    } else {
        open( SIGFN, "$sigfn" );
        while (<SIGFN>) { $sig .= "++ " . $_; }
        close(SIGFN);
    }
}

sub getRTInfoUsingXML {

    my $attachments = $ticket->attachments;

    my $count    = $attachments->count;
    my $iterator = $attachments->get_iterator;
    while ( my $att = &$iterator ) {
        if ($opt_d) { print "Content = ", $att->content, "\n"; }
        $cnt++;
        if ( $att->content =~ /(Dear)|(Sir)|(Madam)|(BEGIN PGP SIGNED)/i ) {
            $body = $att->content;
            $BODY = 1;
        }
        if ($opt_d) { print "In getRTInfoUsingXML: BODY = $BODY\n"; }

#	#
#	# Another kludge to make things work. RIAA changed their greeting from "Dear ..." to "Sir or Madam:" 9/8/09
#	#
#
#	if (!$BODY) {
#		if ($att->content =~ /Sir or Madam:/) {
#			$body = $att->content;
#			$BODY = 1;
#			}
#		}
#
#	if (!$BODY) {
#		if ($att->content =~ /BEGIN PGP SIGNED/) {
#			$body = $att->content;
#			$BODY = 1;
#			}
#		}
#

        if ( !$TIMESTAMP ) {
            ($timestamp) =
                ( $att->content =~ (/.*\<TimeStamp\>(.*)\<\/TimeStamp\>.*/) );
            if ($timestamp) { $TIMESTAMP = 1; }
        }
        if ($opt_d) {
            print "In getRTInfoUsingXML: timestamp = $timestamp\n";
        }

        if ( !$IPADDRESS ) {
            ($ipaddress) =
                (
                $att->content =~ (/.*\<IP_Address\>(.*)\<\/IP_Address\>.*/) );
            if ($ipaddress) { $IPADDRESS = 1; }
        }
        if ($opt_d) {
            print "In getRTInfoUsingXML: ipaddress = $ipaddress\n";
        }

        if ( !$PORT ) {
            ($port) = ( $att->content =~ (/.*\<Port\>(.*)\<\/Port\>.*/) );
            if ($opt_d) { print "In getRTInfoUsingXML: Port = *$port*\n"; }
            if ($opt_d) { print "Port = *$port*\n"; }
            if ($port) {
                $PORT = 1;
            } else {
              #
              # sometimes the port isn't in the XML, but is still in the text!
              #
                ($port) = ( $att->content =~ (/.*IP Port:\s+(\d+)\s+.*/) );
                if ($port) {
                    $PORT = 1;
                }
            }
            if ($opt_d) { print "In getRTInfoUsingXML: Port = *$port*\n"; }
            if ($opt_d) { print "Port = *$port*\n"; }
        }

#
# Once we have all we need, exit the loop, otherwise the REST perl library may crash due to a bug
#
        if ( $BODY && $TIMESTAMP && $IPADDRESS && $PORT ) { last; }
    }

}

sub getRTInfoUsingText {

    my $attachments = $ticket->attachments;

    my $count    = $attachments->count;
    my $iterator = $attachments->get_iterator;
    while ( my $att = &$iterator ) {
        if ($opt_d) { print "Content = ", $att->content, "\n"; }
        $cnt++;
        if ( $att->content =~ /(Dear)|(Sir)|(Madam)|(BEGIN PGP SIGNED)/i ) {
            $body = $att->content;
            $BODY = 1;
        }

        if ( !$TIMESTAMP ) {

            #		($timestamp) = ($body =~ (/.*st Found:\s+(.*)\s*\n/));
            ($timestamp) = ( $body =~ (/.*st Found:\s+(.*)/) );
            if ( !$timestamp ) {
                ($timestamp) = ( $body =~ (/.*st [Ff]ound.*:\s+(.*)/) );
            }
            if ( !$timestamp ) {
                ($timestamp) = ( $body =~ (/.*Timestamp.*:\s+(.*)/i) );
            }
            if ( !$timestamp ) {
                ($timestamp) = ( $body =~ (/.*Last Seen Date.*:\s+(.*)/i) );
            }
            if ($timestamp) { $TIMESTAMP = 1; }
            if ($opt_d) {
                print "In getRTInfoUsingText: timestamp = *$timestamp*\n";
            }
        }

        if ( !$IPADDRESS ) {
            ($ipaddress) = ( $body =~ (/.*Address:\s+(.*)\s+.*/) );
            if ($ipaddress) { $IPADDRESS = 1; }
        }
        if ($opt_d) {
            print "In getRTInfoUsingText: ipaddress = $ipaddress\n";
        }

        if ( !$PORT ) {
            ($port) = ( $body =~ (/.*Port:\s+(.*)\s*\n/) );
            if ( !$port ) {
                ($port) = ( $body =~ (/.*Port ID:\s+(.*)\s*\n/i) );
            }
            if ($port) {
                $PORT = 1;
            } else {
              #
              # sometimes the port isn't in the XML, but is still in the text!
              #
                ($port) = ( $att->content =~ (/.*IP Port:\s+(\d+)\s+.*/) );
                if ($port) {
                    $PORT = 1;
                }
            }
            if ($opt_d) { print "In getRTInfoUsingText: port = $port\n"; }
        }

#
# Once we have all we need, exit the loop, otherwise the REST perl library may crash due to a bug
#
        if ( $BODY && $TIMESTAMP && $IPADDRESS ) { last; }
    }

}

sub newtstamp {

    my ( $oyear, $omonth, $oday, $ohour, $omin, $osec, $interval ) = @_;
    ( $nyear, $nmonth, $nday, $nhour, $nmin, $nsec ) =
        Add_Delta_DHMS( $oyear, $omonth, $oday, $ohour, $omin, $osec, 0, 0,
        $interval, 0 );
    if ( $nmonth <= 9 ) { $nmonth = "0" . $nmonth; }
    if ( $nday <= 9 )   { $nday   = "0" . $nday; }
    if ( $nhour <= 9 )  { $nhour  = "0" . $nhour; }
    if ( $nsec <= 9 )   { $nsec   = "0" . $nsec; }
    if ( $nmin <= 9 )   { $nmin   = "0" . $nmin; }

    my $newdatetime = "$nyear-$nmonth-$nday $nhour:$nmin:$nsec";

    #	print "Returning new flow time: $newdatetime\n";
    return $newdatetime;
}

sub check_flow_range {

    my ( $IP, $PORT ) = @_;
    $todays_date = `date +'%Y-%m-%d'`;
    chop($todays_date);

    # check flow_begin and flow_end to see if they are on the same date
    ($flow_begin_date)    = ( $flow_begin =~ (/\d+\-(\d+\-\d+)\s+.*/) );
    ($flow_end_date)      = ( $flow_end =~   (/\d+\-(\d+\-\d+)\s+.*/) );
    ($flow_end_full_date) = ( $flow_end =~   (/(\d+\-\d+\-\d+)\s+.*/) );
    if ( $flow_begin_date ne $flow_end_date ) {

#		print "Issuing: /usr/local/bin/flow-cat /var/flows/logs/$flow_begin_date/ft*0 -t \"$flow_begin\" -T \"$flow_end\" | /usr/local/bin/flow-filter -p$PORT | /usr/local/bin/flow-print -f 5 | /bin/grep $IP\n";
        open( FIN,
            "/usr/local/bin/flow-cat /var/flows/logs/$flow_begin_date/ft*0 -t \"$flow_begin\" -T \"$flow_end\" | /usr/local/bin/flow-filter -p$PORT | /usr/local/bin/flow-print -f 5 | /bin/grep $IP |"
        );
        while (<FIN>) {
            $flows[$flow_cnt] = $_;
            $flow_out .= $_;
            $flow_cnt++;
            if ( $printed_flows < $num_flows_to_print ) {
                if ( $flow_cnt == 1 ) { print "\n"; }
                $printed_flows++;
                print "$_";
            }
        }
        close(FIN);
    }

# It's possible that the flows are either entirely from today or ending today. If so, adjust the log dir
#
    if ( $flow_end_full_date eq $todays_date ) {
        $flow_log_dir = "/var/flows/";
    } else {
        $flow_log_dir = "/var/flows/logs/$flow_end_date/";
    }

#	print "Issuing: /usr/local/bin/flow-cat $flow_log_dir/ft*0 -t \"$flow_begin\" -T \"$flow_end\" | /usr/local/bin/flow-filter -p$PORT | /usr/local/bin/flow-print -f 5 | /bin/grep $IP\n";
    open( FIN,
        "/usr/local/bin/flow-cat $flow_log_dir/ft*0 -t \"$flow_begin\" -T \"$flow_end\" | /usr/local/bin/flow-filter -p$PORT | /usr/local/bin/flow-print -f 5 | /bin/grep $IP |"
    );
    while (<FIN>) {
        $flows[$flow_cnt] = $_;
        $flow_out .= $_;
        $flow_cnt++;
        if ( $printed_flows < $num_flows_to_print ) {
            if ( $flow_cnt == 1 ) { print "\n"; }
            $printed_flows++;
            print "$_";
        }
    }

    if ( $flow_cnt == 0 ) {
        $flow_out .= "\nNo flows were found \n\n";
        print "\nNo flows were found \n\n";
    } else {
        $flow_out .= "\n\n";
    }
    return;
}

sub disconnect_dbs {
    $dbh->disconnect;
    $world->disconnect;
    $res->disconnect;
}

sub offsetdatetime {
    my ($ts) = @_;
    ( $y, $m, $d, $h, $min, $s ) =
        ( $ts =~ (/(\d+)-(\d+)-(\d+) (\d+):(\d+):(\d+)/) );
    if ( $m <= 9 )   { $m   = "0" . $m; }
    if ( $d <= 9 )   { $d   = "0" . $d; }
    if ( $h <= 9 )   { $h   = "0" . $h; }
    if ( $s <= 9 )   { $s   = "0" . $s; }
    if ( $min <= 9 ) { $min = "0" . $min; }
    $newts = newtstamp( $y, $m, $d, $h, $min, $s, $minoffset );

    #	print "newts = $newts\n";
    return $newts;
}

sub sendEmail {

    my ($netid) = @_;

    if ($MAC) { return 0; }

#            From            => 'ACCC Security Office <accc-security@uic.edu>',
#            Subject         => "SJA complaint needs to be filed for $netid",
#            To              => "esteban\@uic.edu,yanxuan\@uic.edu,jcrochon\@uic.edu",
#            Bcc             => "edz\@uic.edu",

    my $mailer = new Mail::Mailer
        || return (
        {   rc  => 360,
            msg => "ERROR: Cannot create mailer object:\nERROR: $!"
        }
        );
    $mailer->open(
        {   From    => 'nowhere@uic.edu',
            Subject => "SJA complaint needs to be filed for $netid",
            To      => 'security@uic.edu',
            Bcc     => "edz\@uic.edu,esteban\@uic.edu",
        }
        )
        || return (
        { rc => 361, msg => "ERROR: Cannot open mailer:\nERROR: $!" } );

    $mailer->print(
        "$netid was just suspended for a DMCA offense and is a repeat offender."
    );
    $mailer->close;

    print "Email has been sent to file a complaint\n";

    return 0;

}

sub sendQuizEmail {

    my ($netid) = @_;

    if ($MAC) { return 0; }

    my $mailer = new Mail::Mailer
        || return (
        {   rc  => 360,
            msg => "ERROR: Cannot create mailer object:\nERROR: $!"
        }
        );
    $mailer->open(
        {   From => 'nowhere@uic.edu',
            Subject =>
                "SJA complaint needs to be filed for $netid who had passed quiz",
            To  => 'security@uic.edu',
            Bcc => "edz\@uic.edu",
        }
        )
        || return (
        { rc => 361, msg => "ERROR: Cannot open mailer:\nERROR: $!" } );

    $mailer->print(
        "$netid was just suspended for a DMCA offense and was running in Unlimited Bandwidth Mode."
    );
    $mailer->close;

    print
        "Email has been sent to file a complaint for $netid who was running in Unlimited Bandwidth Mode\n";

    return 0;

}

sub create_output {

    my ($netid) = @_;

    #my $tstamp = `/bin/date`;
    #chop($tstamp);

    my $output;

    #$output = "++ $tstamp";

    $output .= $searching_string;

    $output .= "$sig\n\n";

    $output .= "sus\'d $netid\nfiltered $mac_for_netid{$netid}\n\n";

    $output .= "datetime = $datetime\n\n";

    $output
        .= $get_asa_data
        . $get_fw_table_info_results
        . $get_router_table_info_results
        . $get_macmap_info_results
        . $get_wireless_info_results
        . $get_resnet_info_results
        . $bw_info_out;

    my @flows = split( "\n", $flow_out );

    my $flowstring;
    my ($flow_tstamp) = ( $datetime =~ /\d+-\d+\d+\s+(\d+:\d+:\d)\d*/ );

    if ( scalar(@flows) < 15 ) {
        $flowstring = $flow_out;
    } else {

        $flowstring =
            "\nStart             End               Sif   SrcIPaddress    SrcP  DIf   DstIPaddress    DstP    P Fl Pkts       Octets\n";
        my ($flow_tstamp) = ( $datetime =~ /\d+-\d+\d+\s+(\d+:\d+:\d+)/ );

        #print $flow_tstamp,"\n";
        my @out = grep {/$flow_tstamp/} @flows;
        while ( scalar(@out) < 30 ) {
            $flow_tstamp =~ s/\S$//;
            push @out, grep {/$flow_tstamp/} @flows;
        }
        $flowstring .= join( "\n", @out[ 0 .. 30 ] );
    }

    $output .= $flowstring . "\n\n\n\n";

    $output
        .= "RT #"
        . $id . ": "
        . $subject
        . " \nhttps://helpdesk.uic.edu/accc/Ticket/Display.html?id="
        . $id . "\n\n";

    $output .= "---------------\n";

    $body =~ s/Hash: .+\n//g;
    $body =~ s/[^[:ascii:]]+//g;
    $body =~ s/-+BEGIN PGP SIGNED MESSAGE.+//;
    $body =~ s/Start ACNS XML(.+?)End ACNS XML//s;
    $body =~ s/<\?xml(.+)\>//sg;
    $body =~ s/BEGIN PGP SIGNATURE(.+?)END PGP SIGNATURE-.+//s;
    $body =~ s/[\-\s]*$//g;
    $body =~ s/\n+$/\n/sg;

    $output .= $body;
    return $output;

}

sub get_bw_info {

    my ( $netid, $print ) = @_;

    if ($dbh2) { $get_unl_bw_info->finish(); $dbh2->disconnect(); }
    $dbh2 = DBI->connect(
        'dbi:mysql:wireless:mysql-security1-master-1.data.cc.uic.edu',
        "db_wireless",
        UIC::Paw::get('db_wireless@mysql-security1-master-1.priv'),
        { AutoCommit => 0 }
    );
    unless ($dbh) {
        logit( "LOG",
            "connection to db_wireless@mysql-security1-master-1.priv.data.cc.uic.edu failed"
        );
        exit;
    }

    $get_unl_bw_info = $dbh2->prepare(
        "select keynum,dmcasus,dmcaprev,passed_quiz,UNIX_TIMESTAMP(passed_quiz),lifetime 
                     from $unlim_table where netid = ? and passed_quiz>?"
    );

    $get_unl_bw_info->bind_param( 1, $netid );
    $get_unl_bw_info->bind_param( 2, $semester );
    $get_unl_bw_info->execute();

    @row = $get_unl_bw_info->fetchrow_array();

    my ( $keynum, $dmcasusdate, $dmcaprevdate, $passedquizdate, $lifetime );
    $keynum              = $row[0];
    $dmcasusdate         = $row[1];
    $dmcaprevdate        = $row[2];
    $passedquizdate      = $row[3];
    $unix_passedquizdate = $row[4];
    $lifetime            = $row[5];

    if ( $dmcasusdate eq "" )  { $dmcasusdate  = "---------- --------"; }
    if ( $dmcaprevdate eq "" ) { $dmcaprevdate = "---------- --------"; }
    if ( $lifetime eq "" )     { $lifetime     = "- n/a -"; }
    if ( $passedquizdate eq "" ) {
        $passedquizdate = "---------- --------";
    }

    else {

        ### check if passedquizdate is after the incident
        # $passedquizdate format = 2014-08-25 20:18:26
        # $datetime - dmca format = 2014-08-25 02:18:07

        #        my $numpassedquiz = $passedquizdate;
        #        $numpassedquiz =~ s/\-|\s|\://g;

        #        my $numdatetime =~ $datetime;
        #        $numdatetime =~ s/\-|\s|\://g;
        if ( $unix_datetime > $unix_passedquizdate ) {
            $passed_quiz{$netid} = 1;

            #print "passed==>$netid, $unix_datetime, $passedquizdate\n";
            $passedafter = "passed quiz before incident ($datetime)";

            #print ">>>>>>>>>>>>>>>>>>>>>>>>>>>>  $passedafter\n";
        } else {
            $passedafter = "passed quiz after incident ($datetime)";

            #print "<<<<<<<<<<<<<<<<<<<<<<<<<<<<  $passedafter\n";
        }

    }

    #print "--------------------------  hello world\n";
    #print "++++++++++++++++++++++++++  $passedafter\n";

    if ($print) {
        printf "%15s %22s %22s %22s %15s\n", $netid, $dmcasusdate,
            $dmcaprevdate, $passedquizdate, $lifetime;

        #            print "$passedafter";
        $output = sprintf( "%15s %22s %22s %22s %15s\n",
            $netid, $dmcasusdate, $dmcaprevdate, $passedquizdate, $lifetime );
        $bw_info_out .= $output;

        #            $bw_info_out  .= "$passedafter";
    }

    return ( $keynum, $dmcasusdate, $dmcaprevdate, $passedquizdate,
        $lifetime );
}

sub update_bw_info {

    my ($netid) = @_;
    my $tstamp = `/bin/date`;
    chop($tstamp);

    my ( $keynum, $dmcasusdate, $dmcaprevdate, $passedquizdate, $lifetime ) =
        get_bw_info( $netid, 0 );

    $get_unl_bw_info->finish();
    $dbh2->disconnect;
    sleep( 1 * 20 );

    $dbh2 = DBI->connect(
        'dbi:mysql:wireless:mysql-security1-master-1.data.cc.uic.edu',
        "db_wireless",
        UIC::Paw::get('db_wireless@mysql-security1-master-1.priv'),
        { AutoCommit => 0 }
    );
    unless ($dbh) {
        logit( "LOG",
            "connection to db_wireless@mysql-security1-master-1.priv.data.cc.uic.edu failed"
        );
        exit;
    }

#	print "SQL Info for $netid: keynum $keynum / dmcasusdate $dmcasusdate / dmcaprevdate $dmcaprevdate / passedquizdate $passedquizdate / lifetime $lifetime\n";

   #
   # Logic:
   #
   # If never took quiz --> add row to table to prevent reset by taking quiz
   #
   # If quiz date, but no dmcasusdate or dmcaprevdate -- > add dmca sus date
   #
   # if prevdate, zero out prevdate and add dmcasusdate
   #
   # if lifetime, remove lifetime and add dmcasusdate -- issue lifetime notice
   #

    ( $dsus_year, $dsus_month, $dsus_day ) =
        ( $dmcasusdate =~ (/(\d+)\-(\d+)\-(\d+)\s.*/) );
    ( $dprev_year, $dprev_month, $dprev_day ) =
        ( $dmcaprevdate =~ (/(\d+)\-(\d+)\-(\d+)\s.*/) );
    ( $dpass_year, $dpass_month, $dpass_day ) =
        ( $passedquizdate =~ (/(\d+)\-(\d+)\-(\d+)\s.*/) );
    $now = `/bin/date +'%F %T'`;
    chop($now);

    if ( $keynum eq "" ) {
        $dbh2->do(
            "insert into $unlim_table (netid,dmcasus) values('$netid','$now')"
        );

        open( LOG, ">>$logfile" );
        print LOG
            "$tstamp ($uname) $netid did not exist in $unlim_table : row added and dmca suspension date updated\n";
        close(LOG);

        return;

    }

    if ( $dmcasusdate ne "0000-00-00 00:00:00" ) {
        open( LOG, ">>$logfile" );
        print LOG
            "$tstamp ($uname) $netid already has a dmcasusdate = $dmcasusdate -- no changes\n";
        close(LOG);

        return;
    }

    if ( $dmcaprevdate ne "0000-00-00 00:00:00" ) {
        $dbh2->do(
            "update $unlim_table set dmcasus = '$now', dmcaprev = '0000-00-00 00:00:00' where keynum = '$keynum'"
        );

        open( LOG, ">>$logfile" );
        print LOG
            "$tstamp ($uname) $netid had prevdate = $dmcaprevdate : reset to zero and dmca suspension date updated\n";
        close(LOG);

        return;
    }

    if ( $lifetime ne "- n/a -" ) {
        $dbh2->do(
            "update $unlim_table set dmcasus = '$now', dmcaprev = '0000-00-00 00:00:00' where keynum = '$keynum'"
        );

        open( LOG, ">>$logfile" );
        print LOG
            "$tstamp ($uname) $netid had LIFETIME status! : dmca suspension date updated\n";
        print
            "\n\n$tstamp $netid had LIFETIME status! : dmca suspension date updated\n\n";
        close(LOG);

        return;
    }

    if ( $dmcasusdate eq "0000-00-00 00:00:00" ) {
        $dbh2->do(
            "update $unlim_table set dmcasus = '$now' where keynum = '$keynum'"
        );

        open( LOG, ">>$logfile" );
        print LOG
            "$tstamp ($uname) $netid : dmca suspension date updated - SJA Case must be filed\n";
        close(LOG);

        sendQuizEmail($netid);

        return;
    }
}
