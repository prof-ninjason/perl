#!/usr/bin/perl

 # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
#                                                                                      #
#   Jason C. Rochon                                                                    #
#   July 26, 2017                                                                      #
#   Retrieve banners via nmap                                                          #
#                                                                                      #
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

use Getopt::Std;
use Nmap::Parser;


 # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
#   Parse File                                                                         #
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

my $np     = new Nmap::Parser;
my $infile = $ARGV[0];
$np->parsefile($infile);


 # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
#   Vulnerability Data                                                                 #
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

our @vulnports = qw( 80 443 );

sub process_host {
  my ( $host, $vport ) = @_;
  
  print "\nHost: " . $host->hostname . "\tIP: " . $host->ipv4_addr;
  
  my $name = $host->tcp_service($vport)->name;
  print "\nPort: $vport (" . $name . ")\t open";
  
  my $banner = $host->tcp_service($vport)->scripts('banner-plus');
  if ( defined $banner->{output} ) {
    print "\nbanner: " . $banner->{output};
  }
}


for my $host ( $np->all_hosts ) {
  foreach my $vport (@vulnports) {
    if ( $host->tcp_port_state($vport) eq 'open' ) {
      process_host( $host, $vport );
    }
  }
}
 
 
 # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
#   Exit Routine                                                                       #
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

print "\n\n";
exit;
