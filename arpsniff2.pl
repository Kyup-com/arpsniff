#!/usr/bin/perl
use Net::Pcap;
use NetPacket::Ethernet;
use NetPacket::ARP;
use Net::ARP;
use Net::Interface;
use Data::Dumper;

my $VERSION = "1.1";
my $errbuf;
my $out_dev;
my $listen_dev;
my @interfaces;
my $perp_dir = '/etc/perp/';
my $default_if = `ip r l | awk '/default/ {print \$5}'`;
my $main_service = '/etc/perp/arpsniff/rc.main-service';
my $rc_log = 'etc/perp/.boot/rc.log-template';

$out_dev = $ARGV[0] if ($ARGV[0]);
$listen_dev = $ARGV[1] if ($ARGV[1]);


$SIG{"HUP"} = \&sigHup;

sub get_interfaces {
	my @result;
	my @all_ifs = Net::Interface->interfaces();
	for my $if (@all_ifs){
		push @result, $if->name;
	}
	return @result;
}

@interfaces = get_interfaces;

sub verify_iface {
	return 1 if ($_[0] =~ /^veth(c[0-9]+)?[0-9]+(.[0-9]+|:[0-9]+)?$/);
	return 0;
}

# adding perp directory with required files to run each running container interface.
sub perp_add {
	my $ct_if = $_[0];
	my $perp_loc = $_[1];
	my $perpif_dir = $perp_dir."arpsniff-".$ct_if;
	mkdir $perpif_dir if ( ! -d $perpif_dir );
	my $perp_conf = "${perpif_dir}/conf.sh";

	if ( ! -f $perp_conf ) {
			open my $conf, '>', "$perp_conf";
			print $conf "DEV=${default_if}DEV2=${ct_if}\n";
			close $conf;
	}
	if ( ! -f "$perpif_dir/rc.main" ) {
		symlink("$main_service", "$perpif_dir/rc.main");
	}
	if ( ! -f "$perpif_dir/rc.log" ) {
		symlink("/etc/perp/.boot/rc.log-template", "$perpif_dir/rc.log");
	}
	if ( -f "/usr/bin/pstart" ) {
		system("/usr/bin/pstart arpsniff-$ct_if");
	}
}

# removing perp files and directories for non-running containers.
sub perp_remove {
	my @perp_ifs;
	my @perplist = grep { -d } glob ( "${perp_dir}*" );
	for my $perpapp (@perplist) {
		if ( $perpapp =~ /^\/etc\/perp\/arpsniff-veth(c[0-9]+)?[0-9]+(.[0-9]+|:[0-9]+)?$/ ) {
			my @perp_app = split /arpsniff-/, $perpapp;
			push @perp_ifs, $perp_app[1];
		}
	}
	my %up_ifs = map { $_ => 1 } @interfaces;
	for my $ct_if (@perp_ifs) {
		if(verify_iface($ct_if) && exists($up_ifs{$ct_if})) {
			next;
		}
		system("/usr/bin/pstop arpsniff-${ct_if}");
		my $perpif_dir = $perp_dir."arpsniff-".$ct_if;
		unlink $perpif_dir."/rc.log";
		unlink $perpif_dir."/rc.main";
		unlink $perpif_dir."/conf.sh";
		rmdir $perpif_dir;
	}	
}

sub run_without_params {
	@interfaces = get_interfaces;
	for my $vif (@interfaces) {
		if (verify_iface($vif)) {
				perp_add($vif, $perp_dir);
			}

	}
}

sub sigHup {
    @interfaces = get_interfaces;

}


if (not defined($ARGV[0]) or not defined($ARGV[1])) {
	run_without_params;
	perp_remove;
}
my $mac = Net::ARP::get_mac($ARGV[0]) if ($ARGV[0]);

if ($ARGV[0] && $ARGV[1]){

	perp_remove;
	$out_dev = $ARGV[0];
	$listen_dev = $ARGV[1];
	my $device = $listen_dev;
	# open device
	my $handle = Net::Pcap::open_live($device, 2000, 1, 0, \$errbuf);
	die "Unable to open ",$device, " - ", $errbuf if (!defined $handle);

	# find netmask so we can set a filter on the interface
	Net::Pcap::lookupnet(\$device, \my $netp, \my $maskp, \$errbuf) || die "Can't find network info"; 
	
	# set filter on interface
	my $filter = "arp";
	Net::Pcap::compile($handle,\$fp, $filter, 0, $maskp) && die "Unable to compile BPF";
	Net::Pcap::setfilter($handle, $fp) && die "Unable to set filter";

	# start sniffing
	Net::Pcap::loop($handle, -1, \&process_packet, '') || die "Unable to start sniffing";

	# close
	Net::Pcap::close($handle);
}

sub process_packet {
	my ($user, $header, $packet) = @_;
	my $eth_data = NetPacket::Ethernet::strip($packet);
	my $arp = NetPacket::ARP->decode($eth_data);

	# convert hex number to IP dotted - from rob_au at perlmonks
	my $spa = join '.', map { hex } ($arp->{'spa'} =~ /([[:xdigit:]]{2})/g);
	my $tpa = join '.', map { hex } ($arp->{'tpa'} =~ /([[:xdigit:]]{2})/g);

	if ($spa eq $tpa) {
		print "Source: ",$spa,"( $mac)\tDestination: ",$tpa, "(ff:ff:ff:ff:ff:ff)\n";
		Net::ARP::send_packet($out_dev,			# Device
                        $tpa,					# Source IP
                        $tpa,					# Destination IP
                        $mac,					# Source MAC
                        'ff:ff:ff:ff:ff:ff',	# Destinaton MAC
                        'reply');				# ARP operation
	}
}


