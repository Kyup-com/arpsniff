#!/usr/bin/perl
use Net::Pcap;
use NetPacket::Ethernet;
use NetPacket::ARP;
use Net::ARP;
use Net::Interface;
use Data::Dumper;

my $VERSION = "2.0";
my $pid;
my $errbuf;
my $out_dev;
my $listen_dev;
my %running_ifs;
my @interfaces;
my $perp_dir = '/etc/perp/arpsniff';
my $default_if = `ip r l | awk '/default/ {print \$5}'`;
my $rc_main = '/etc/perp/arpsniff/rc.main';
my $main_service = '/etc/perp/arpsniff/rc.main-service';
my $rc_log = '/etc/perp/arpsniff/rc.log';

$out_dev = $ARGV[0] if ($ARGV[0]);
$listen_dev = $ARGV[1] if ($ARGV[1]);


$SIG{"HUP"} = \&sigHup;
$SIG{CHLD} = 'IGNORE';

# Collecting all interfaces in array
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

sub write_newfile {
	my $filename = $_[0];
	my $content = $_[1];
	open my $tmpcont, '>', "$filename";
	print $tmpcont $content;
	chmod (0755, "$filename");
	close $tmpcont;
}

sub should_start {
	my $ct_if = $_[0];
	my $result = 0;
	$result = $running_ifs{$ct_if} if($running_ifs{$ct_if});
	return $result;
}

# Spawning child process for each container interface
sub start_child {
    my $ct_if = $_[0];
	my $out_if = $default_if;
	$out_if =~ s/[\n\r]//g;
	next if $pid = fork;
	$running_ifs{$ct_if} = $pid;
	die "fork failed: $!" unless defined $pid;
	exec("$0 $out_if $ct_if");
	exit;
}

sub reload_childs {
	my $ct_if = $_[0];
	my $out_if = $default_if;
	$out_if =~ s/[\n\r]//g;
	$child_exist = kill 0, $running_ifs{$ct_if};
	if (!$child_exist) {
		next if ($pid = fork);
		$running_ifs{$ct_if} = $pid;
		die "fork failed: $!" unless defined $pid;
		exec("$0 $out_if $ct_if");
		exit;
	}
	
}

# Adding perp directory with required files to run each running container interface.
sub perp_add {
		mkdir $perp_dir;
		write_newfile($rc_main,"#!/bin/sh\n\n. /etc/perp/.boot/service_lib.sh\n\nstart() {\n\n exec /usr/local/bin/arpsniff\n\n   }\n\neval \"\$TARGET\" \"\$@\"\n\nexit 0");
		write_newfile($rc_log, "#!/bin/sh\n\n. /etc/perp/.boot/rc.log-template\n");
		system("/usr/bin/pstart arpsniff") if (-f "/usr/bin/pstart");
		exit;
}

sub run_without_params {
	my $runtime = $_[0];
	@interfaces = get_interfaces;
	for my $vif (@interfaces) {
		if (verify_iface($vif) && !$runtime) {
			start_child($vif);
		}
		if (verify_iface($vif) && $runtime) {
			reload_childs($vif);
			}
	}
}

sub sigHup {
	run_without_params(1);
}


if (not defined($ARGV[0]) or not defined($ARGV[1])) {
	perp_add if ( ! -d $perp_dir);
	run_without_params;
	while(1) {
		sleep(1);
	}
}

sub arpsniff_instance {
    $out_dev = $_[0];
    $listen_dev = $_[1];
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

my $mac = Net::ARP::get_mac($out_dev) if ($out_dev);

arpsniff_instance($out_dev, $listen_dev) if ($out_dev && $listen_dev);

