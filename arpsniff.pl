#!/usr/bin/perl
use Net::Pcap;
use NetPacket::Ethernet;
use NetPacket::ARP;
use Net::ARP;

my $VERSION = "1.0";
my $errbuf;
my $out_dev;
my $listen_dev;
my $pid_dir = "/var/run/arpsniff";

sub verify_iface {
	return 1 if ($_[0] =~ /^v?eth(c[0-9]+)?[0-9]+(.[0-9]+|:[0-9]+)?$/);
	return 0;
}

if (not defined($ARGV[0]) or not defined($ARGV[1])) {
	print "Usage: $0 outgoing_interface listening_interface\n";
	exit 1;
}

if (!verify_iface($ARGV[0])) {
	print "Error: invalid outgoing_interface\n";
	exit 1;
}
if (!verify_iface($ARGV[1])) {
	print "Error: invalid listening_interface\n";
	exit 1;
}

$out_dev = $ARGV[0];
$listen_dev = $ARGV[1];

my $mac = Net::ARP::get_mac($out_dev);

$device = $listen_dev;
# open device
$handle = Net::Pcap::open_live($device, 2000, 1, 0, \$errbuf);
die "Unable to open ",$device, " - ", $errbuf if (!defined $handle);

# find netmask so we can set a filter on the interface
Net::Pcap::lookupnet(\$device, \$netp, \$maskp, \$errbuf) || die "Can't find network info"; 

# set filter on interface
$filter = "arp";
Net::Pcap::compile($handle, \$fp, $filter, 0, $maskp) && die "Unable to compile BPF";
Net::Pcap::setfilter($handle, $fp) && die "Unable to set filter";


mkdir $pid_dir if ( ! -d $pid_dir );
if ( -f "$pid_dir/$listen_dev" ) {
	open my $pid, '<', "$pid_dir/$listen_dev";
	my $old_pid = <$pid>;
	close $pid;
	if ( -d "/proc/$old_pid" ) {
		open my $old_cmd, '<', "/proc/$old_pid/cmdline";
		my $cmdline = <$old_cmd>;
		close $old_cmd;
		if ($cmdline =~ /arpsniff/g) {
			print "Error: ARPsniff already started for $listen_dev!\n\tOld pid file: $pid_dir/$listen_dev\n";
			exit 1;
		}
	}
}

print "Starting ARP listener $VERSION on $listen_dev with outgoing interface $out_dev:\n";

# become daemon
defined(my $pid=fork) or die "DIE: Cannot fork process: $! \n";
exit if $pid;
setsid or die "DIE: Unable to setsid: $!\n";
# redirect standart file descriptors to /dev/null
open(STDIN, '<', '/dev/null') or die("DIE: Cannot read stdin: $! \n");
open(STDOUT, '>>', '/dev/null') or die("DIE: Cannot write to stdout: $! \n");
open(STDERR, '>>', '/dev/null') or die("DIE: Cannot write to stderr: $! \n");

open my $pid, '>', "/var/run/arpsniff/$listen_dev";
print $pid $$;
close $pid;


# start sniffing
Net::Pcap::loop($handle, -1, \&process_packet, '') || die "Unable to start sniffing";

# close
Net::Pcap::close($handle);

sub process_packet {
	my ($user, $header, $packet) = @_;
	my $eth_data = NetPacket::Ethernet::strip($packet);
	my $arp = NetPacket::ARP->decode($eth_data);

	# convert hex number to IP dotted - from rob_au at perlmonks
	my $spa = join '.', map { hex } ($arp->{'spa'} =~ /([[:xdigit:]]{2})/g);
	my $tpa = join '.', map { hex } ($arp->{'tpa'} =~ /([[:xdigit:]]{2})/g);

	if ($spa eq $tpa) {
		print "Source: ",$spa,"($mac)\tDestination: ",$tpa, "(ff:ff:ff:ff:ff:ff)\n";
		Net::ARP::send_packet($out_dev,			# Device
                        $tpa,					# Source IP
                        $tpa,					# Destination IP
                        $mac,					# Source MAC
                        'ff:ff:ff:ff:ff:ff',	# Destinaton MAC
                        'reply');				# ARP operation
	}
}
