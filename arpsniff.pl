#!/usr/bin/perl
use Net::Pcap;
use NetPacket::Ethernet;
use NetPacket::ARP;
use Net::ARP;
use POSIX qw(strftime :sys_wait_h);
use Data::Dumper;

my $VERSION = "1.1";
my $pid;
my $errbuf;
my $out_dev;
my $listen_dev;
my %running_ifs;
my @interfaces;
my $perp_dir = '/etc/perp/arpsniff';
my $rc_main = '/etc/perp/arpsniff/rc.main';
my $rc_log = '/etc/perp/arpsniff/rc.log';
my $logfile = '/var/log/arpsniff.log';
our $default_if = `ip r l | awk '/default/ {print \$5}'`;


sub sigHup {
	logger("SIGHUP received");
	run_without_params;
}

sub sigChld {
	while ( (my $pid = waitpid(-1, WNOHANG)) > 0 ) {
		my %rhash = reverse %running_ifs;
		my $veth = $rhash{$pid};
		delete $running_ifs{$veth};
		logger("$veth child ($pid) has been stopped.");
		run_without_params;
	}
}

sub sigTerm {
	my $veth =~ s/[\n\r]//g;
	foreach(keys %running_ifs) {
		kill 9, $running_ifs{$_};
	}
}

sub logger {
	print CLOG strftime('%b %d %H:%M:%S', localtime(time)) . ' Arpsniff - ' . $_[0] . "\n";
}

# Spawning child process for each container interface
sub start_child {
	my $ct_if = $_[0];
	my $out_if = $default_if;
	$out_if =~ s/[\n\r]+//g;
	$ct_if =~ s/[\n\r]+//g;
	next if ($running_ifs{$ct_if});
	$pid = fork;

	if (defined($pid) && $pid > 0) {
		$running_ifs{$ct_if} = $pid;
		return;
	}
	exec("$0 $out_if $ct_if");
	exit;
}

sub run_without_params {
	@interfaces = `awk '/veth/ {gsub(":",""); print \$1}' /proc/net/dev`;
	for my $vif (@interfaces) {
		start_child($vif) if ($vif =~ /^veth(c[0-9]+)?[0-9]+(.[0-9]+|:[0-9]+)?$/);
	}
}

sub arpsniff_instance {
	my $device = $_[0];
	# open device
	my $handle = Net::Pcap::open_live($device, 2000, 1, 0, \$errbuf);

	die "Unable to open ",$device, " - ", $errbuf if (!defined $handle);

	# find netmask so we can set a filter on the interface
	Net::Pcap::lookupnet(\$device, \my $netp, \my $maskp, \$errbuf) || die "Can't find network info";

	# set filter on interface

	Net::Pcap::compile($handle,\$fp, 'arp', 0, $maskp) && die "Unable to compile BPF";
	Net::Pcap::setfilter($handle, $fp) && die "Unable to set filter";

	# start sniffing
	Net::Pcap::loop($handle, -1, \&process_packet, '') || die "Unable to start sniffing";

	# close
	Net::Pcap::close($handle);
}

sub process_packet {
	my $mac = Net::ARP::get_mac($out_dev);
	my ($user, $header, $packet) = @_;
	my $eth_data = NetPacket::Ethernet::strip($packet);
	my $arp = NetPacket::ARP->decode($eth_data);
	# convert hex number to IP dotted - from rob_au at perlmonks
	my $spa = join '.', map { hex } ($arp->{'spa'} =~ /([[:xdigit:]]{2})/g);
	my $tpa = join '.', map { hex } ($arp->{'tpa'} =~ /([[:xdigit:]]{2})/g);
	if ($spa eq $tpa) {
		logger("Source: $spa ($mac)\tDestination: $tpa (ff:ff:ff:ff:ff:ff)");
		Net::ARP::send_packet($out_dev,			# Device
			$tpa,					# Source IP
			$tpa,					# Destination IP
			$mac,					# Source MAC
			'ff:ff:ff:ff:ff:ff',	# Destinaton MAC
			'reply');				# ARP operation
	}
}

$out_dev = $ARGV[0] if ($ARGV[0]);
$listen_dev = $ARGV[1] if ($ARGV[1]);

$SIG{"HUP"} = \&sigHup;
$SIG{"CHLD"} = \&sigChld;
$SIG{"TERM"} = \&sigTerm;

die "No default route interface" if (!$default_if || $default_if !~ /^eth(c[0-9]+)?[0-9]+(.[0-9]+|:[0-9]+)?$/);

open CLOG, '>>', $logfile or die "Unable to open logfile $logfile: $!\n";
# make the output to LOG and to STDOUT unbuffered
# this has to be done after the fork and after detaching from the command terminal
$|=1;
select((select(CLOG), $| = 1)[0]);

if (not defined($ARGV[0]) or not defined($ARGV[1])) {
	run_without_params;
	while(1) {
		my $res = waitpid($pid, WNOHANG);
		sleep(10);
		run_without_params;
		if ($res == -1) {
			logger("Some error occurred"), $? >> 8;
			exit;
		}
		if ($res) {
			logger("Child $res ended "), $? >> 8;
			last;
		}
	}
}

arpsniff_instance($listen_dev) if ($out_dev && $listen_dev);
