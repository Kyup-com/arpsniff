#!/usr/bin/perl
use Net::Pcap;
use NetPacket::Ethernet;
use NetPacket::ARP;
use Net::ARP;
use POSIX qw(strftime :sys_wait_h);
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
my $logfile = '/var/log/arpsniff.log';

$out_dev = $ARGV[0] if ($ARGV[0]);
$listen_dev = $ARGV[1] if ($ARGV[1]);

$SIG{"HUP"} = \&sigHup;
$SIG{"CHLD"} = \&sigChld;
$SIG{"TERM"} = \&sigTerm;

open CLOG, '>>', $logfile or die "Unable to open logfile $logfile: $!\n";
# make the output to LOG and to STDOUT unbuffered
# # this has to be done after the fork and after detaching from the command terminal
$|=1;
select((select(CLOG), $| = 1)[0]);

sub logger {
	    print CLOG strftime('%b %d %H:%M:%S', localtime(time)) . ' Arpsniff - ' . $_[0] . "\n";
}

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

# Spawning child process for each container interface
sub start_child {
    my $ct_if = $_[0];
	my $out_if = $default_if;
	my $is_running = 0;
	$is_running = $running_ifs{$ct_if} if ($running_ifs{$ct_if});
	next if ( -d "/proc/$is_running/");
	$out_if =~ s/[\n\r]//g;
	$pid = fork;
	die "fork failed: $!" unless defined $pid;
	if ($pid > 0) {
		$running_ifs{$ct_if} = $pid;
		return;
	}
	exec("$0 $out_if $ct_if");
	exit;
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
	@interfaces = `awk '/veth/ {gsub(":",""); print \$1}' /proc/net/dev`;
	for my $vif (@interfaces) {
		start_child($vif) if (verify_iface($vif));
	}
}

sub sigHup {
	logger("SIGHUP");
	run_without_params;
}

sub sigChld {
    while (waitpid(-1,WNOHANG)>0 ) {
		my %rhash = reverse %running_ifs;
		my $veth = $rhash{$pid};
		$veth  =~ s/[\n\r]//g;
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

if (not defined($ARGV[0]) or not defined($ARGV[1])) {
	perp_add if ( ! -d $perp_dir);
	run_without_params;
	while(1) {
		my $res = waitpid($pid, WNOHANG);
		sleep(10);
		run_without_params;
		if ($res == -1) {
			logger("Some error occurred"), $? >> 8;
			exit();
		}
		if ($res) {
			logger("Child $res ended with "), $? >> 8;
			last;
		}
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

my $mac = Net::ARP::get_mac($out_dev) if ($out_dev);

sub process_packet {
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


arpsniff_instance($out_dev, $listen_dev) if ($out_dev && $listen_dev);
