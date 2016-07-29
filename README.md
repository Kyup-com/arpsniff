This project has tools that are useful for proxy_arp setup.

 arpsniff.pl is a daemon that listens on specific interface for Gratuitous ARP requests and creates a new Gratuitous ARP packets on another interface but for the same IP

 To work properly with perp arpsniff2.pl should be added as /usr/local/bin/arpsniff 

INSTALL

 yum install -y libpcap-devel && for i in Net::Pcap NetPacket::Ethernet NetPacket::ARP Net::ARP Net::Interface; do cpan -f $i; done
