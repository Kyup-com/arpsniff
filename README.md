This project has tools that are useful for proxy_arp setup.

 arpsniff.pl is a daemon that listens on specific interface for Gratuitous ARP requests and creates a new Gratuitous ARP packets on another interface but for the same IP

INSTALL

 yum install -y libpcap-devel && for i in Net::Pcap NetPacket::Ethernet NetPacket::ARP Net::ARP; do cpan -f $i; done
