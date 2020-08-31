#include <pcap.h>
#include <iostream>
#include<WinSock2.h>
#include<WS2tcpip.h>
#include <ctime>

#pragma comment(lib, "ws2_32.lib")
using namespace std;

#define IPTOSBUFFERS	12
#define ETHER_ADDR_LEN	6 // Ethernet addresses are 6 bytes 
#define SIZE_ETHERNET 14 // ethernet headers 

// Ethernet protocol ID's 
#define ETHERTYPE_IPv4 0x0800 // IPv4
#define ETHERTYPE_ARP 0x0806 // Address resolution
#define ETHERTYPE_REVARP 0x8035 // Reverse ARP 
#define WIFI 0x8902 // 802.11
#define ETHERTYPE_IPv6 0x86dd // IPv6

// Ethernet header
struct sniff_ethernet {
	u_char  ether_dhost[ETHER_ADDR_LEN];    // адрес получателя 
	u_char  ether_shost[ETHER_ADDR_LEN];    // адрес отправителя
	u_short ether_type;                     // IP? ARP? RARP?  
};

// IP header
struct sniff_ip {
	u_char  ip_vhl;                 // version << 4 | header length >> 2 
	u_char  ip_tos;                 // type of service 
	u_short ip_len;                 // total length 
	u_short ip_id;                  // identification 
	u_short ip_off;                 // fragment offset field
#define IP_RF 0x8000            // reserved fragment flag
#define IP_DF 0x4000            // dont fragment flag 
#define IP_MF 0x2000            // more fragments flag 
#define IP_OFFMASK 0x1fff       // mask for fragmenting bits
	u_char  ip_ttl;                 // time to live
	u_char  ip_p;                   // protocol 
	u_short ip_sum;                 // checksum 
	//struct  in_addr ip_src, ip_dst;  // source and dest address 
	bpf_u_int32 ip_src, ip_dst;
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

// TCP header
struct sniff_tcp
{
	u_short th_sport;               // source port 
	u_short th_dport;               // destination port
	u_int th_seq;                 // sequence number 
	u_int th_ack;                 // acknowledgement number
	u_char  th_offx2;               // data offset, rsvd 
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
	u_char  th_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;                 // window 
	u_short th_sum;                 // checksum 
	u_short th_urp;                 // urgent pointer
};

// UDP header
typedef struct sniff_udp
{
	u_short sport;			// Source port
	u_short dport;			// Destination port
	u_short len;			// Datagram length
	u_short crc;			// Checksum
};

// ip address to string
static char *iptos(bpf_u_int32 in)//usual type of ip,netmask
{
	static char output[IPTOSBUFFERS][3 * 4 + 3 + 1];
	static short which;
	u_char *p;

	p = (u_char *)&in;
	which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
	sprintf_s(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return output[which];
}

//sniff ip header
void get_ip(const u_char* pkt_data)
{
	const struct sniff_ip* ip;              // The IP header 
	const struct sniff_tcp* tcp;            // The TCP header 
	const struct sniff_udp* udp; // udp header
	int size_ip;
	int size_tcp;
	char ntop_buf[INET_ADDRSTRLEN];
	// compute ip header 
	ip = (struct sniff_ip*)(pkt_data + SIZE_ETHERNET);
	size_ip = IP_HL(ip) * 4;
	if (size_ip < 20) {
		cout<<"   * Invalid IP header length: "<< size_ip <<" bytes\n";
		return;
	}

	/* print source and destination IP addresses */
	cout << "From: " << iptos(ip->ip_src) << "  To: " << iptos(ip->ip_dst) << " TTL: " << int(ip->ip_ttl) << " Len: " << ntohs(ip->ip_len);

	/* determine protocol */
	switch (ip->ip_p)
	{
	case IPPROTO_TCP:
		cout<< "  \n Protocol: TCP  ";
		/* define/compute tcp header offset */
		tcp = (struct sniff_tcp*)(pkt_data + SIZE_ETHERNET + size_ip);
		size_tcp = TH_OFF(tcp) * 4;
		if (size_tcp < 20) {
			cout<< "   * Invalid TCP header length: "<< size_tcp <<" bytes\n";
			return;
		}

		cout<<"   Src port: "<< ntohs(tcp->th_sport) << "   Dst port: " << ntohs(tcp->th_dport)<<endl;
		//cout << "  Sec: " << ntohs(tcp->th_seq) << " Ack: " << ntohl(tcp->th_ack) << " Win: "<<ntohs(tcp->th_win) << endl;
		break;
	case IPPROTO_UDP:
		cout << "   \n Protocol: UDP";
		udp = (struct sniff_udp*)(pkt_data + SIZE_ETHERNET + size_ip);
		cout << "   Src port: " << ntohs(udp->sport) << "   Dst port: " << ntohs(udp->dport)<<" Len: "<<ntohs(udp->len) <<endl;
		return;
	case IPPROTO_ICMP:
		cout << "   Protocol: ICMP\n";
		return;
	default:
		cout<<"   Protocol: unknown\n";
		return;
	}
}

// callback function for incoming packets
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	const struct sniff_ethernet* ethernet;  // The ethernet header
	struct tm ltime;
	char timestr[16];
	time_t local_tv_sec;
	static int count = 1;
	
	/* convert the timestamp to readable format */
	local_tv_sec = header->ts.tv_sec;
	localtime_s(&ltime, &local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);

	cout <<dec<< count << ". " << timestr << " dur: " << header->ts.tv_usec << " len: " << header->len ;
	count++;
	
	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(pkt_data);
	switch (ntohs(ethernet->ether_type))
	{
	case ETHERTYPE_IPv4:
		cout << " (IPv4)\n ";
		get_ip(pkt_data);
		break;
	case ETHERTYPE_ARP:
		cout << " (ARP)\n";
		break;
	case ETHERTYPE_REVARP:
		cout << " (RARP)\n";
		break;
	case WIFI:
		cout << " (802.11)\n ";
		break;
	case ETHERTYPE_IPv6:
		cout << " (IPv6)\n";
		break;
	default:
		cout << " (UNKNOWN TYPE)\n";
		break;
	}
	
}

// show info about device
void show_info(pcap_if_t *dev)
{
	char ip6str[128];
	char ntop_buf[INET6_ADDRSTRLEN];
	if (dev->description)
		cout << "\t" << dev->description << "\n";
	else
		cerr << "No description available";

	if (dev->addresses != NULL) {

		switch (dev->addresses->addr->sa_family)
		{
		case AF_INET:
			cout << "\tAddress Family Name: AF_INET(IPv4)\n";
			if (dev->addresses->addr)
				cout << "\tIP: " << iptos(((struct sockaddr_in *)dev->addresses->addr)->sin_addr.S_un.S_addr);
			if (dev->addresses->netmask)
				cout << "\tNetmask:" << iptos(((struct sockaddr_in *)dev->addresses->netmask)->sin_addr.S_un.S_addr);
			break;
		case AF_INET6:
			cout << "\tAddress Family Name: AF_INET6(IPv6)\n";
			if (dev->addresses->addr)
				cout<< "\tIPv6: " << inet_ntop(AF_INET6,((struct sockaddr_in6 *)(dev->addresses->addr))->sin6_addr.s6_addr,ntop_buf, sizeof ntop_buf);	
			break;
		default:
			cout << "\tAddress Family Name: Unknown\n";
			break;
		}
	}
}

// open device for sniffing
void open_dev(pcap_if_t *alldevs,int counter,char *errbuf)
{
	pcap_if_t *dev;
	pcap_t *adhandle;
	int dev_num;

	// choose device
	cout << "Enter interface number \t";
	cin >> dev_num;

	if (dev_num < 1 || dev_num > counter) // if incorrect number
	{
		cerr << "\nInterface number out of range.\n";
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return ;
	}

	for (dev = alldevs, counter = 0; counter < dev_num - 1; dev = dev->next, counter++);// choose entered  device

	if ((adhandle = pcap_open_live(dev->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, errbuf)) != NULL)
	{
		if (dev->addresses->addr->sa_family == AF_INET) // for ipv4 
		{
			cout << "Listening on: \t";
			show_info(dev);
			cout << endl;
		}
		else  // for ipv6 
		{
			cout << "Listening on: \t";
			show_info(dev);
			cout << endl;
		}
		pcap_freealldevs(alldevs);
		pcap_loop(adhandle, 0, packet_handler, NULL);
		return;
	}
	else
	{
		cerr << "Unable to open the device" << dev->name;
		pcap_freealldevs(alldevs);
		return ;
	}
}

// print list of devices
void print_dev_list(pcap_if_t *alldevs, char *errbuf )
{
	pcap_if_t *dev;
	int counter = 0;
	for (dev = alldevs; dev != NULL; dev = dev->next)
	{

		cout << ++counter << ". " << dev->name;
		show_info(dev);
		cout << "\n";
	}
	if (counter == 0)
	{
		cerr << "No interfaces found! Make sure Npcap is installed.";
		return ;
	}
	open_dev(alldevs, counter, errbuf);//open our device
	return;
	
}

int main(int argc, char *argv[])
{
	pcap_if_t *alldevs;
	char errbuf[PCAP_ERRBUF_SIZE]; // 256
	
	//serch device on local machine 
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		cerr << "Error in pcap_findalldevs_ex:" << errbuf;
		return -1;
	}

	// print all devices
	print_dev_list(alldevs, errbuf);
	pcap_freealldevs(alldevs);
}