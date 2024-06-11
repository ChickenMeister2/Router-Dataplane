#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <arpa/inet.h>
#include <string.h>

struct route_table_entry rtable[MAX_SIZE];
int rtable_len;

struct arp_table_entry mac_table[MAX_SIZE];
int mac_table_len;

/*	Functie de comparare pentru qsort
	Comparam prefixele si mastile in ordine crescatoare
	Primul criteriu de comparare este prefixul
	Daca prefixele sunt egale, comparam mastile
	Daca prefixul nu este egal comparam prefixele
*/

int rtable_compare(const void *first, const void *second)
{
	uint32_t hostPrefix1 = ntohl(((const struct route_table_entry *)first)->prefix);
	uint32_t hostPrefix2 = ntohl(((const struct route_table_entry *)second)->prefix);
	uint32_t hostMask1 = ntohl(((const struct route_table_entry *)first)->mask);
	uint32_t hostMask2 = ntohl(((const struct route_table_entry *)second)->mask);

	if (hostPrefix1 == hostPrefix2)
	{
		if (hostMask1 == hostMask2)
		{
			return 0;
		} else {
			if(hostMask1 > hostMask2)
				return 1;
			else
				return -1;
		}
	} else {
		if(hostPrefix1 > hostPrefix2)
			return 1;
		else
			return -1;
	}
}

//	Functie de cautare binara a celei mai bune rute
struct route_table_entry *get_best_route(uint32_t ip_dest)
{
	int left = 0, right = rtable_len - 1;
	struct route_table_entry *candidate = NULL;

	while (left <= right) {
		int mid = left + (right - left) / 2;
		if (rtable[mid].prefix == (ip_dest & rtable[mid].mask)) {
			candidate = &rtable[mid];
			left = mid + 1;
		}
		if (ntohl(rtable[mid].prefix) > ntohl(ip_dest)) {
			right = mid - 1;
		} else {
			left = mid + 1;
		}
	}

 	return candidate;
 }

// Functie de parsare a tabelei ARP
struct arp_table_entry *get_mac_entry(uint32_t given_ip)
{
	for (int i = 0; i < mac_table_len; i++)
	{
		if (given_ip == mac_table[i].ip)
			return &mac_table[i];
	}

		return NULL;
}

// Functie care se ocupa de icmp
void icmp(struct iphdr *ipHeader, struct ether_header *ethHeader, uint8_t type, int interface)
{
	uint16_t len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);
	char *buf = malloc(len);
	DIE(buf == NULL, "malloc");

	struct ether_header *newEthHeader = (struct ether_header *) buf;
	struct iphdr *newIpHeader = (struct iphdr *)(buf + sizeof(struct ether_header));
	struct icmphdr *icmpHeader = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));

	memcpy(newEthHeader->ether_dhost, ethHeader->ether_shost, ETH_ALEN);
	get_interface_mac(interface, newEthHeader->ether_shost);
	newEthHeader->ether_type = htons(ETHERTYPE_IP);

	newIpHeader->version = 4;
	newIpHeader->ihl = 5;
	newIpHeader->tos = 0;
	newIpHeader->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
	newIpHeader->id = htons(0);
	newIpHeader->frag_off = 0;
	newIpHeader->ttl = 64;
	newIpHeader->protocol = IPPROTO_ICMP;
	newIpHeader->saddr = inet_addr(get_interface_ip(interface));
	newIpHeader->daddr = ipHeader->saddr;
	newIpHeader->check = 0;
	newIpHeader->check = htons(checksum((uint16_t *)newIpHeader, sizeof(struct iphdr)));

	icmpHeader->type = type;
	icmpHeader->code = 0;
	icmpHeader->checksum = 0;
	icmpHeader->un.echo.id = htons(0);
	icmpHeader->un.echo.sequence = htons(0);
	icmpHeader->checksum = htons(checksum((uint16_t *)icmpHeader, sizeof(struct icmphdr)));

	send_to_link(interface, buf, len);
	free(buf);
}



int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	rtable_len = read_rtable(argv[1], rtable);
	mac_table_len = parse_arp_table("arp_table.txt", mac_table);

	// Do not modify this line
	init(argc - 2, argv + 2);

	// Sortam tabela de rutare pentru cautarea binara
	qsort(rtable, rtable_len, sizeof(struct route_table_entry), rtable_compare);

	while (1) {

		int interface;
		size_t len;
		
		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *ethHeader = (struct ether_header *) buf;
		struct iphdr *ipHeader = (struct iphdr *)(buf + sizeof(struct ether_header));             
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */

		if (ethHeader->ether_type != ntohs(0x0800)) {
			printf("Ignored non-IPv4 packet\n");
			continue;
		}

		if(checksum((uint16_t *)ipHeader, sizeof(struct iphdr)) != 0) {
			printf("Ignored corrupt packet\n");
			continue;
		}

		struct route_table_entry *best_route = get_best_route(ipHeader->daddr);

		if(ipHeader->daddr == inet_addr(get_interface_ip(interface))) { 
			icmp(ipHeader, ethHeader, ECHO_REPLY, interface);
			continue;
		}

		if (best_route == NULL) {
			icmp(ipHeader, ethHeader, DEST_UNREACHABLE, interface);
			continue;
		}

		if (ipHeader->ttl <= 1) {
			icmp(ipHeader, ethHeader, TTL_EXPIRED, interface);
			continue;
		}

		ipHeader->ttl -= 1;
		ipHeader->check = 0;
		ipHeader->check = htons(checksum((uint16_t *)ipHeader, sizeof(struct iphdr)));

		struct arp_table_entry *destination = get_mac_entry(best_route->next_hop);

		if (destination == NULL) {
			printf("Ignored packet, no MAC entry found\n");
			continue;
		}

		memcpy(ethHeader->ether_dhost, destination->mac, ETH_ALEN);

		get_interface_mac(best_route->interface, ethHeader->ether_shost);

		send_to_link(best_route->interface, buf, len);

	}
}



