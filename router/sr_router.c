/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

#define OP_ARP_REQUEST 1
#define OP_ARP_REPLY 2

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
	/* REQUIRES */
	assert(sr);
	assert(packet);
	assert(interface);
	
	struct sr_arpreq *req;
	struct sr_arpcache *cache = &(sr->cache);

	uint16_t ethtype = ethertype(packet);

	printf("*** -> Received packet of length %d \n",len);
	/*printf("%u \n", packet);*/
	print_hdrs(packet, len);
	/*printf("%s\n", sr.user);*/
	
	if (ethtype == ethertype_arp) {

		uint8_t* arp_data = packet +  sizeof(sr_ethernet_hdr_t);
		sr_arp_hdr_t* arp_hdr = (sr_arp_hdr_t *) arp_data;
		if (arp_hdr->ar_op == htons(arp_op_request)){
			send_arpreply(sr, packet, len, interface);
			sr_print_routing_table(sr);
		}
		else if(arp_hdr->ar_op == htons(arp_op_reply)){
			req = sr_arpcache_insert(cache, arp_hdr->ar_sha, arp_hdr->ar_sip);
			struct sr_packet *pkt, *nxt;
        
        	for (pkt = req->packets; pkt; pkt = nxt) {
        		handle_ip(sr, pkt->buf, pkt->len);
            	nxt = pkt->next;
            }
            sr_arpreq_destroy(cache, req);
		}
		
	}
	
	else if (ethtype == ethertype_ip) {

		handle_ip(sr, packet, len);
		
		/*send_arprequest(sr, htonl(3232236033));*/
		print_hdrs(packet, len);
		
	}
	
	else{
		sr_arpcache_dump(&(sr->cache));
	}
	
  

  /* fill in code here */

}/* end sr_ForwardPacket */

void handle_ip(struct sr_instance* sr, 
		uint8_t * packet/* lent */,
        unsigned int len)

{
	struct sr_if* iface = 0;
	char outgoing_iface[sr_IFACE_NAMELEN];
	struct sr_arpcache *cache = &(sr->cache);
	uint8_t* ip_data = packet +  sizeof(sr_ethernet_hdr_t);
	sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(ip_data);

	sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t*) packet;

	iface = sr_get_interface_byip(sr, iphdr->ip_dst);
	if(iface){
		handle_icmp(sr, packet, iface, 0, 0);
		return;
	}

	struct sr_arpentry* entry = sr_arpcache_lookup(cache, iphdr->ip_dst);
	printf("%s\n",sr_longest_prefix_iface(sr, iphdr->ip_dst, &outgoing_iface));
	iface = sr_get_interface(sr, outgoing_iface);

	if(entry){
		memcpy(eth_hdr->ether_dhost, entry->mac, ETHER_ADDR_LEN);
		memcpy(eth_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);

		iphdr->ip_ttl--;
		if(iphdr->ip_ttl==0){
			handle_icmp(sr, packet, iface, 11, 0);
		}
		else{

			iphdr->ip_sum = 0;
			fprintf(stderr, "checksum: %d\n", iphdr->ip_sum);
			iphdr->ip_sum = cksum(iphdr, sizeof(sr_ip_hdr_t));
			fprintf(stderr, "calculated: %d\n", iphdr->ip_sum);
			if (sr_send_packet(sr, packet, len, iface->name) == -1 ) {
				fprintf(stderr, "CANNOT FORWARD IP PACKET \n");
			}
		}
	}
	else{ 
		sr_arpcache_queuereq(cache, iphdr->ip_dst, packet, len, outgoing_iface);
	}
}

void handle_icmp(struct sr_instance* sr, 
				uint8_t * packet, 
				struct sr_if* iface, 
				int type, int code)
{
	unsigned int len=98;

	

	sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t*) packet;
	

	uint8_t* ip_data = packet +  sizeof(sr_ethernet_hdr_t);
	
	/*bzero(eth_hdr->ether_dhost, 6);*/
	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
	memcpy(eth_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
	eth_hdr->ether_type = htons(ethertype_ip);

	/* Create IP packet */
	
	sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t *)(ip_data);

	ip_hdr->ip_ttl = 100;
	ip_hdr->ip_dst = ip_hdr->ip_src;
	ip_hdr->ip_src = iface->ip;
	ip_hdr->ip_sum = cksum(ip_data, sizeof(sr_ip_hdr_t));
	

	uint8_t* icmp_data = packet +  sizeof(sr_ethernet_hdr_t)+  sizeof(sr_ip_hdr_t);
	if(type == 0){
		sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t *)icmp_data;
		icmp_hdr->icmp_type = (uint8_t)0;
		icmp_hdr->icmp_code = (uint8_t)0;
		icmp_hdr->icmp_sum = 0;
		icmp_hdr->icmp_sum = cksum(icmp_data, (len-(sizeof(sr_ethernet_hdr_t)+ sizeof(sr_ip_hdr_t))));
		print_hdr_icmp(icmp_data);
	}
	printf("%s\n", iface->name);
	if (sr_send_packet(sr, packet, len, iface->name) == -1 ) {
				fprintf(stderr, "CANNOT SEND ICMP PACKET \n");
			}

}

void send_arprequest(struct sr_instance* sr, uint32_t ip, char* name)
{
	unsigned int len=42;
	/* Assume MAC address is not found in ARP cache. We are using the next IP hop*/
	struct sr_if* iface = 0;


	iface = sr_get_interface(sr, name);
	uint8_t broadcast_addr[ETHER_ADDR_LEN]  = {255, 255, 255, 255, 255, 255};
	
	uint8_t* arp_packet = (uint8_t*) malloc(len);
	/*memcpy(arp_packet, packet, len);*/
	
	sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t*) arp_packet;
	/*bzero(eth_hdr->ether_dhost, 6);*/
	memcpy(eth_hdr->ether_dhost, broadcast_addr, ETHER_ADDR_LEN);
	memcpy(eth_hdr->ether_shost, iface->addr, 6);
	eth_hdr->ether_type = htons(ethertype_arp);
	
	/* Create ARP packet */
	uint8_t* arp_data = arp_packet +  sizeof(sr_ethernet_hdr_t);
	sr_arp_hdr_t* arp_hdr = (sr_arp_hdr_t *) arp_data;
	
	arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
	arp_hdr->ar_pro = htons(ethertype_ip);
	arp_hdr->ar_hln = (unsigned char) 6;
	arp_hdr->ar_pln = (unsigned char) 4;
	arp_hdr->ar_op = htons(arp_op_request);
	memcpy(arp_hdr->ar_sha, iface->addr, ETHER_ADDR_LEN);
	arp_hdr->ar_sip = iface->ip;
	bzero(arp_hdr->ar_tha, ETHER_ADDR_LEN);
	arp_hdr->ar_tip = ip;
	
	if (sr_send_packet(sr, arp_packet, len, iface->name) == -1 ) {
		fprintf(stderr, "CANNOT SEND ARP REQUEST \n");
	}
	
}

void send_arpreply(struct sr_instance* sr,
				uint8_t* packet,
				unsigned int len,
				const char* name) {

	/*sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet);*/
					
	struct sr_if* iface = 0;
	
	/* Create Ethernet header */
	uint8_t* arp_packet = (uint8_t *)malloc(len);
	memcpy(arp_packet, packet, len);
					
	sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)arp_packet;
	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost,6);
	iface = sr_get_interface(sr, name);
	memcpy(eth_hdr->ether_shost,iface->addr,6);
	
	/* Create ARP packet */
	uint8_t* arp_data = arp_packet + sizeof(sr_ethernet_hdr_t);					
	sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(arp_data);
	
	/*if (arp_hdr->ar_op == htons(OP_ARP_REQUEST)){*/
		arp_hdr->ar_op = htons(OP_ARP_REPLY);
		memcpy(arp_hdr->ar_tha, arp_hdr->ar_sha, arp_hdr->ar_hln);
		arp_hdr->ar_tip = arp_hdr->ar_sip;
		memcpy(arp_hdr->ar_sha, iface->addr, arp_hdr->ar_hln);
		arp_hdr->ar_sip = iface->ip;	
	/*}*/
	printf("IP ADDRESS: %lu \n", ntohl(arp_hdr->ar_tip));
	/*TODO:
		We want to be able to send out an ARP Requset. An ARP Request must be sent out if:
			1. An ARP Request is recevied and the request is looking for an IP address that is not ourself; OR
			2. An IP packet is received and we don't know the next-hop MAC address for that IP packet
	
	*/
					
	/*
	int sr_send_packet(struct sr_instance* sr  borrowed ,
                         uint8_t* buf  borrowed  ,
                         unsigned int len,
                         const char* iface  borrowed )
	*/
	
	if (sr_send_packet(sr, arp_packet, len, name) == -1 ) {
		fprintf(stderr, "CANNOT SEND ARP REPLY \n");
	}
	
	
}

