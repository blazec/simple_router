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
	
	/*
	int version;
	int header_len;
	int type;
	int packet_len;
	int id;
	int offset;
	int ttl;
	int protocol;
	int checksum;
	int src;
	int dest;
	*/
	uint16_t ethtype = ethertype(packet);

	printf("*** -> Received packet of length %d \n",len);
	/*printf("%u \n", packet);*/
	print_hdrs(packet, len);
	/*printf("%s\n", sr.user);*/
	
	if (ethtype == ethertype_arp) {
		handle_arppacket(sr, packet, len, interface);
		/*fprintf(stderr, "ARP!!!!!!!!!!!!!!! \n");*/
	}
	
	sr_print_if_list(sr);
	
	/*  struct sr_if* if_list; list of interfaces */ 
	
	/*
	printf("IP Header: \n");
	printf("\t Version: %d \n", version);
	printf("\t Header Length: %d \n", header_len);
	printf("\t Type of Service: %d \n", type);
	printf("\t Length: %d \n", packet_len);
	printf("\t ID: %d \n", id);
	printf("\t Offset: %d \n", offset);
	printf("\t TTL: %d \n", ttl);
	printf("\t Protocol: %d \n", protocol);
	printf("\t Checksum: %d \n", checksum);
	printf("\t Source: %d \n", src);
	printf("\t Destination: %d \n", dest);
	*/
	
  

  /* fill in code here */

}/* end sr_ForwardPacket */

void handle_arppacket(struct sr_instance* sr,
				uint8_t* packet,
				unsigned int len,
				const char* name) {

	/*sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet);*/
					
	struct sr_if* iface = 0;
	
	/* Create Ethernet header */
	uint8_t* arppckt = (uint8_t *)malloc(len);
	memcpy(arppckt, packet, len);
					
	sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)arppckt;
	memcpy(ehdr->ether_dhost, ehdr->ether_shost,6);
	iface = sr_get_interface(sr, name);
	memcpy(ehdr->ether_shost,iface->addr,6);
	
	/* Create ARP packet */
	uint8_t* arp_with_eth = arppckt + sizeof(sr_ethernet_hdr_t);					
	sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(arp_with_eth);
	
	if (arp_hdr->ar_op == htons(OP_ARP_REQUEST)){
		arp_hdr->ar_op = htons(OP_ARP_REPLY);
		memcpy(arp_hdr->ar_tha, arp_hdr->ar_sha, arp_hdr->ar_hln);
		arp_hdr->ar_tip = arp_hdr->ar_sip;
		memcpy(arp_hdr->ar_sha, iface->addr, arp_hdr->ar_hln);
		arp_hdr->ar_sip = iface->ip;	
	}
	
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
	
	if (sr_send_packet(sr, arppckt, len, name) == -1 ) {
		fprintf(stderr, "CANNOT SEND ARP REPLY \n");
	}
	
	
}

