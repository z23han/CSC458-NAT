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
#include <string.h>
#include <stdlib.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"


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


    /* copy into a new packet for better handling :) */
    uint8_t *packet1 = packet;

    printf("*** -> Received packet of length %d \n",len);

    /* sanity-check the packet (meets min length) */
    if (!check_min_length(len, ETHER_PACKET_LEN)) {
        fprintf(stderr, "packet length is smaller the ethernet size. Drop it!\n");
        return;
    }

    uint16_t eth_type = ethertype(packet1);

    /* ARP REQUEST & REPLY */
    if (eth_type == ethertype_arp) {
        sr_handle_arppacket(sr, packet1, len, interface);
        return;
    }
    /* IP REQUEST & REPLY */
    else if (eth_type == ethertype_ip) {
        sr_handle_ippacket(sr, packet1, len, interface);
        return;
    }
    /* OTHERWISE, DROP!!! */
    else {
        fprintf(stderr, "Invalid ethernet type, drop the packet!\n");
        return;
    }

    return;

}/* end sr_ForwardPacket */


/* handle/generate ARP packet */
void sr_handle_arppacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */) 
{
    assert(sr);
    assert(packet);
    assert(interface);

    /* Get ethernet header */
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)get_eth_hdr(packet);
	if (eth_hdr == NULL) {
		printf("ethernet header NULL!!!\n");
		return;
	}

    /* Get arp header */
    sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)get_arp_hdr(packet);
	if (arp_hdr == NULL) {
		printf("arp header NULL!!!\n");
		return;
	}

    /* Check the arp packet minimum length */
    if (!check_min_length(len, ARP_PACKET_LEN)) {
        fprintf(stderr, "arp packet length is not enough:(\n");
        return;
    }

    /* check the opcode to see if it is request or reply */
    unsigned short ar_op = ntohs(arp_hdr->ar_op);
    /* Get the connected interface in the router */
    struct sr_if *sr_con_if = sr_get_interface(sr, interface);
	/* Get the detination interface in the router */
	/*struct sr_if *sr_iface = sr_get_router_if(sr, arp_hdr->ar_tip);*/
	
	/* If the connected interface exists, because arp has to be the connected interface */
    if (sr_con_if) {
        /* ********** ARP request ********** */
        /* Construct an arp reply and send it back */
        if (ar_op == arp_op_request) {
            /*fprintf(stderr, "********** ARP REQUEST **********\n");  ar_op = 1 */
            /* Set the back-packet length */
            int packet_len = ARP_PACKET_LEN;
            uint8_t *arp_reply_hdr = (uint8_t *)malloc(packet_len);

            /* Create ethernet header */
            create_ethernet_hdr(eth_hdr, (sr_ethernet_hdr_t *)arp_reply_hdr, sr_con_if);

            /* Create arp header */
            create_back_arp_hdr(arp_hdr, (sr_arp_hdr_t *)((unsigned char *)arp_reply_hdr+ETHER_PACKET_LEN), sr_con_if);

            /* Send APR reply */
            sr_send_packet(sr, /*(sr_ethernet_hdr_t *)*/arp_reply_hdr, packet_len, sr_con_if->name);
            free(arp_reply_hdr);
            return;
        }
        /* ********** ARP reply ********** */
        /* Cache it, go thru my request queue and send outstanding packets */
        else if (ar_op == arp_op_reply) {
            /*fprintf(stderr, "********** ARP REPLY **********\n");   ar_op = 2 */
            /* cache first, and send all the packets in the queue with ip->mac mapping!!! */
            handle_arpreply(arp_hdr, sr);
            return;
        }
        /* ********** Otherwise, error! ********** */
        else {
            fprintf(stderr, "Invalid arp type!!!\n");
            return;
        }
    } else {
        fprintf(stderr, "Router doesnt have this interface, drop it!\n");
        return;
    }
    
    return;
}


/* Handle IP packet */
void sr_handle_ippacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */) 
{
    assert(sr);
    assert(packet);
    assert(interface);

    /* Get ethernet header */
    sr_ethernet_hdr_t *eth_hdr = get_eth_hdr(packet);
	if (eth_hdr == NULL) {
		printf("ethernet header NULL!!!\n");
		return;
	}

    /* Get ip header */
    sr_ip_hdr_t *ip_hdr = get_ip_hdr(packet);
	if (ip_hdr == NULL) {
		printf("ip header NULL!!!\n");
		return;
	}

	/* Before doing ttl decrement, check checksum */
	uint16_t old_ip_sum = ip_hdr->ip_sum;
	ip_hdr->ip_sum = 0;

	if (!verify_checksum(ip_hdr, sizeof(sr_ip_hdr_t), old_ip_sum)) {
		fprintf(stderr, "CHECKSUM FAILED!!\n");
		return;
	}
	ip_hdr->ip_sum = old_ip_sum;

	ip_hdr->ip_ttl--;

	/* recompute the packet checksum over the modified header */
	ip_hdr->ip_sum = 0;
	uint16_t new_ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
	ip_hdr->ip_sum = new_ip_sum;

    /* Get the arp cache */
    struct sr_arpcache *sr_arp_cache = &sr->cache;

    /* Get the destination interface on the router */
	struct sr_if *sr_iface = sr_get_router_if(sr, ip_hdr->ip_dst);
	/* Get the connected interface on the router */
	struct sr_if *sr_con_if = sr_get_interface(sr, interface);

    /* Check the time exceeded condition, if ttl==0, we need to form icmp 11 and send back */
    if (ip_hdr->ip_ttl <= 0) {
        /* time exceeded message and icmp type 11 */
        printf("TTL time exceeded\n");
        int packet_len = ICMP_T3_PACKET_LEN;
        uint8_t *icmp_t3_hdr = (uint8_t *)malloc(packet_len);

        create_ethernet_hdr(eth_hdr, (sr_ethernet_hdr_t *)icmp_t3_hdr, sr_con_if);
        /* Create ip header */
        create_echo_ip_hdr(ip_hdr, (sr_ip_hdr_t *)((char *)icmp_t3_hdr+ETHER_PACKET_LEN), sr_con_if);

        /* Send icmp type 11 time exceeded */
        /* icmp_t3 type=11, code=0 */
        create_icmp_t3_hdr(ip_hdr, (sr_icmp_t3_hdr_t *)((char *)icmp_t3_hdr+IP_PACKET_LEN), 11, 0);

        /* Send icmp type 11 packet */
		struct sr_arpentry *arp_entry = sr_arpcache_lookup(sr_arp_cache, ip_hdr->ip_src);
		if (arp_entry != NULL) {
			sr_send_packet(sr, icmp_t3_hdr, packet_len, sr_con_if->name);
			free(icmp_t3_hdr);
		} else {
			struct sr_arpreq *arp_req = sr_arpcache_queuereq(sr_arp_cache, ip_hdr->ip_src, icmp_t3_hdr, packet_len, sr_con_if->name);
			handle_arpreq(arp_req, sr);
		}
        return;
    }

    /* Get the protocol from IP */
    uint8_t ip_p = ip_hdr->ip_p;

    /* If the packet is sent to self, meaning the ip is sent to the router */
    if (sr_iface) {
        /* Check the protocol if it is icmp */
        if (ip_p == ip_protocol_icmp) {
            /* Get the icmp header */
            sr_icmp_hdr_t *icmp_hdr = get_icmp_hdr(packet);

            /* Check if it is ICMP echo request */
            /* icmp_echo_req = 8 */
            if (icmp_hdr->icmp_type == 8) {
				/* Do LPM on the routing table */
        		/* Check the routing table and see if the incoming ip matches the routing table ip, and find LPM router entry */
        		struct sr_rt *longest_pref_match = sr_lpm(sr, ip_hdr->ip_src);

				if (longest_pref_match) {
					/* check ARP cache */
					/*struct sr_arpentry *arp_entry = sr_arpcache_lookup(sr_arp_cache, ip_hdr->ip_src);*/
					struct sr_arpentry *arp_entry = sr_arpcache_lookup(&sr->cache, longest_pref_match->gw.s_addr); /* ip_hdr->ip_dst */

					/* If hit, meaning the arp mapping has been cached */
					if (arp_entry != NULL) {
						/* We need to send the icmp echo reply */
				        /* Modify ethernet header */
						memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
						memcpy(eth_hdr->ether_shost, sr_con_if->addr, ETHER_ADDR_LEN);

				        /* Modify ip header */
						ip_hdr->ip_off = htons(0b0100000000000000);        /* fragment offset field */
						ip_hdr->ip_ttl = 100;                    			/* time to live */
						/* source and destination should be altered */
						uint32_t temp = ip_hdr->ip_src;
						ip_hdr->ip_src = ip_hdr->ip_dst;        /* source address */
						ip_hdr->ip_dst = temp;        			/* dest address */
						ip_hdr->ip_sum = 0;
						uint16_t new_ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
						ip_hdr->ip_sum = new_ip_sum;			/* checksum */

				        /* Modify icmp header */
						unsigned int icmp_whole_size = len - IP_PACKET_LEN;
						icmp_hdr->icmp_type = 0;
						/* code and checksum should be the same */
						icmp_hdr->icmp_code = 0;
						/* we need to check the checksum */
						icmp_hdr->icmp_sum = 0;
						icmp_hdr->icmp_sum = cksum(icmp_hdr, icmp_whole_size);

				        /* Send icmp echo reply */
				        sr_send_packet(sr, packet, len, sr_con_if->name);
				        return;
					}
					/* Else no hit, we cache it to the queue and send arp request */ 
					else {
						/* Add reply to the ARP queue */
						/* We need to send the icmp echo reply */
				        /* Modify ethernet header */
						memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
						memcpy(eth_hdr->ether_shost, sr_con_if->addr, ETHER_ADDR_LEN);

				        /* Modify ip header */
						ip_hdr->ip_off = htons(0b0100000000000000);        /* fragment offset field */
						ip_hdr->ip_ttl = 100;                    			/* time to live */
						/* source and destination should be altered */
						uint32_t temp = ip_hdr->ip_src;
						ip_hdr->ip_src = ip_hdr->ip_dst;        /* source address */
						ip_hdr->ip_dst = temp;        			/* dest address */
						ip_hdr->ip_sum = 0;
						uint16_t new_ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
						ip_hdr->ip_sum = new_ip_sum;			/* checksum */

				        /* Modify icmp header */
						unsigned int icmp_whole_size = len - IP_PACKET_LEN;
						icmp_hdr->icmp_type = 0;
						/* code and checksum should be the same */
						icmp_hdr->icmp_code = 0;
						/* we need to check the checksum */
						icmp_hdr->icmp_sum = 0;
						icmp_hdr->icmp_sum = cksum(icmp_hdr, icmp_whole_size);
						struct sr_arpreq *arp_req = sr_arpcache_queuereq(sr_arp_cache, ip_hdr->ip_dst, packet, len, sr_con_if->name);
						/* Send ARP request, which is a broadcast */
						handle_arpreq(arp_req, sr);
						return;
					}
				} else {
					fprintf(stderr, "Longest prefix doesnt match!!\n");
                	return;
				}

            } else {
                fprintf(stderr, "Not an ICMP request!\n");
                return;
            }
        }
        /* Else it is TCP/UDP request */
        else {
            fprintf(stderr, "*** -> Received TCP/UDP!\n");

			/* Do LPM on the routing table */
    		/* Check the routing table and see if the incoming ip matches the routing table ip, and find LPM router entry */
    		struct sr_rt *longest_pref_match = sr_lpm(sr, ip_hdr->ip_src);

			if (longest_pref_match) {
				/* check ARP cache */
				/*struct sr_arpentry *arp_entry = sr_arpcache_lookup(sr_arp_cache, ip_hdr->ip_src);*/
				struct sr_arpentry *arp_entry = sr_arpcache_lookup(&sr->cache, longest_pref_match->gw.s_addr); /* ip_hdr->ip_dst */
				
				/* Send ICMP port unreachable */
				/*struct sr_arpentry *arp_entry = sr_arpcache_lookup(sr_arp_cache, ip_hdr->ip_src);*/
				if (arp_entry != NULL) {

					int packet_len = ICMP_T3_PACKET_LEN;
				    uint8_t *icmp_t3_hdr = (uint8_t *)malloc(packet_len);

				    /* Create ethernet header */
				    create_ethernet_hdr(eth_hdr, (sr_ethernet_hdr_t *)icmp_t3_hdr, sr_con_if);

				    /* Create ip header */
				    create_echo_ip_hdr(ip_hdr, (sr_ip_hdr_t *)((char *)icmp_t3_hdr+ETHER_PACKET_LEN), sr_con_if);

					/* Should update source address to be interface address */

				    /* Send icmp type 3 port unreachable */
				    /* Create icmp port unreachable packet */
				    /* icmp_t3 type=3, code=3 */
				    create_icmp_t3_hdr(ip_hdr, (sr_icmp_t3_hdr_t *)((char *)icmp_t3_hdr+IP_PACKET_LEN), 3, 3);

				    /* Send icmp type 3 packet */
				    sr_send_packet(sr, icmp_t3_hdr, packet_len, sr_con_if->name);

				    free(icmp_t3_hdr);
				    return;
				} else {
				
					int packet_len = ICMP_T3_PACKET_LEN;
				    uint8_t *icmp_t3_hdr = (uint8_t *)malloc(packet_len);

				    /* Create ethernet header */
				    create_ethernet_hdr(eth_hdr, (sr_ethernet_hdr_t *)icmp_t3_hdr, sr_con_if);

				    /* Create ip header */
				    create_echo_ip_hdr(ip_hdr, (sr_ip_hdr_t *)((char *)icmp_t3_hdr+ETHER_PACKET_LEN), sr_con_if);

				    /* Send icmp type 3 port unreachable */
				    /* Create icmp port unreachable packet */
				    /* icmp_t3 type=3, code=3 */
				    create_icmp_t3_hdr(ip_hdr, (sr_icmp_t3_hdr_t *)((char *)icmp_t3_hdr+IP_PACKET_LEN), 3, 3);

					struct sr_arpreq *arp_req = sr_arpcache_queuereq(sr_arp_cache, ip_hdr->ip_src, icmp_t3_hdr, packet_len, sr_con_if->name);
					/* Send ARP request, which is a broadcast */
					handle_arpreq(arp_req, sr);
					return;
				}
			} else {
				fprintf(stderr, "Longest prefix doesnt match!!\n");
                return;
			}            
            
        }
    }
    /* Else Check the routing table, perfomr LPM */
    else {
        /* Sanity-check the packet */
        /* minimum length */
        if (!check_min_length(len, IP_PACKET_LEN)) {
            fprintf(stderr, "The packet length is not enough:(\n");
            return;
        }
		
        /* Do LPM on the routing table */
        /* Check the routing table and see if the incoming ip matches the routing table ip, and find LPM router entry */
        struct sr_rt *longest_pref_match = sr_lpm(sr, ip_hdr->ip_dst);
        if (longest_pref_match) {
			/*fprintf(stderr, "********* Get the longest prefix match *********\n");*/
            /* check ARP cache */
            struct sr_if *out_if = sr_get_interface(sr, longest_pref_match->interface);
			/*print_addr_ip_int(longest_pref_match->gw.s_addr);*/

            struct sr_arpentry *arp_entry = sr_arpcache_lookup(&sr->cache, longest_pref_match->gw.s_addr); /* ip_hdr->ip_dst */
         
			/* If hit, meaning the arp_entry is found */
            if (arp_entry) {

				/*fprintf(stderr, "************ found the lpm router entry ***********\n");*/
                /* Send frame to next hop */
                /* update the eth_hdr source and destination ethernet address */
                /* use next_hop_ip->mac mapping in the entry to send the packet */
                memcpy(eth_hdr->ether_shost, out_if->addr, ETHER_ADDR_LEN);
                memcpy(eth_hdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
                sr_send_packet(sr, packet, len, out_if->name);
				printf("Received IP header\n");
				print_hdr_ip((uint8_t*)ip_hdr);
                /* free the entry */
                free(arp_entry);
                return;
            } else/* No Hit */ {
                /* send an ARP request for the next-hop IP */
                /* add the packet to the queue of packets waiting on this ARP request */
                /* Add request to ARP queue*/
                struct sr_arpreq *arp_req = sr_arpcache_queuereq(sr_arp_cache, ip_hdr->ip_dst, packet, len, out_if->name);
                /* send ARP request, this is a broadcast */
                handle_arpreq(arp_req, sr);
                return;
            }
        } else /* if not matched */ {
            /* Send ICMP net unreachable */
			printf("--------------- Net Unreachable ---------------\n");

			/* Do LPM on the routing table */
    		/* Check the routing table and see if the incoming ip matches the routing table ip, and find LPM router entry */
    		struct sr_rt *longest_pref_match = sr_lpm(sr, ip_hdr->ip_src);

			if (longest_pref_match) {
				/* check ARP cache */
				/*struct sr_arpentry *arp_entry = sr_arpcache_lookup(sr_arp_cache, ip_hdr->ip_src);*/
				struct sr_arpentry *arp_entry = sr_arpcache_lookup(&sr->cache, longest_pref_match->gw.s_addr); /* ip_hdr->ip_dst */

				/* struct sr_arpentry *arp_entry = sr_arpcache_lookup(sr_arp_cache, ip_hdr->ip_src); */
				if (arp_entry) {
					int packet_len = ICMP_T3_PACKET_LEN;
				    uint8_t *icmp_t3_hdr = (uint8_t *)malloc(packet_len);

				    /* Create ethernet header */
				    create_ethernet_hdr(eth_hdr, (sr_ethernet_hdr_t *)icmp_t3_hdr, sr_con_if);

				    /* Create ip header */
				    create_echo_ip_hdr(ip_hdr, (sr_ip_hdr_t *)((char *)icmp_t3_hdr+ETHER_PACKET_LEN), sr_con_if);

				    /* Create icmp net unreachable */
				    /* icmp_t3 type=3, code=0 */
				    create_icmp_t3_hdr(ip_hdr, (sr_icmp_t3_hdr_t *)((char *)icmp_t3_hdr+IP_PACKET_LEN), 3, 0);

				    /* Send icmp type 3 packet */
				    sr_send_packet(sr, icmp_t3_hdr, packet_len, sr_con_if->name);

				    free(icmp_t3_hdr);
				    return;
				} else {

					int packet_len = ICMP_T3_PACKET_LEN;
				    uint8_t *icmp_t3_hdr = (uint8_t *)malloc(packet_len);

				    /* Create ethernet header */
				    create_ethernet_hdr(eth_hdr, (sr_ethernet_hdr_t *)icmp_t3_hdr, sr_con_if);

				    /* Create ip header */
				    create_echo_ip_hdr(ip_hdr, (sr_ip_hdr_t *)((char *)icmp_t3_hdr+ETHER_PACKET_LEN), sr_con_if);
					/*	((sr_ip_hdr_t *)((char *)icmp_t3_hdr+ETHER_PACKET_LEN))->ip_ttl += 1; */

				    /* Send icmp type 3 port unreachable */
				    /* Create icmp net unreachable packet */
				    /* icmp_t3 type=3, code=0 */
				    create_icmp_t3_hdr(ip_hdr, (sr_icmp_t3_hdr_t *)((char *)icmp_t3_hdr+IP_PACKET_LEN), 3, 0);

					struct sr_arpreq *arp_req = sr_arpcache_queuereq(sr_arp_cache, ip_hdr->ip_src, icmp_t3_hdr, packet_len, sr_con_if->name);
					/* Send ARP request, which is a broadcast */
					handle_arpreq(arp_req, sr);
					return;
				}
			} else {
				fprintf(stderr, "Longest prefix doesnt match!!\n");
                return;
			}
        }
    }

    return;
}


/* Get the ethernet header */
sr_ethernet_hdr_t *get_eth_hdr(uint8_t *packet) {
    assert(packet);
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)(packet);
    if (!eth_hdr) {
        fprintf(stderr, "Failed to get the ethernet header!\n");
        return NULL;
    } 
    return eth_hdr;
}


/* Get the arp header */
sr_arp_hdr_t * get_arp_hdr(uint8_t *packet) {
    assert(packet);
    sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)((unsigned char *)packet + ETHER_PACKET_LEN);
    if (!arp_hdr) {
        fprintf(stderr, "Failed to get arp header!\n");
        return NULL;
    } 
    return arp_hdr;
}


/* Get IP header */
sr_ip_hdr_t *get_ip_hdr(uint8_t *packet) {
    assert(packet);
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)((unsigned char *)packet + ETHER_PACKET_LEN);
    if (!ip_hdr) {
        fprintf(stderr, "Failed to get ip header!\n");
        return NULL;
    }
    return ip_hdr;
}


/* Get icmp header */
sr_icmp_hdr_t *get_icmp_hdr(uint8_t *packet) {
    assert(packet);
    sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)((unsigned char *)packet + IP_PACKET_LEN);
    if (!icmp_hdr) {
        fprintf(stderr, "Failed to get icmp header!\n");
        return NULL;
    }
    return icmp_hdr;
}


/* Create ethernet header */
void create_ethernet_hdr(sr_ethernet_hdr_t *eth_hdr, sr_ethernet_hdr_t *new_eth_hdr, struct sr_if *sr_iface) {
    assert(eth_hdr);
    assert(new_eth_hdr);
    /* swap the sender and receiver ethernet addresses */
    memcpy(new_eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
    memcpy(new_eth_hdr->ether_shost, sr_iface->addr, ETHER_ADDR_LEN);
    /* type should be the same as the input ethernet */
    new_eth_hdr->ether_type = eth_hdr->ether_type;
    return;
}


/* Create arp header reply back */
void create_back_arp_hdr(sr_arp_hdr_t *arp_hdr, sr_arp_hdr_t *new_arp_hdr, struct sr_if *sr_iface) {
    assert(arp_hdr);
    assert(new_arp_hdr);
    /* these terms should be the same as input arp */
    new_arp_hdr->ar_hrd = arp_hdr->ar_hrd;
    new_arp_hdr->ar_pro = arp_hdr->ar_pro;
    new_arp_hdr->ar_hln = arp_hdr->ar_hln;
    new_arp_hdr->ar_pln = arp_hdr->ar_pln;
    /* here we form the arp opcode as reply */
    new_arp_hdr->ar_op = htons(arp_op_reply);
    /* target ip address is the sender ip */
    new_arp_hdr->ar_tip = arp_hdr->ar_sip;
    /* sender ip address is the router ip */
    new_arp_hdr->ar_sip = sr_iface->ip;
    /* target mac address is the sender mac address */
    memcpy(new_arp_hdr->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
    /* sender mac address is the router mac address */
    memcpy(new_arp_hdr->ar_sha, sr_iface->addr, ETHER_ADDR_LEN);
    return;
}


/* Create echo ip header */
void create_echo_ip_hdr(sr_ip_hdr_t *ip_hdr, sr_ip_hdr_t *new_ip_hdr, struct sr_if *sr_iface) {
    assert(ip_hdr);
    assert(new_ip_hdr);
	new_ip_hdr->ip_hl = ip_hdr->ip_hl;			/* header length */
	new_ip_hdr->ip_v = ip_hdr->ip_v; 			/* header version */
    new_ip_hdr->ip_tos = ip_hdr->ip_tos;        /* type of service */
    new_ip_hdr->ip_len = htons(56); /* ip_hdr->ip_len;         total length */
    new_ip_hdr->ip_id = 0; /*ip_hdr->ip_id;*/          /* identification */
    new_ip_hdr->ip_off = htons(0b0100000000000000);        /* fragment offset field */
    new_ip_hdr->ip_ttl = 64;                    /* time to live */
    new_ip_hdr->ip_p = ip_protocol_icmp;            /* protocol */
    /* source and destination should be altered */
    new_ip_hdr->ip_src =  sr_iface->ip;/* ip_hdr->ip_dst;  */      /* source address */
    new_ip_hdr->ip_dst = ip_hdr->ip_src;        /* dest address */
	new_ip_hdr->ip_sum = 0;
	uint16_t new_ip_sum = cksum(new_ip_hdr, sizeof(sr_ip_hdr_t));
	new_ip_hdr->ip_sum = new_ip_sum;			/* checksum */
    return;
}


/* Create icmp header */
void create_icmp_hdr(sr_icmp_hdr_t *icmp_hdr, sr_icmp_hdr_t *new_icmp_hdr, unsigned int len) {
    assert(icmp_hdr);
    assert(new_icmp_hdr);
    /* here we construct a echo reply icmp */
	unsigned int icmp_whole_size = len - IP_PACKET_LEN;
    new_icmp_hdr->icmp_type = 0;
    /* code and checksum should be the same */
    new_icmp_hdr->icmp_code = 0;
    /* do we need to check the checksum??? */
    new_icmp_hdr->icmp_sum = 0;
    memcpy(new_icmp_hdr+sizeof(sr_icmp_hdr_t), icmp_hdr+sizeof(sr_icmp_hdr_t), icmp_whole_size-sizeof(sr_icmp_hdr_t));
    new_icmp_hdr->icmp_sum = cksum(new_icmp_hdr, icmp_whole_size);
	print_hdr_icmp((uint8_t*)new_icmp_hdr);
    return;
}


/* Create type3 icmp header */
void create_icmp_t3_hdr(sr_ip_hdr_t *ip_hdr, sr_icmp_t3_hdr_t *icmp_t3_hdr, uint8_t icmp_type, uint8_t icmp_code) {
    assert(icmp_t3_hdr);
    /* type here should be 3 actually */
    icmp_t3_hdr->icmp_type = icmp_type;
    /* get the icmp code from the input */
    icmp_t3_hdr->icmp_code = icmp_code;
    icmp_t3_hdr->unused = 0;
    icmp_t3_hdr->next_mtu = 0;
    memcpy(icmp_t3_hdr->data, ip_hdr, ICMP_DATA_SIZE); 
	icmp_t3_hdr->icmp_sum = 0;
    uint16_t checksum = cksum(icmp_t3_hdr, sizeof(sr_icmp_t3_hdr_t));
    icmp_t3_hdr->icmp_sum = checksum;

/*	memcpy(icmp_t3_hdr->data, ip_hdr, sizeof(sr_ip_hdr_t)); */ 
	print_hdr_icmp((uint8_t*)icmp_t3_hdr);
    return;
}


/* Check the checksum */
int verify_checksum(void *_data, int len, uint16_t packet_cksum) {
    if (cksum(_data, len) == packet_cksum) {
        return 1;
    } else {
        fprintf(stderr, "checksum is not correct!\n");
        return 0;
    }
}


/* Check the min length of input packet */
int check_min_length(unsigned int len, unsigned int packet_len) {
    if (len < packet_len) {
        fprintf(stderr, "packet length doesn't satisfy the minimum length requirements!\n");
        return 0;
    } else {
        return 1;
    }
}


/* Find the longest prefix match */
struct sr_rt *sr_lpm(struct sr_instance *sr, uint32_t ip_dst) {
    /* sr_rt is a linkedList until reaching the end */
    struct sr_rt *routing_table = sr->routing_table;
    uint32_t len = 0;
    struct sr_rt *lpm_rt = NULL; /*sr->routing_table;*/

    while (routing_table) {
        if ((ip_dst & routing_table->mask.s_addr) == (routing_table->dest.s_addr & routing_table->mask.s_addr)) {
            if (len < routing_table->mask.s_addr) { /* routing_table->dest.s_addr & routing_table->mask.s_addr) { */
                len = routing_table->mask.s_addr; /*& routing_table->mask.s_addr;*/
                lpm_rt = routing_table;
            }
        }
        routing_table = routing_table->next;
    }
    return lpm_rt;
}


/* Send arp request packet, this is broadcast */
void send_arp_req_packet_broadcast(struct sr_instance *sr, char * out_iface, uint32_t dest_ip) {
    assert(sr);
    assert(out_iface);
    assert(dest_ip);
    /* Get the interface from the router */
	/*fprintf(stderr, "********* send arp request ***********\n");*/
    struct sr_if *out_if = sr_get_interface(sr, out_iface);
    int packet_len = ARP_PACKET_LEN;
    uint8_t *arp_req_hdr = (uint8_t *)malloc(packet_len);
    /* Create ethernet header */
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)arp_req_hdr;
    memcpy(eth_hdr->ether_shost, out_if->addr, ETHER_ADDR_LEN);     /* destination ethernet address */
	int i;
    for (i = 0; i < ETHER_ADDR_LEN; ++i) {                      /* source ethernet address */
        eth_hdr->ether_dhost[i] = 255;          
    }
    eth_hdr->ether_type = htons(ethertype_arp);             /* packet type ID */

    /* Create arp header */
    sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)((char *)arp_req_hdr + ETHER_PACKET_LEN);
    arp_hdr->ar_hrd = htons(arp_hrd_ethernet);      /* format of hardware address   */
    arp_hdr->ar_pro = htons(ethertype_ip);         /* format of protocol address   */
    arp_hdr->ar_hln = ETHER_ADDR_LEN;               /* length of hardware address   */
    arp_hdr->ar_pln = 4;                     		/* length of protocol address   */
    arp_hdr->ar_op = htons(arp_op_request);         /* ARP opcode (command)         */
    /* sender hardware address      */
    memcpy(arp_hdr->ar_sha, out_if->addr, ETHER_ADDR_LEN);
    /* sender IP address            */
    arp_hdr->ar_sip = out_if->ip;
    /* target hardware address      */
    for (i = 0; i < ETHER_ADDR_LEN; ++i) {
        arp_hdr->ar_tha[i] = 255;
    }
    /* target IP address            */
    arp_hdr->ar_tip = dest_ip;
    
    /* Send arp request packet */
    sr_send_packet(sr, arp_req_hdr, packet_len, out_if->name);
	/*printf("************ send arp packet *************\n");*/
    free(arp_req_hdr);
    return;
}


/* get the possible interface from router */
struct sr_if *sr_get_router_if(struct sr_instance *sr, uint32_t ip) {
	assert(sr);
	assert(ip);
	struct sr_if *iface_list = sr->if_list;		/* Get a list of interfaces */
	/* Loop through the interface list until reaching the same ip */
	while (iface_list) {
		if (iface_list->ip == ip) {
			return iface_list;
		}
		iface_list = iface_list->next;
	}
	return NULL;
}


