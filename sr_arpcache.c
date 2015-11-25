#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_rt.h"
#include "sr_utils.h"


/*
function handle_arpreq(req):
   if difftime(now, req->sent) > 1.0
       if req->times_sent >= 5:
           send icmp host unreachable to source addr of all pkts waiting
             on this request
           arpreq_destroy(req)
       else:
           send arp request
           req->sent = now
           req->times_sent++
*/
void handle_arpreq(struct sr_arpreq *arp_req, struct sr_instance *sr) {
    /* Get the ARP cache */
/*	fprintf(stderr, "********* handle arp request **************\n"); */
    struct sr_arpcache *cache = &(sr->cache);
    time_t now = time(0);
    if (difftime(now, arp_req->sent) >= 0.9) {
        if (arp_req->times_sent >= 5) {

            /* Get a list of packets on the queue */
            struct sr_packet *packet_walker = arp_req->packets;
			
            while (packet_walker != NULL) {
		
                /* Send icmp host unreachable */
                /* Get the interface of the router */
                struct sr_if *out_if = sr_get_interface(sr, packet_walker->iface);
				if (out_if == NULL) {
					return;
				}
                /* Collect the sender and receiver mac/ip addresses */
                /*unsigned char *sender_mac = out_if->addr;
                uint32_t sender_ip = out_if->ip;*/
                /* get the packet frame in the waiting queue */
                uint8_t *buf = packet_walker->buf;
                uint8_t *receiver_mac = ((sr_ethernet_hdr_t *)buf)->ether_shost;
                uint32_t receiver_ip = ((sr_ip_hdr_t *)((char *)buf+ sizeof(sr_ethernet_hdr_t)))->ip_src;
				/*uint32_t sender = ((sr_ip_hdr_t *)((char *)buf+ sizeof(sr_ethernet_hdr_t)))->ip_dst;*/

				struct sr_rt* longest_pref_match = sr_lpm(sr, receiver_ip);
				struct sr_if *cont_if = sr_get_interface(sr, longest_pref_match->interface);
                
                /* allocated a space for icmp_t3_hdr */
                int packet_len = ICMP_T3_PACKET_LEN;
                uint8_t *icmp_t3_hdr = (uint8_t *)malloc(packet_len);
                /* Create ethernet header */
                sr_ethernet_hdr_t *new_eth_hdr = (sr_ethernet_hdr_t *)icmp_t3_hdr;
                sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)buf;
				memcpy(new_eth_hdr->ether_dhost, receiver_mac, ETHER_ADDR_LEN);
             	/*   memcpy(new_eth_hdr->ether_dhost, receiver_mac, ETHER_ADDR_LEN); */
                memcpy(new_eth_hdr->ether_shost, cont_if->addr, ETHER_ADDR_LEN);
                new_eth_hdr->ether_type = eth_hdr->ether_type;
                /* Create ip header */
                sr_ip_hdr_t *new_ip_hdr = (sr_ip_hdr_t *)((char *)icmp_t3_hdr+ sizeof(sr_ethernet_hdr_t));
                sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)((char *)buf+ sizeof(sr_ethernet_hdr_t));
				new_ip_hdr->ip_hl = ip_hdr->ip_hl;			/* header length */
				new_ip_hdr->ip_v = ip_hdr->ip_v; 			/* header version */
                new_ip_hdr->ip_tos = ip_hdr->ip_tos;
                new_ip_hdr->ip_len = htons(56);
                new_ip_hdr->ip_id = ip_hdr->ip_id;
                new_ip_hdr->ip_off = htons(0b0100000000000000);
                new_ip_hdr->ip_ttl = 64;
                new_ip_hdr->ip_p = ip_protocol_icmp;
                new_ip_hdr->ip_src = cont_if->ip; 
                new_ip_hdr->ip_dst = receiver_ip;
				new_ip_hdr->ip_sum = 0;
                new_ip_hdr->ip_sum = cksum(new_ip_hdr, sizeof(sr_ip_hdr_t));
                /* Create icmp type 3 header */
                sr_icmp_t3_hdr_t *new_icmp_hdr = (sr_icmp_t3_hdr_t *)((char *)icmp_t3_hdr + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
                new_icmp_hdr->icmp_type = 3;
                new_icmp_hdr->icmp_code = 1;
                new_icmp_hdr->unused = 0;
                new_icmp_hdr->next_mtu = 0;
                memcpy(new_icmp_hdr->data, ip_hdr, ICMP_DATA_SIZE);
				new_icmp_hdr->icmp_sum = 0;
                new_icmp_hdr->icmp_sum = cksum(new_icmp_hdr, sizeof(sr_icmp_t3_hdr_t));
				
				struct sr_arpentry *arp_entry = sr_arpcache_lookup(cache, receiver_ip);
				if (arp_entry != NULL) {
					sr_send_packet(sr, icmp_t3_hdr, packet_len, longest_pref_match->interface);
					free(icmp_t3_hdr);
				} else {
					struct sr_arpreq *arp_req_1 = sr_arpcache_queuereq(cache, receiver_ip, icmp_t3_hdr, packet_len, longest_pref_match->interface);
					handle_arpreq(arp_req_1, sr);
				}
                /* Send icmp type 3 packet */
         		/* sr_send_packet(sr, icmp_t3_hdr, packet_len, longest_pref_match->interface);*/
				/* printf("---------------- Host unreachable -----------------\n"); */
				packet_walker = packet_walker->next;
            }
            sr_arpreq_destroy(cache, arp_req); 
        } else {
            /* send arp request */
            send_arp_req_packet_broadcast(sr, (arp_req->packets)->iface, arp_req->ip);
            arp_req->sent = now; /* current time */
            arp_req->times_sent++;
        }
    }
    return;
}


/* Handle arp reply
The ARP reply processing code should move entries from the ARP request queue to the ARP cache
 */
void handle_arpreply(sr_arp_hdr_t *arp_hdr, struct sr_instance* sr) {

    /* Get the ARP cache */
    struct sr_arpcache *cache = &(sr->cache);
    /* When servicing an arp reply that gives us an IP->MAC mapping, 
        they are all from arp_hdr sender part
    */
    struct sr_arpreq *arp_req = sr_arpcache_insert(cache, arp_hdr->ar_sha, arp_hdr->ar_sip);
    /* if req:
       send all packets on the req->packets linked list
       arpreq_destroy(req)
     */
    if (arp_req) {
        fprintf(stderr, "********** Received ARP reply\n");
        /* Get the list of packets root node waiting on the req queue */
        struct sr_packet *packet_walker = arp_req->packets;

        while (packet_walker) {
            /* Get the raw ethernet frame */
            uint8_t *buf = packet_walker->buf;
            unsigned int length = packet_walker->len;
            /* we only need to update the mac sender address in the ethernet header part  */
            sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)buf;
			/* Get the interface from the router */
			struct sr_if *out_if = sr_get_interface(sr, packet_walker->iface);
			unsigned char *sender_mac = out_if->addr;
			/* Change the sender mac address to be the router address */
            memcpy(eth_hdr->ether_shost, sender_mac, ETHER_ADDR_LEN);
			/* Change the receiver mac address to be the arp source address, which is the sender of the arp reply */
			memcpy(eth_hdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
			print_hdrs(buf, length);
            sr_send_packet(sr, buf, length, out_if->name);
            packet_walker = packet_walker->next;
        }
        sr_arpreq_destroy(cache, arp_req);
    }
    return;
}

/* 
  This function gets called every second. For each request sent out, we keep
  checking whether we should resend an request or destroy the arp request.
  See the comments in the header file for an idea of what it should look like.
*/
/*
void sr_arpcache_sweepreqs(struct sr_instance *sr) {
   for each request on sr->cache.requests:
       handle_arpreq(request)
   }
*/
void sr_arpcache_sweepreqs(struct sr_instance *sr) { 
    /* Fill this in */
    struct sr_arpreq *arp_req = sr->cache.requests;
    struct sr_arpreq *arp_req_next = NULL;
    while (arp_req != NULL) {
		arp_req_next = arp_req->next;
        handle_arpreq(arp_req, sr);
		arp_req = arp_req_next;
    }
    return;
}

/* You should not need to touch the rest of this code. */

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order.
   You must free the returned structure if it is not NULL. */
struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip) {
   printf("start lookup\n");   
    pthread_mutex_lock(&(cache->lock));
     printf("start lookup get lock\n");  
    struct sr_arpentry *entry = NULL, *copy = NULL;
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if ((cache->entries[i].valid) && (cache->entries[i].ip == ip)) {
            entry = &(cache->entries[i]);
        }
    }
    
    /* Must return a copy b/c another thread could jump in and modify
       table after we return. */
    if (entry) {
        copy = (struct sr_arpentry *) malloc(sizeof(struct sr_arpentry));
        memcpy(copy, entry, sizeof(struct sr_arpentry));
    }
        
    pthread_mutex_unlock(&(cache->lock));
   printf("end lookup\n");   
    return copy;
}

/* Adds an ARP request to the ARP request queue. If the request is already on
   the queue, adds the packet to the linked list of packets for this sr_arpreq
   that corresponds to this ARP request. You should free the passed *packet.
   
   A pointer to the ARP request is returned; it should not be freed. The caller
   can remove the ARP request from the queue by calling sr_arpreq_destroy. */
struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache,
                                       uint32_t ip,
                                       uint8_t *packet,           /* borrowed */
                                       unsigned int packet_len,
                                       char *iface)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            break;
        }
    }
    
    /* If the IP wasn't found, add it */
    if (!req) {
        req = (struct sr_arpreq *) calloc(1, sizeof(struct sr_arpreq));
        req->ip = ip;
        req->next = cache->requests;
        cache->requests = req;
    }
    
    /* Add the packet to the list of packets for this request */
    if (packet && packet_len && iface) {
        struct sr_packet *new_pkt = (struct sr_packet *)malloc(sizeof(struct sr_packet));
        
        new_pkt->buf = (uint8_t *)malloc(packet_len);
        memcpy(new_pkt->buf, packet, packet_len);
        new_pkt->len = packet_len;
		new_pkt->iface = (char *)malloc(sr_IFACE_NAMELEN);
        strncpy(new_pkt->iface, iface, sr_IFACE_NAMELEN);
        new_pkt->next = req->packets;
        req->packets = new_pkt;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* This method performs two functions:
   1) Looks up this IP in the request queue. If it is found, returns a pointer
      to the sr_arpreq with this IP. Otherwise, returns NULL.
   2) Inserts this IP to MAC mapping in the cache, and marks it valid. */
struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache,
                                     unsigned char *mac,
                                     uint32_t ip)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req, *prev = NULL, *next = NULL; 
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {            
            if (prev) {
                next = req->next;
                prev->next = next;
            } 
            else {
                next = req->next;
                cache->requests = next;
            }
            
            break;
        }
        prev = req;
    }
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if (!(cache->entries[i].valid))
            break;
    }
    
    if (i != SR_ARPCACHE_SZ) {
        memcpy(cache->entries[i].mac, mac, 6);
        cache->entries[i].ip = ip;
        cache->entries[i].added = time(NULL);
        cache->entries[i].valid = 1;
    }
    
    pthread_mutex_unlock(&(cache->lock));
  
    return req;
}

/* Frees all memory associated with this arp request entry. If this arp request
   entry is on the arp request queue, it is removed from the queue. */
void sr_arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry) {
    pthread_mutex_lock(&(cache->lock));
    
    if (entry) {
        struct sr_arpreq *req, *prev = NULL, *next = NULL; 
        for (req = cache->requests; req != NULL; req = req->next) {
            if (req == entry) {                
                if (prev) {
                    next = req->next;
                    prev->next = next;
                } 
                else {
                    next = req->next;
                    cache->requests = next;
                }
                
                break;
            }
            prev = req;
        }
        
        struct sr_packet *pkt, *nxt;
        
        for (pkt = entry->packets; pkt; pkt = nxt) {
            nxt = pkt->next;
            if (pkt->buf)
                free(pkt->buf);
            if (pkt->iface)
                free(pkt->iface);
            free(pkt);
        }
        
        free(entry);
    }
   
    pthread_mutex_unlock(&(cache->lock));
}

/* Prints out the ARP table. */
void sr_arpcache_dump(struct sr_arpcache *cache) {
    fprintf(stderr, "\nMAC            IP         ADDED                      VALID\n");
    fprintf(stderr, "-----------------------------------------------------------\n");
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        struct sr_arpentry *cur = &(cache->entries[i]);
        unsigned char *mac = cur->mac;
        fprintf(stderr, "%.1x%.1x%.1x%.1x%.1x%.1x   %.8x   %.24s   %d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ntohl(cur->ip), ctime(&(cur->added)), cur->valid);
    }
    
    fprintf(stderr, "\n");
}

/* Initialize table + table lock. Returns 0 on success. */
int sr_arpcache_init(struct sr_arpcache *cache) {  
    /* Seed RNG to kick out a random entry if all entries full. */
    srand(time(NULL));
    
    /* Invalidate all entries */
    memset(cache->entries, 0, sizeof(cache->entries));
    cache->requests = NULL;
    
    /* Acquire mutex lock */
    pthread_mutexattr_init(&(cache->attr));
    pthread_mutexattr_settype(&(cache->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(cache->lock), &(cache->attr));
    
    return success;
}

/* Destroys table + table lock. Returns 0 on success. */
int sr_arpcache_destroy(struct sr_arpcache *cache) {
    return pthread_mutex_destroy(&(cache->lock)) && pthread_mutexattr_destroy(&(cache->attr));
}

/* Thread which sweeps through the cache and invalidates entries that were added
   more than SR_ARPCACHE_TO seconds ago. */
void *sr_arpcache_timeout(void *sr_ptr) {
    struct sr_instance *sr = sr_ptr;
    struct sr_arpcache *cache = &(sr->cache);
    
    while (1) {
        sleep(1.0);
        
        pthread_mutex_lock(&(cache->lock));
        time_t curtime = time(NULL);
        
        int i;    
        for (i = 0; i < SR_ARPCACHE_SZ; i++) {
            if ((cache->entries[i].valid) && (difftime(curtime,cache->entries[i].added) > SR_ARPCACHE_TO)) {
                cache->entries[i].valid = 0;
            }
        }
        
        sr_arpcache_sweepreqs(sr);

        pthread_mutex_unlock(&(cache->lock));
    }
    
    return NULL;
}


