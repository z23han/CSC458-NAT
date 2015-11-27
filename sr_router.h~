/*-----------------------------------------------------------------------------
 * File: sr_router.h
 * Date: ?
 * Authors: Guido Apenzeller, Martin Casado, Virkam V.
 * Contact: casado@stanford.edu
 *
 *---------------------------------------------------------------------------*/

#ifndef SR_ROUTER_H
#define SR_ROUTER_H

#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>

#include "sr_protocol.h"
#include "sr_arpcache.h"

/* we dont like this debug , but what to do for varargs ? */
#ifdef _DEBUG_
#define Debug(x, args...) printf(x, ## args)
#define DebugMAC(x) \
  do { int ivyl; for(ivyl=0; ivyl<5; ivyl++) printf("%02x:", \
  (unsigned char)(x[ivyl])); printf("%02x",(unsigned char)(x[5])); } while (0)
#else
#define Debug(x, args...) do{}while(0)
#define DebugMAC(x) do{}while(0)
#endif

#define INIT_TTL 255
#define PACKET_DUMP_SIZE 1024
#define ETHER_PACKET_LEN sizeof(sr_ethernet_hdr_t)
#define IP_PACKET_LEN sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)
#define ARP_PACKET_LEN sizeof(sr_ethernet_hdr_t)+sizeof(sr_arp_hdr_t)
#define ICMP_PACKET_LEN sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_hdr_t)
#define ICMP_T3_PACKET_LEN sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t3_hdr_t)


/* forward declare */
struct sr_if;
struct sr_rt;

/* ----------------------------------------------------------------------------
 * struct sr_instance
 *
 * Encapsulation of the state for a single virtual router.
 *
 * -------------------------------------------------------------------------- */

struct sr_instance
{
    int  sockfd;   /* socket to server */
    char user[32]; /* user name */
    char host[32]; /* host name */ 
    char template[30]; /* template name if any */
    unsigned short topo_id;
    struct sockaddr_in sr_addr; /* address to server */
    struct sr_if* if_list; /* list of interfaces */
    struct sr_rt* routing_table; /* routing table */
    struct sr_arpcache cache;   /* ARP cache */
    pthread_attr_t attr;
    FILE* logfile;
};

/* -- sr_main.c -- */
int sr_verify_routing_table(struct sr_instance* sr);

/* -- sr_vns_comm.c -- */
int sr_send_packet(struct sr_instance* , uint8_t* , unsigned int , const char*);
int sr_connect_to_server(struct sr_instance* ,unsigned short , char* );
int sr_read_from_server(struct sr_instance* );

/* -- sr_router.c -- */
void sr_init(struct sr_instance* sr);
void sr_handlepacket(struct sr_instance* sr, uint8_t *packet, unsigned int len, char* interface);
void sr_handle_arppacket(struct sr_instance* sr, uint8_t *packet, unsigned int len, char* interface);
void sr_handle_ippacket(struct sr_instance* sr, uint8_t *packet, unsigned int len, char* interface);
sr_ethernet_hdr_t *get_eth_hdr(uint8_t *packet);
sr_arp_hdr_t * get_arp_hdr(uint8_t *packet);
sr_ip_hdr_t *get_ip_hdr(uint8_t *packet);
sr_icmp_hdr_t *get_icmp_hdr(uint8_t *packet);
void create_ethernet_hdr(sr_ethernet_hdr_t *eth_hdr, sr_ethernet_hdr_t *new_eth_hdr, struct sr_if *sr_iface);
void create_back_arp_hdr(sr_arp_hdr_t *arp_hdr, sr_arp_hdr_t *new_arp_hdr, struct sr_if *sr_iface);
void create_echo_ip_hdr(sr_ip_hdr_t *ip_hdr, sr_ip_hdr_t *new_ip_hdr, struct sr_if *sr_iface);
void create_icmp_hdr(sr_icmp_hdr_t *icmp_hdr, sr_icmp_hdr_t *new_icmp_hdr, unsigned int len);
void create_icmp_t3_hdr(sr_ip_hdr_t *ip_hdr, sr_icmp_t3_hdr_t *icmp_t3_hdr, uint8_t icmp_type, uint8_t icmp_code);
int check_min_length(unsigned int len, unsigned int packet_len);
int verify_checksum(void *_data, int len, uint16_t packet_cksum);
struct sr_rt *sr_lpm(struct sr_instance *sr, uint32_t ip_dst);
void send_arp_req_packet_broadcast(struct sr_instance *sr, char * out_iface, uint32_t dest_ip);
struct sr_if *sr_get_router_if(struct sr_instance *sr, uint32_t ip);

/* -- sr_if.c -- */
void sr_add_interface(struct sr_instance* , const char* );
void sr_set_ether_ip(struct sr_instance* , uint32_t );
void sr_set_ether_addr(struct sr_instance* , const unsigned char* );
void sr_print_if_list(struct sr_instance* );

#endif /* SR_ROUTER_H */
