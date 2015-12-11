
#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include <unistd.h>
#include <time.h>
#include <stdlib.h>
#include "sr_router.h"

int sr_nat_init(struct sr_instance *sr, struct sr_nat *nat) { /* Initializes the nat */

  assert(nat);

  /* Acquire mutex lock */
  pthread_mutexattr_init(&(nat->attr));
  pthread_mutexattr_settype(&(nat->attr), PTHREAD_MUTEX_RECURSIVE);
  int success = pthread_mutex_init(&(nat->lock), &(nat->attr));

  /* Initialize timeout thread */

  pthread_attr_init(&(nat->thread_attr));
  pthread_attr_setdetachstate(&(nat->thread_attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_create(&(nat->thread), &(nat->thread_attr), sr_nat_timeout, sr);

  /* CAREFUL MODIFYING CODE ABOVE THIS LINE! */

  nat->mappings = NULL;
  /* Initialize any variables here */
  nat->port_counter = MIN_PORT;
  nat->identifier_counter = MIN_ICMP_IDENTIFIER;
	nat->unsolicited_packet = NULL;

  return success;
}


int sr_nat_destroy(struct sr_nat *nat) {  /* Destroys the nat (free memory) */

  pthread_mutex_lock(&(nat->lock));

  /* free nat memory here */

  pthread_kill(nat->thread, SIGKILL);
  return pthread_mutex_destroy(&(nat->lock)) &&
    pthread_mutexattr_destroy(&(nat->attr));

}

void *sr_nat_timeout(void *sr_ptr) {  /* Periodic Timout handling */
	struct sr_instance *sr = (struct sr_instance *)sr_ptr;
  struct sr_nat *nat = sr->nat;
  while (1) {
    sleep(1.0);
    pthread_mutex_lock(&(nat->lock));

    /* handle periodic tasks here */
	time_t curtime = time(NULL);

	struct sr_tcp_unsolicited_packet *my_pkt = nat->unsolicited_packet;
	/* if my_pkt is NULL, finish! */
	if (my_pkt == NULL) {
		pthread_mutex_unlock(&(nat->lock));
	}
	else {
        /* get the next packet */
        struct sr_tcp_unsolicited_packet *next_pkt = my_pkt->next;

        /* if next pkt is NULL, only check my_pkt */
        if (next_pkt == NULL) {
            time_t pkt_time = my_pkt->time_updated;

            /* if the time difference is bigger than 6 seconds */
            if (difftime(curtime, pkt_time) >= 6) {
                /* get all the headers */
                uint8_t *packet = my_pkt->buf;
                sr_ethernet_hdr_t *eth_hdr = get_eth_hdr(packet);
                sr_ip_hdr_t *ip_hdr = get_ip_hdr(packet);

                /* create a new icmp t3 port unreachable */
                int packet_len = ICMP_T3_PACKET_LEN;
                uint8_t *icmp_t3_hdr = (uint8_t *)malloc(packet_len);
                /* create ethernet header */
                sr_ethernet_hdr_t *new_eth_hdr = (sr_ethernet_hdr_t *)icmp_t3_hdr;
                memcpy(new_eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
                memcpy(new_eth_hdr->ether_shost, eth_hdr->ether_dhost, ETHER_ADDR_LEN);
                /* create ip header */
                sr_ip_hdr_t *new_ip_hdr = (sr_ip_hdr_t *)((char *)icmp_t3_hdr + ETHER_PACKET_LEN);
                new_ip_hdr->ip_hl = ip_hdr->ip_hl;          /* header length */
                new_ip_hdr->ip_v = ip_hdr->ip_v;            /* header version */
                new_ip_hdr->ip_tos = ip_hdr->ip_tos;        /* type of service */
                new_ip_hdr->ip_len = htons(56);             /* total length */
                new_ip_hdr->ip_id = 0;              /* identification */
                new_ip_hdr->ip_off = htons(0b0100000000000000);        /* fragment offset field */
                new_ip_hdr->ip_ttl = 64;                    /* time to live */
                new_ip_hdr->ip_p = ip_protocol_icmp;            /* protocol */
                new_ip_hdr->ip_src =  ip_hdr->ip_dst;       /* source address */
                new_ip_hdr->ip_dst = ip_hdr->ip_src;        /* dest address */
                new_ip_hdr->ip_sum = 0;
                new_ip_hdr->ip_sum = cksum(new_ip_hdr, sizeof(sr_ip_hdr_t));;   /* checksum */
                /* create icmp t3 header */
                sr_icmp_t3_hdr_t *new_icmp_t3_hdr = (sr_icmp_t3_hdr_t *)((char *)icmp_t3_hdr + IP_PACKET_LEN);
                new_icmp_t3_hdr->icmp_type = htons(3);
                new_icmp_t3_hdr->icmp_code = htons(3);
                new_icmp_t3_hdr->unused = 0;
                new_icmp_t3_hdr->next_mtu = 0;
                memcpy(new_icmp_t3_hdr->data, new_ip_hdr, ICMP_DATA_SIZE); 
                new_icmp_t3_hdr->icmp_sum = 0;
                new_icmp_t3_hdr->icmp_sum = cksum(new_icmp_t3_hdr, sizeof(sr_icmp_t3_hdr_t));

                struct sr_if *out_iface = sr_get_router_if(sr, ip_hdr->ip_dst);

				sr_send_packet(sr, icmp_t3_hdr, packet_len, out_iface->name);

                /* set unsolicited_packet to be NULL */
                nat->unsolicited_packet = NULL;
            }
            pthread_mutex_unlock(&(nat->lock));
        }
        /* otherwise we need to loop through the packets */
        else {
            while (next_pkt != NULL) {

                time_t pkt_time = my_pkt->time_updated;

                /* if the time difference is bigger than 6 seconds */
                if (difftime(curtime, pkt_time) >= 6) {
                    /* get all the headers */
                    uint8_t *packet = my_pkt->buf;
                    sr_ethernet_hdr_t *eth_hdr = get_eth_hdr(packet);
                    sr_ip_hdr_t *ip_hdr = get_ip_hdr(packet);

                    /* create a new icmp t3 port unreachable */
                    int packet_len = ICMP_T3_PACKET_LEN;
                    uint8_t *icmp_t3_hdr = (uint8_t *)malloc(packet_len);
                    /* create ethernet header */
                    sr_ethernet_hdr_t *new_eth_hdr = (sr_ethernet_hdr_t *)icmp_t3_hdr;
                    memcpy(new_eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
                    memcpy(new_eth_hdr->ether_shost, eth_hdr->ether_dhost, ETHER_ADDR_LEN);
                    /* create ip header */
                    sr_ip_hdr_t *new_ip_hdr = (sr_ip_hdr_t *)((char *)icmp_t3_hdr + ETHER_PACKET_LEN);
                    new_ip_hdr->ip_hl = ip_hdr->ip_hl;          /* header length */
                    new_ip_hdr->ip_v = ip_hdr->ip_v;            /* header version */
                    new_ip_hdr->ip_tos = ip_hdr->ip_tos;        /* type of service */
                    new_ip_hdr->ip_len = htons(56);             /* total length */
                    new_ip_hdr->ip_id = 0;              /* identification */
                    new_ip_hdr->ip_off = htons(0b0100000000000000);        /* fragment offset field */
                    new_ip_hdr->ip_ttl = 64;                    /* time to live */
                    new_ip_hdr->ip_p = ip_protocol_icmp;            /* protocol */
                    new_ip_hdr->ip_src =  ip_hdr->ip_dst;       /* source address */
                    new_ip_hdr->ip_dst = ip_hdr->ip_src;        /* dest address */
                    new_ip_hdr->ip_sum = 0;
                    new_ip_hdr->ip_sum = cksum(new_ip_hdr, sizeof(sr_ip_hdr_t));;   /* checksum */
                    /* create icmp t3 header */
                    sr_icmp_t3_hdr_t *new_icmp_t3_hdr = (sr_icmp_t3_hdr_t *)((char *)icmp_t3_hdr + IP_PACKET_LEN);
                    new_icmp_t3_hdr->icmp_type = htons(3);
                    new_icmp_t3_hdr->icmp_code = htons(3);
                    new_icmp_t3_hdr->unused = 0;
                    new_icmp_t3_hdr->next_mtu = 0;
                    memcpy(new_icmp_t3_hdr->data, new_ip_hdr, ICMP_DATA_SIZE); 
                    new_icmp_t3_hdr->icmp_sum = 0;
                    new_icmp_t3_hdr->icmp_sum = cksum(new_icmp_t3_hdr, sizeof(sr_icmp_t3_hdr_t));

                    struct sr_if *out_iface = sr_get_router_if(sr, ip_hdr->ip_dst);

					sr_send_packet(sr, icmp_t3_hdr, packet_len, out_iface->name);

                    /* unlist the my_pkt */
                    if (my_pkt == nat->unsolicited_packet) {
                        nat->unsolicited_packet = next_pkt;
                        my_pkt = next_pkt;
                        next_pkt = next_pkt->next;
                    } else {
                        my_pkt = next_pkt;
                        next_pkt = next_pkt->next;
                    }
                }
            }
            pthread_mutex_unlock(&(nat->lock));
        }
	}
  }
  return NULL;
}

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy */
  struct sr_nat_mapping *copy = nat->mappings;

  while (copy != NULL) {
    if ((copy->aux_ext == aux_ext) && (copy->type == type)) {
        break;
    }
    copy = copy->next;
  }

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy. */
  struct sr_nat_mapping *copy = nat->mappings;

  while (copy != NULL) {
      if ((copy->ip_int == ip_int) && (copy->aux_int == aux_int) 
        && (copy->type == type)) {
          break;
      }
      copy = copy->next;
  }

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Insert a new mapping into the nat's mapping table.
   Actually returns a copy to the new mapping, for thread safety.
 */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle insert here, create a mapping, and then return a copy of it */
  struct sr_nat_mapping *currMapping = nat->mappings;
  if (currMapping == NULL) {
    currMapping = (struct sr_nat_mapping *)malloc(sizeof(struct sr_nat_mapping));
    currMapping->type = type;
    currMapping->ip_int = ip_int;
    currMapping->ip_ext = 0;
    currMapping->aux_int = aux_int;
    currMapping->aux_ext = 0;
    currMapping->last_updated = time(NULL);
    currMapping->conns = NULL;
    currMapping->next = NULL;
    nat->mappings = currMapping;

    pthread_mutex_unlock(&(nat->lock));
    return currMapping;
  }

  struct sr_nat_mapping *nextMapping = currMapping->next;

  while (nextMapping != NULL) {
    currMapping = nextMapping;
    nextMapping = currMapping->next;
  }

  nextMapping = (struct sr_nat_mapping *)malloc(sizeof(struct sr_nat_mapping));
  nextMapping->type = type;
  nextMapping->ip_int = ip_int;
  nextMapping->ip_ext = 0;
  nextMapping->aux_int = aux_int;
  nextMapping->aux_ext = 0;
  nextMapping->last_updated = time(NULL);
  nextMapping->conns = NULL;
  nextMapping->next = NULL;
  currMapping->next = nextMapping;

  pthread_mutex_unlock(&(nat->lock));
  return nextMapping;
}


/* Generate a unique ICMP identifier */
int generate_icmp_identifier(struct sr_nat *nat) {

    pthread_mutex_lock(&(nat->lock));

    uint16_t identifier = nat->identifier_counter;
    nat->identifier_counter ++;

    pthread_mutex_unlock(&(nat->lock));
    return identifier;
}


/* generate a unique port */
int generate_port(struct sr_nat *nat) {

    pthread_mutex_lock(&(nat->lock));

    uint16_t port = nat->port_counter;
    nat->port_counter ++;

    pthread_mutex_unlock(&(nat->lock));
    return port;
}


/* Get the connection associated with all the parameters */
struct sr_nat_connection *sr_nat_lookup_tcp_con(struct sr_nat *nat, struct sr_nat_mapping *copy,  
    uint32_t ip_server, uint16_t port_server) {

    pthread_mutex_lock(&(nat->lock));

    struct sr_nat_mapping *currMapping = nat->mappings;

    /* find the mapping */
    while (currMapping != NULL) {
        if (currMapping->ip_int == copy->ip_int && currMapping->aux_int == copy->aux_int && currMapping->ip_ext == copy->ip_ext 
            && currMapping->aux_ext == copy->aux_ext && currMapping->type == nat_mapping_tcp) {

            struct sr_nat_connection *currConn = currMapping->conns;

            /* find the connection */
            while (currConn) {
                if (currConn->ip_server == ip_server && currConn->port_server == port_server) {
                    pthread_mutex_unlock(&(nat->lock));
                    return currConn;
                }
                currConn = currConn->next;
            }
            break;
        }
        currMapping = currMapping->next;
    }
    pthread_mutex_unlock(&(nat->lock));

    return NULL;
}


/* insert a new connection associated with all the parameters */
struct sr_nat_connection *sr_nat_insert_tcp_con(struct sr_nat *nat, struct sr_nat_mapping *copy, uint32_t ip_server, 
    uint16_t port_server) {

    pthread_mutex_lock(&(nat->lock));

    struct sr_nat_mapping *currMapping = nat->mappings;

	/* create a new connection */
    struct sr_nat_connection *newConn = (struct sr_nat_connection *)malloc(sizeof(struct sr_nat_connection));
	assert(newConn != NULL);

    while (currMapping) {
        if (currMapping->ip_int == copy->ip_int && currMapping->aux_int == copy->aux_int && currMapping->ip_ext == copy->ip_ext 
            && currMapping->aux_ext == copy->aux_ext && currMapping->type == nat_mapping_tcp) {
            
            /* modify all the parameters */
            newConn->ip_server = ip_server;
            newConn->port_server = port_server;
            newConn->isn_client = -1;
            newConn->isn_server = -1;
            newConn->last_updated = time(NULL);
            newConn->tcp_state = CLOSED;

            /* add the new connection to the mapping */
            newConn->next = currMapping->conns;
            currMapping->conns = newConn;
            break;
        }
        currMapping = currMapping->next;
    }

    pthread_mutex_unlock(&(nat->lock));
    
    return newConn;
}


/* Destroy nat tcp connection */
void destroy_tcp_conn(struct sr_nat *nat, struct sr_nat_mapping *copy, struct sr_nat_connection *conn) {
    pthread_mutex_lock(&(nat->lock));

    struct sr_nat_mapping *currMapping = nat->mappings;

    while (currMapping) {
        if (currMapping->ip_int == copy->ip_int && currMapping->aux_int == copy->aux_int 
            && currMapping->aux_int == copy->aux_int && currMapping->aux_ext == copy->aux_ext 
            && currMapping->type == copy->type) {
            
            struct sr_nat_connection *currConn = currMapping->conns;
            /* if the mapping has no connection */
            if (currConn == NULL) {
                pthread_mutex_unlock(&(nat->lock));
                return;
            }
            /* if the head of the connection is copy */
            if (currConn->ip_server == conn->ip_server && currConn->port_server == conn->port_server) {
                currMapping->conns = currConn->next;
                free(currConn);
                pthread_mutex_unlock(&(nat->lock));
                return;
            }

            struct sr_nat_connection *nextConn = currConn->next;

            /* else loop through until we find the connection */
            while (nextConn) {
                if (nextConn->ip_server == conn->ip_server && nextConn->port_server == conn->port_server) {
                    currConn->next = nextConn->next;
                    free(nextConn);
                    pthread_mutex_unlock(&(nat->lock));
                    return;
                }
                currConn = nextConn;
                nextConn = nextConn->next;
            }

            break;
        }
    }

    pthread_mutex_unlock(&(nat->lock));
    return;

}


struct sr_tcp_unsolicited_packet *sr_nat_unsolicited_queue(struct sr_nat *nat, uint8_t *packet, unsigned int packet_len) {
    pthread_mutex_lock(&(nat->lock));
    
	/* get ethernet header, ip header, tcp header */
	/*sr_ethernet_hdr_t *eth_hdr = get_eth_hdr(packet);*/
	sr_ip_hdr_t *ip_hdr = get_ip_hdr(packet);
	sr_tcp_hdr_t *tcp_hdr = get_tcp_hdr(packet);

    struct sr_tcp_unsolicited_packet *my_pkt = NULL;

	int found = 0;

    for (my_pkt = nat->unsolicited_packet; my_pkt != NULL; my_pkt = my_pkt->next) {

		/*sr_ethernet_hdr_t *my_pkt_eth_hdr = get_eth_hdr(my_pkt->buf);*/
		sr_ip_hdr_t *my_pkt_ip_hdr = get_ip_hdr(my_pkt->buf);
		sr_tcp_hdr_t *my_pkt_tcp_hdr = get_tcp_hdr(my_pkt->buf);
		
		/* check if the ip_src/dst and src/dst_port match */
		if (ip_hdr->ip_src == my_pkt_ip_hdr->ip_src && ip_hdr->ip_dst == my_pkt_ip_hdr->ip_dst 
		&& tcp_hdr->src_port == my_pkt_tcp_hdr->src_port && tcp_hdr->dst_port == my_pkt_tcp_hdr->dst_port) {
			found = 1;
			break;
		}
    }
    
    /* If the packet wasn't found, add it */
    if (found == 0) {
		struct sr_tcp_unsolicited_packet *new_pkt = (struct sr_tcp_unsolicited_packet *)malloc(sizeof(struct sr_tcp_unsolicited_packet));
		new_pkt->buf = (uint8_t *)malloc(packet_len);
		memcpy(new_pkt->buf, packet, packet_len);
		new_pkt->len = packet_len;
		new_pkt->time_updated = time(NULL);
		new_pkt->next = nat->unsolicited_packet;
		nat->unsolicited_packet = new_pkt;
		
		pthread_mutex_unlock(&(nat->lock));
		return new_pkt;
    }
    
    pthread_mutex_unlock(&(nat->lock));

	return my_pkt;

}


