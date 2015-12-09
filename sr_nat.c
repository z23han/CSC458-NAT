
#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include <unistd.h>
#include <time.h>
#include <stdlib.h>

int sr_nat_init(struct sr_nat *nat) { /* Initializes the nat */

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
  pthread_create(&(nat->thread), &(nat->thread_attr), sr_nat_timeout, nat);

  /* CAREFUL MODIFYING CODE ABOVE THIS LINE! */

  nat->mappings = NULL;
  /* Initialize any variables here */
  nat->port_counter = MIN_PORT;
  nat->identifier_counter = MIN_ICMP_IDENTIFIER;

  return success;
}


int sr_nat_destroy(struct sr_nat *nat) {  /* Destroys the nat (free memory) */

  pthread_mutex_lock(&(nat->lock));

  /* free nat memory here */

  pthread_kill(nat->thread, SIGKILL);
  return pthread_mutex_destroy(&(nat->lock)) &&
    pthread_mutexattr_destroy(&(nat->attr));

}

void *sr_nat_timeout(void *nat_ptr) {  /* Periodic Timout handling */
  struct sr_nat *nat = (struct sr_nat *)nat_ptr;
  while (1) {
    sleep(1.0);
    pthread_mutex_lock(&(nat->lock));

    /*time_t curtime = time(NULL);*/

    /* handle periodic tasks here */

    pthread_mutex_unlock(&(nat->lock));
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
