
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
