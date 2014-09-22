#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <event2/bufferevent.h>

#include "log.h"
#include "util.h"

void sleep_time(double duration) {
  if (duration > 0) usleep((useconds_t) (duration * 1000000));
}

#define FNV_64_PRIME (0x100000001b3ULL)
#define FNV1_64_INIT (0xcbf29ce484222325ULL)
uint64_t fnv_64_buf(const void* buf, size_t len) {
  uint64_t hval = FNV1_64_INIT;

  unsigned char *bp = (unsigned char *)buf;   /* start of buffer */
  unsigned char *be = bp + len;               /* beyond end of buffer */

  while (bp < be) {
    hval ^= (uint64_t)*bp++;
    hval *= FNV_64_PRIME;
  }

  return hval;
}

void generate_key(int n, int length, char *buf) {
  snprintf(buf, length + 1, "%0*d", length, n);
}

/**
 * Convert a hostname into an IP address.
 */
string name_to_ipaddr(string host) {
  void *ptr = NULL;
  char ipaddr[16];
  struct evutil_addrinfo hints;
  struct evutil_addrinfo* answer = NULL;
  int err;

  /* Build the hints to tell getaddrinfo how to act. */
  memset(&hints, 0, sizeof(hints));
  hints.ai_family   = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  hints.ai_flags    = EVUTIL_AI_ADDRCONFIG;

  /* Look up the hostname. */
  err = evutil_getaddrinfo(host.c_str(), NULL, &hints, &answer);
  if (err < 0) {
    DIE("Error while resolving '%s': %s",
        host.c_str(), evutil_gai_strerror(err));
  } else if (answer == NULL) {
    DIE("No DNS answer.");
  }

  switch (answer->ai_family) {
  case AF_INET:
    ptr = &((struct sockaddr_in *) answer->ai_addr)->sin_addr;
    break;
  case AF_INET6:
    ptr = &((struct sockaddr_in6 *) answer->ai_addr)->sin6_addr;
    break;
  }

  inet_ntop (answer->ai_family, ptr, ipaddr, 16);

  D("Resolved %s to %s", host.c_str(), ipaddr);
  return string(ipaddr);
}

