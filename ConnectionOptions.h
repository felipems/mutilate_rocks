#ifndef CONNECTIONOPTIONS_H
#define CONNECTIONOPTIONS_H

#include "distributions.h"

typedef struct {
  int    connections;
  bool   blocking;
  double lambda;
  int    qps;
  int    records;

  bool etcd;
  bool binary;
  bool sasl;
  char username[32];
  char password[32];

  char keysize[32];
  char valuesize[32];
  char ia[32];

  double update;
  int    time;
  bool   loadonly;
  int    depth;
  bool   no_nodelay;
  bool   noload;
  int    threads;
  enum   distribution_t iadist;
  int    warmup;
  bool   skip;
  bool   linear;
  int    reserve;

  bool roundrobin;
  int  server_given;
  int  lambda_denom;

  bool moderate;
} options_t;

#endif // CONNECTIONOPTIONS_H
