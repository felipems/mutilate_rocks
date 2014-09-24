// -*- c++-mode -*-
#ifndef CONNECTION_H
#define CONNECTION_H

#include <queue>
#include <string>

#include <event2/bufferevent.h>
#include <event2/dns.h>
#include <event2/event.h>
#include <event2/util.h>

#include "AdaptiveSampler.h"
#include "cmdline.h"
#include "ConnectionOptions.h"
#include "ConnectionStats.h"
#include "Generator.h"
#include "Operation.h"
#include "util.h"

#include "Protocol.h"

using namespace std;

class Connection;
class Protocol;

enum read_state_enum {
  INIT_READ,
  CONN_SETUP,
  LOADING,
  IDLE,
  WAITING_FOR_GET,
  WAITING_FOR_SET,
  MAX_READ_STATE,
};

enum write_state_enum {
  INIT_WRITE,
  ISSUING,
  WAITING_FOR_TIME,
  WAITING_FOR_OPQ,
  MAX_WRITE_STATE,
};

typedef struct {
    unsigned int          id;
    string                host;
    string                port;
    Connection*           conn;
    Protocol*             prot;
    struct bufferevent*   bev;
    std::queue<Operation> op_queue;
    read_state_enum       read_state;
    write_state_enum      write_state;
} server_t;

void bev_event_cb(struct bufferevent *bev, short events, void *ptr);
void bev_read_cb(struct bufferevent *bev, void *ptr);
void bev_write_cb(struct bufferevent *bev, void *ptr);
void timer_cb(evutil_socket_t fd, short what, void *ptr);

class Connection {
public:
  Connection(struct event_base* _base, struct evdns_base* _evdns,
             options_t options, string host, bool sampling = true);
  ~Connection();

  double start_time; // Time when this connection began operations.
  ConnectionStats stats;
  options_t options;

  bool is_ready();
  void set_priority(int pri);
  void set_leader(unsigned int id);
  unsigned int get_leader();

  // state commands
  void start() { drive_write_machine(leader); }
  void start_loading();
  void reset();
  bool check_exit_condition(double now = 0.0);

  // event callbacks
  void event_callback(server_t* serv, short events);
  void read_callback(server_t* serv);
  void write_callback();
  void timer_callback();

private:
  vector<server_t> servers;
  server_t* leader;

  struct event_base *base;
  struct evdns_base *evdns;

  struct event *timer; // Used to control inter-transmission time.
  double next_time;    // Inter-transmission time parameters.
  double last_rx;      // Used to moderate transmission rate.
  double last_tx;

  // Parameters to track progress of the data loader.
  int loader_issued, loader_completed;

  Generator *valuesize;
  Generator *keysize;
  KeyGenerator *keygen;
  Generator *iagen;

  // server functions
  server_t parse_hoststring(string s);
  void connect_server(server_t &serv);

  // state machine functions / event processing
  void pop_op(server_t* serv);
  void finish_op(server_t* serv, Operation *op);
  void issue_something(server_t* serv, double now = 0.0);
  void drive_write_machine(server_t* serv, double now = 0.0);

  // request functions
  void issue_get(server_t* serv, const char* key, double now = 0.0);
  void issue_set(server_t* serv, const char* key, const char* value,
                 int length, double now = 0.0);
};

#endif
