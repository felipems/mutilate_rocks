#include <netinet/tcp.h>

#include <string>
#include <sstream>
#include <vector>

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/dns.h>
#include <event2/event.h>
#include <event2/thread.h>
#include <event2/util.h>

#include "config.h"

#include "Connection.h"
#include "distributions.h"
#include "Generator.h"
#include "mutilate.h"
#include "binary_protocol.h"
#include "util.h"

/**
 * Create a new connection to a server endpoint.
 */
Connection::Connection(struct event_base* _base, struct evdns_base* _evdns,
                       options_t _options, string hosts, bool sampling) :
  start_time(0), stats(sampling), options(_options), base(_base), evdns(_evdns)
{
  valuesize = createGenerator(options.valuesize);
  keysize = createGenerator(options.keysize);
  keygen = new KeyGenerator(keysize, options.records);

  stringstream ss(hosts);
  string item;
  while (getline(ss, item, '|')) {
    servers.push_back(parse_hoststring(item));
  }

  if (options.lambda <= 0) {
    iagen = createGenerator("0");
  } else {
    D("iagen = createGenerator(%s)", options.ia);
    iagen = createGenerator(options.ia);
    iagen->set_lambda(options.lambda);
  }

  if (sampling && options.reserve > 0) {
    stats.get_sampler.samples.reserve(
      options.reserve * (1 - options.update) + 1);
    stats.set_sampler.samples.reserve(options.reserve * options.update + 1);
  }

  for (auto &s : servers) {
    s.read_state  = INIT_READ;
    s.write_state = INIT_WRITE;
  }

  last_tx = last_rx = 0.0;

  set_leader(1);
  for (server_t &s : servers) {
    connect_server(s);
  }

  timer = evtimer_new(base, timer_cb, this);
}

/**
 * Destroy a connection, performing cleanup.
 */
Connection::~Connection() {
  event_free(timer);
  timer = NULL;

  for (server_t &s : servers) {
    if (s.bev != NULL) bufferevent_free(s.bev);
    if (s.prot != NULL) delete s.prot;
  }

  delete iagen;
  delete keygen;
  delete keysize;
  delete valuesize;
}

/**
 * Check that the connection is ready to go.
 */
bool Connection::is_ready() {
  for (auto &s : servers) {
    if (s.read_state != IDLE) return false;
  }
  return true;
}

/**
 * Connect to the specified server.
 */
void Connection::connect_server(server_t &serv) {
  struct bufferevent* bev;
  Protocol* prot;

  bev = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);
  bufferevent_setcb(bev, bev_read_cb, bev_write_cb, bev_event_cb, &serv);
  bufferevent_enable(bev, EV_READ | EV_WRITE);

  if (options.etcd2) {
    prot = new ProtocolEtcd2(options, serv.id, this, bev);
  } else if (options.etcd) {
    prot = new ProtocolEtcd(options, serv.id, this, bev);
  } else if (options.binary) {
    prot = new ProtocolBinary(options, serv.id, this, bev);
  } else {
    prot = new ProtocolAscii(options, serv.id, this, bev);
  }

  serv.bev  = bev;
  serv.prot = prot;

  if (bufferevent_socket_connect_hostname(bev, evdns, AF_UNSPEC,
                                          serv.host.c_str(),
                                          atoi(serv.port.c_str()))) {
    DIE("bufferevent_socket_connect_hostname()");
  }
}

/**
 * Split host into host:port using strtok().
 */
server_t Connection::parse_hoststring(string s) {
  static int id = 0;
  server_t serv; 
  char *saveptr = NULL; // For reentrant strtok().
  char *s_copy = new char[s.length() + 1];
  strcpy(s_copy, s.c_str());

  char *h_ptr = strtok_r(s_copy, ":", &saveptr);
  char *p_ptr = strtok_r(NULL, ":", &saveptr);
  if (h_ptr == NULL) DIE("strtok(.., \":\") failed to parse %s", s.c_str());

  serv.id   = ++id;
  serv.host = name_to_ipaddr(h_ptr);
  serv.port = p_ptr ? p_ptr : "11211";
  serv.conn = this;
  serv.prot = NULL;
  serv.bev  = NULL;
  delete[] s_copy;

  return serv;
}

/**
 * Set the leader to use for this connection.
 */
void Connection::set_leader(unsigned int id) {
  if (0 < id && id <= servers.size()) {
    leader = &servers[id - 1];
  } else {
    DIE("Leader ID out of range! %d (%d)\n", id, servers.size());
  }
}

/**
 * Return the current leader.
 */
unsigned int Connection::get_leader() {
  return leader->id;
}

/**
 * Reset the connection back to an initial, fresh state.
 */
void Connection::reset() {
  // FIXME: Actually check the connection, drain all bufferevents, drain op_q.
  for (auto &s : servers) {
    assert(s.op_queue.size() == 0);
    s.read_state = IDLE;
    s.write_state = INIT_WRITE;
  }
  evtimer_del(timer);
  stats = ConnectionStats(stats.sampling);
}

/**
 * Set our event processing priority.
 */
void Connection::set_priority(int pri) {
  for (auto &s : servers) {
    if (bufferevent_priority_set(s.bev, pri)) {
      DIE("bufferevent_set_priority(bev, %d) failed", pri);
    }
  }
}

/**
 * Load any required test data onto the server.
 */
void Connection::start_loading() {
  for (auto &s : servers) {
    s.read_state = LOADING;
  }
  loader_issued = loader_completed = 0;

  for (int i = 0; i < LOADER_CHUNK; i++) {
    if (loader_issued >= options.records) break;
    char key[256];
    int index = lrand48() % (1024 * 1024);
    string keystr = keygen->generate(loader_issued);
    strcpy(key, keystr.c_str());
    issue_set(leader, key, &random_char[index], valuesize->generate());
    loader_issued++;
  }
}

/**
 * Issue either a get or set request to the server according to our probability distribution.
 */
void Connection::issue_something(server_t* serv, double now) {
  char key[256];
  // FIXME: generate key distribution here!
  string keystr = keygen->generate(lrand48() % options.records);
  strcpy(key, keystr.c_str());

  if (drand48() < options.update) {
    int index = lrand48() % (1024 * 1024);
    issue_set(serv, key, &random_char[index], valuesize->generate(), now);
  } else {
    issue_get(serv, key, now);
  }
}

/**
 * Issue a get request to the server.
 */
void Connection::issue_get(server_t* serv, const char* key, double now) {
  Operation op;
  int l;

#if HAVE_CLOCK_GETTIME
  op.start_time = get_time_accurate();
#else
  if (now == 0.0) {
#if USE_CACHED_TIME
    struct timeval now_tv;
    event_base_gettimeofday_cached(base, &now_tv);
    op.start_time = tv_to_double(&now_tv);
#else
    op.start_time = get_time();
#endif
  } else {
    op.start_time = now;
  }
#endif

  op.type = Operation::GET;
  serv->op_queue.push(op);

  if (serv->read_state == IDLE) serv->read_state = WAITING_FOR_GET;
  l = serv->prot->get_request(key);
  if (serv->read_state != LOADING) stats.tx_bytes += l;
}

/**
 * Issue a set request to the server.
 */
void Connection::issue_set(server_t* serv, const char* key, const char* value,
                           int length, double now) {
  Operation op;
  int l;

#if HAVE_CLOCK_GETTIME
  op.start_time = get_time_accurate();
#else
  if (now == 0.0) op.start_time = get_time();
  else op.start_time = now;
#endif

  op.type = Operation::SET;
  serv->op_queue.push(op);

  if (serv->read_state == IDLE) serv->read_state = WAITING_FOR_SET;
  l = serv->prot->set_request(key, value, length);
  if (serv->read_state != LOADING) stats.tx_bytes += l;
}

/**
 * Return the oldest live operation in progress.
 */
void Connection::pop_op(server_t* serv) {
  assert(serv->op_queue.size() > 0);

  serv->op_queue.pop();

  if (serv->read_state == LOADING) return;
  serv->read_state = IDLE;

  // Advance the read state machine.
  if (serv->op_queue.size() > 0) {
    Operation& op = serv->op_queue.front();
    switch (op.type) {
    case Operation::GET: serv->read_state = WAITING_FOR_GET; break;
    case Operation::SET: serv->read_state = WAITING_FOR_SET; break;
    default: DIE("Not implemented.");
    }
  }
}

/**
 * Finish up (record stats) an operation that just returned from the
 * server.
 */
void Connection::finish_op(server_t* serv, Operation *op) {
  double now;
#if USE_CACHED_TIME
  struct timeval now_tv;
  event_base_gettimeofday_cached(base, &now_tv);
  now = tv_to_double(&now_tv);
#else
  now = get_time();
#endif
#if HAVE_CLOCK_GETTIME
  op->end_time = get_time_accurate();
#else
  op->end_time = now;
#endif

  switch (op->type) {
  case Operation::GET: stats.log_get(*op); break;
  case Operation::SET: stats.log_set(*op); break;
  default: DIE("Not implemented.");
  }

  last_rx = now;
  pop_op(serv);
  drive_write_machine(leader);
}

/**
 * Check if our testing is done and we should exit.
 */
bool Connection::check_exit_condition(double now) {
  bool connected = true;
  bool idle = true;

  for (auto &s : servers) {
    if (s.read_state == INIT_READ) connected = false;
    if (s.read_state != IDLE) idle = false;
  }

  if (!connected) return false;
  if (now == 0.0) now = get_time();
  if (now > start_time + options.time) return true;
  if (options.loadonly && idle) return true;
  return false;
}

/**
 * Handle new connection and error events.
 */
void Connection::event_callback(server_t* serv, short events) {
  if (events & BEV_EVENT_CONNECTED) {
    D("Connected to %s:%s.\n", serv->host.c_str(), serv->port.c_str());
    int fd = bufferevent_getfd(serv->bev);
    if (fd < 0) DIE("bufferevent_getfd\n");

    if (!options.no_nodelay) {
      int one = 1;
      if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY,
                     (void *) &one, sizeof(one)) < 0)
        DIE("setsockopt()\n");
    }

    serv->read_state = CONN_SETUP;
    if (serv->prot->setup_connection_w()) {
      serv->read_state = IDLE;
    }

  } else if (events & BEV_EVENT_ERROR) {
    int err = bufferevent_socket_get_dns_error(serv->bev);
    if (err) DIE("DNS error: %s\n", evutil_gai_strerror(err));
    DIE("BEV_EVENT_ERROR: %s\n", strerror(errno));

  } else if (events & BEV_EVENT_EOF) {
    DIE("Unexpected EOF from server.\n");
  }
}

/**
 * Request generation loop. Determines whether or not to issue a new command,
 * based on timer events.
 *
 * Note that this function loops. Be wary of break vs. return.
 */
void Connection::drive_write_machine(server_t* serv, double now) {
  if (now == 0.0) now = get_time();

  double delay;
  struct timeval tv;

  if (check_exit_condition(now)) return;

  while (1) {
    switch (serv->write_state) {
    case INIT_WRITE:
      delay = iagen->generate();
      next_time = now + delay;
      double_to_tv(delay, &tv);
      evtimer_add(timer, &tv);
      serv->write_state = WAITING_FOR_TIME;
      break;

    case ISSUING:
      if (serv->op_queue.size() >= (size_t) options.depth) {
        serv->write_state = WAITING_FOR_OPQ;
        return;
      } else if (now < next_time) {
        serv->write_state = WAITING_FOR_TIME;
        break; // We want to run through the state machine one more time
               // to make sure the timer is armed.
      } else if (options.moderate && now < last_rx + 0.00025) {
        serv->write_state = WAITING_FOR_TIME;
        if (!event_pending(timer, EV_TIMEOUT, NULL)) {
          delay = last_rx + 0.00025 - now;
          double_to_tv(delay, &tv);
          evtimer_add(timer, &tv);
        }
        return;
      }

      issue_something(serv, now);
      last_tx = now;
      stats.log_op(serv->op_queue.size());
      next_time += iagen->generate();

      if (options.skip && options.lambda > 0.0 &&
          now - next_time > 0.005000 &&
          serv->op_queue.size() >= (size_t) options.depth) {

        while (next_time < now - 0.004000) {
          stats.skips++;
          next_time += iagen->generate();
        }
      }
      break;

    case WAITING_FOR_TIME:
      if (now < next_time) {
        if (!event_pending(timer, EV_TIMEOUT, NULL)) {
          delay = next_time - now;
          double_to_tv(delay, &tv);
          evtimer_add(timer, &tv);
        }
        return;
      }
      serv->write_state = ISSUING;
      break;

    case WAITING_FOR_OPQ:
      if (serv->op_queue.size() >= (size_t) options.depth) return;
      serv->write_state = ISSUING;
      break;

    default: DIE("Not implemented");
    }
  }
}

/**
 * Handle incoming data (responses).
 */
void Connection::read_callback(server_t* serv) {
  struct evbuffer *input = bufferevent_get_input(serv->bev);
  Operation *op = NULL;

  if (serv->op_queue.size() == 0) V("Spurious read callback.");

  while (1) {
    if (serv->op_queue.size() > 0) {
      op = &serv->op_queue.front();
    } else {
      // since we're in a loop, may need to escape if out of op's to process
      return;
    }

    switch (serv->read_state) {
    case INIT_READ: DIE("event from uninitialized connection");
    case IDLE: return;  // We munched all the data we expected?

    case WAITING_FOR_GET:
    case WAITING_FOR_SET:
      assert(serv->op_queue.size() > 0);
      if (!serv->prot->handle_response(input)) return;
      finish_op(serv, op); // sets read_state = IDLE
      break;

    case LOADING:
      assert(serv->op_queue.size() > 0);
      if (!serv->prot->handle_response(input)) return;
      loader_completed++;
      pop_op(serv);

      if (loader_completed == options.records) {
        D("Finished loading.");
        for (auto &s : servers) {
          s.read_state = IDLE;
        }
      } else {
        while (loader_issued < loader_completed + LOADER_CHUNK) {
          if (loader_issued >= options.records) break;

          char key[256];
          string keystr = keygen->generate(loader_issued);
          strcpy(key, keystr.c_str());
          int index = lrand48() % (1024 * 1024);
          issue_set(serv, key, &random_char[index], valuesize->generate());

          loader_issued++;
        }
      }
      break;

    case CONN_SETUP:
      assert(options.binary);
      if (!serv->prot->setup_connection_r(input)) return;
      serv->read_state = IDLE;
      break;

    default: DIE("not implemented");
    }
  }
}

/**
 * Callback called when write requests finish.
 */
void Connection::write_callback() {}

/**
 * Callback for timer timeouts.
 */
void Connection::timer_callback() {
  drive_write_machine(leader);
}


/* The follow are C trampolines for libevent callbacks. */
void bev_event_cb(struct bufferevent *bev, short events, void *ptr) {
  server_t* serv = (server_t*) ptr;
  serv->conn->event_callback(serv, events);
}

void bev_read_cb(struct bufferevent *bev, void *ptr) {
  server_t* serv = (server_t*) ptr;
  serv->conn->read_callback(serv);
}

void bev_write_cb(struct bufferevent *bev, void *ptr) {
  server_t* serv = (server_t*) ptr;
  serv->conn->write_callback();
}

void timer_cb(evutil_socket_t fd, short what, void *ptr) {
  Connection* conn = (Connection*) ptr;
  conn->timer_callback();
}

