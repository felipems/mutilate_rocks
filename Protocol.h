// -*- c++-mode -*-
#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <event2/bufferevent.h>

#include "ConnectionOptions.h"

using namespace std;

class Connection;

class Protocol {
public:
  Protocol(options_t _opts, unsigned int _id, Connection* _conn,
    bufferevent* _bev): opts(_opts), id(_id), conn(_conn), bev(_bev) {};
  virtual ~Protocol() {};

  virtual bool setup_connection_w() = 0;
  virtual bool setup_connection_r(evbuffer* input) = 0;
  virtual int  get_request(const char* key) = 0;
  virtual int  set_request(const char* key, const char* value, int len) = 0;
  virtual bool handle_response(evbuffer* input) = 0;

protected:
  options_t    opts;
  unsigned int id;
  Connection*  conn;
  bufferevent* bev;
};

class ProtocolAscii : public Protocol {
public:
  ProtocolAscii(options_t opts, unsigned int id, Connection* conn,
    bufferevent* bev): Protocol(opts, id, conn, bev) { read_state = IDLE; };
  ~ProtocolAscii() {};

  virtual bool setup_connection_w() { return true; }
  virtual bool setup_connection_r(evbuffer* input) { return true; }
  virtual int  get_request(const char* key);
  virtual int  set_request(const char* key, const char* value, int len);
  virtual bool handle_response(evbuffer* input);

private:
  enum read_fsm {
    IDLE,
    WAITING_FOR_GET,
    WAITING_FOR_GET_DATA,
    WAITING_FOR_END,
  };

  read_fsm read_state;
  int data_length;
};

class ProtocolBinary : public Protocol {
public:
  ProtocolBinary(options_t opts, unsigned int id, Connection* conn,
    bufferevent* bev): Protocol(opts, id, conn, bev) {};
  ~ProtocolBinary() {};

  virtual bool setup_connection_w();
  virtual bool setup_connection_r(evbuffer* input);
  virtual int  get_request(const char* key);
  virtual int  set_request(const char* key, const char* value, int len);
  virtual bool handle_response(evbuffer* input);
};

class ProtocolEtcd : public Protocol {
public:
  ProtocolEtcd(options_t opts, unsigned int id, Connection* conn,
    bufferevent* bev): Protocol(opts, id, conn, bev) { read_state = IDLE; };
  virtual ~ProtocolEtcd() {};

  virtual bool setup_connection_w() { return true; }
  virtual bool setup_connection_r(evbuffer* input) { return true; }
  virtual int  get_request(const char* key);
  virtual int  set_request(const char* key, const char* value, int len);
  virtual bool handle_response(evbuffer* input);

protected:
  enum read_fsm {
    IDLE,
    WAITING_FOR_HTTP,
    WAITING_FOR_HTTP_BODY,
    LEADER_CHANGED,
  };

  read_fsm read_state;
  int data_length;
};

class ProtocolEtcd2 : public ProtocolEtcd {
public:
  ProtocolEtcd2(options_t opts, unsigned int id, Connection* conn,
    bufferevent* bev): ProtocolEtcd(opts, id, conn, bev) {};
  ~ProtocolEtcd2() {};

  virtual bool handle_response(evbuffer* input);
};

#endif
