// -*- c++-mode -*-
#ifndef OPERATION_H
#define OPERATION_H

#include <string>

using namespace std;

class Operation {
public:
  double start_time, end_time;

  enum type_enum {
    GET, SET, SASL
  };

  type_enum type;

  string key;

  double time() const { return (end_time - start_time) * 1000000; }

  bool operator < (const Operation& op) const {
    return (start_time < op.start_time);
  }

  const char* toString() {
    switch(type) {
    case GET:  return "GET";
    case SET:  return "SET";
    case SASL: return "SASL";
    default:   return "?";
    }
  }
};


#endif // OPERATION_H
