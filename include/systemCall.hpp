#ifndef SYSTEM_CALL_H
#define SYSTEM_CALL_H

#include <stdexcept>
#include "state.hpp"
#include "ptracer.hpp"

using namespace std;

// Needed to avoid recursive dependencies between classes.
class state;

/**
 * Class to hold handling function per system call.
 * You should derive from this class and implement handleDeterministically() using
 * the override attribute.
 * default implementation throws exeception.
 */
class systemCall{
public:
  systemCall(long syscallNumber, string syscallName);

  /**
   * Function to call before system call is exectuted to handle deterministicallly.
   * This is different in a per system call basis. This is the default
   * implementation, notice this means we rely on virtual dispatch to call the correct
   * function, haters will say it's slow.
   * @param s: Current state of the program state of tracer.
   * @return  executeSystemCall: Dictate whether we should execute the system call.
   */
  virtual bool handleDetPre(state& s, ptracer& t);

  virtual void handleDetPost(state& s, ptracer& t);

  const long syscallNumber;
  const string syscallName;
};

#endif
