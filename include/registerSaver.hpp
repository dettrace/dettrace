#ifndef REGISTER_SAVER_H
#define REGISTER_SAVER_H

#include <sys/user.h>
using namespace std;
/**
 * A register saver class that has the ability to save/retrieve a register
 * struct by pushing and popping. Only a single register struct can be saved at
 * a time, and a pop cannot be performed unless preceded by a push and
 * vice-versa.
 */

class registerSaver {
private:
  /**
   * A copy of the saved register state
   */
  struct user_regs_struct regs;
  /**
   * A boolean indicating whether or not a register state has been pushed
   */
  bool hasPushed = false;

public:
  /**
   * Push a given register state to be saved. Throws an error if a state has
   * already been pushed and has yet to be popped.
   * @param newRegs the register struct to be saved
   */
  void pushRegisterState(struct user_regs_struct newRegs) {
    // error checking
    if (hasPushed) {
      throw runtime_error(
          "dettrace runtime exception: Attempting to push to a filed "
          "registerSaver.\n");
    }

    // hasn't pushed, so push state
    hasPushed = true;
    regs = newRegs;
  };

  /**
   * Pop the saved register state. Throws an error if no state was pushed.
   * @return the saved register.
   */
  struct user_regs_struct popRegisterState() {
    // error checking
    if (!hasPushed) {
      throw runtime_error(
          "dettrace runtime exception: Attempting to pop from an empty "
          "registerSaver.\n");
    }

    // return saved state
    hasPushed = false;
    return regs;
  };
};

#endif
