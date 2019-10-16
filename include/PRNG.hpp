#pragma once

#include <cstdint>

/** This class implements an Xorshift Linear-Feedback Shift Register
https://en.wikipedia.org/wiki/Linear-feedback_shift_register#Xorshift_LFSRs
which is a very simple pseudorandom number generator.
 */
class PRNG {
public:
  /** Initialize this pseudorandom number generator with the given state */
  PRNG(uint16_t startingState) : lfsr(startingState) {}

  /** @return a 16b pseudorandom value */
  uint16_t get() {
    this->lfsr ^= this->lfsr >> 7;
    this->lfsr ^= this->lfsr << 9;
    this->lfsr ^= this->lfsr >> 13;
    return this->lfsr;
  }

private:
  /** Our current internal state */
  uint16_t lfsr;
};
