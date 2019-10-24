#include "globalState.hpp"

globalState::globalState(
    logger& log,
    ValueMapper<ino_t, ino_t> inodeMap,
    ModTimeMap mtimeMap,
    bool kernelPre4_12,
    unsigned prngSeed,
    logical_clock::time_point epoch,
    bool allow_network)
    : log(log),
      inodeMap{inodeMap},
      mtimeMap{mtimeMap},
      kernelPre4_12{kernelPre4_12},
      prng(prngSeed),
      epoch(epoch),
      allow_network(allow_network) {
  allow_trapCPUID = true;
}
