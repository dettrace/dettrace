#include "globalState.hpp"

globalState::globalState(logger& log, ValueMapper<ino_t, ino_t> inodeMap,
                         ValueMapper<ino_t, time_t> mtimeMap, bool kernelPre4_12,
			 unsigned prngSeed, bool allow_network):
  prng(prngSeed),
  inodeMap{ inodeMap },
  mtimeMap{ mtimeMap },
  kernelPre4_12{ kernelPre4_12 },
  log(log),
  allow_network(allow_network) {}
