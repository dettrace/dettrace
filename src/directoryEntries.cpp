#include <cstdint>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <stdexcept>
#include <string.h>

#include <algorithm>
#include <tuple>
#include <vector>

#include "directoryEntries.hpp"

using namespace std;

directoryEntries::directoryEntries(size_t bytes){
  rawEntries.reserve(bytes);
}

vector<int8_t> directoryEntries::getSortedEntries(size_t bytesNeeded){
  vector<int8_t> toFill {};

  if(!sorted){
    sorted = true;
    sortOurEntries();
  }

  while(true){
    // We read all entries before filling this buffer.
    if(entries.empty()){
      break;
    }

    // Get current head entry from our queue.
    auto tupleEntry = entries.front();
    size_t entrySize = get<2>(tupleEntry);

    // Ensure we have enough room for this entry. Otherwise we're done!
    if(entrySize + toFill.size() > bytesNeeded){
      break;
    }

    // We know we have enough room, it is now okay to get rid of this entry.
    entries.pop_front();

    // Copy over entry based on address and size of struct.
    toFill.insert(toFill.end(), get<1>(tupleEntry), get<1>(tupleEntry) + entrySize);
  }

  return toFill;
}

void directoryEntries::sortOurEntries(){
  if(! entries.empty()){
    throw runtime_error("sortOurEntries was called with non-empty entries.");
  }

  // Variable size data, we cannot "iterate" over the entries in the array.
  uint8_t* position = rawEntries.data();
  while(position < rawEntries.data() + rawEntries.size()){
    linux_dirent* currentEntry = (linux_dirent*) position;
    size_t entrySize = currentEntry->d_reclen;

    entries.push_back(make_tuple(string { currentEntry->d_name },
                                 (uint8_t*) currentEntry,
                                 entrySize
                                 ));
    position += entrySize;
  }

  // Sort!
  sort(entries.begin(), entries.end(), [](auto& p1, auto& p2) {
      return get<0>(p1) > get<0>(p2);
    });
}

void directoryEntries::addChunk(vector<uint8_t> newChunk){
  rawEntries.insert(rawEntries.end(), newChunk.begin(), newChunk.end());

  return;
}

