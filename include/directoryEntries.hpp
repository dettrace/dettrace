#ifndef DIRECTORY_ENTRIES_H
#define DIRECTORY_ENTRIES_H

#include <cstdint>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

#include <deque>
#include <string>
#include <algorithm>
#include <memory>
#include <vector>

using namespace std;

// As per getdents(2)
struct linux_dirent {
  long           d_ino;
  off_t          d_off;
  unsigned short d_reclen;
  char           d_name[];
};

struct linux_dirent64 {
  ino64_t        d_ino;    /* 64-bit inode number */
  off64_t        d_off;    /* 64-bit offset to next structure */
  unsigned short d_reclen; /* Size of this dirent */
  unsigned char  d_type;   /* File type */
  char           d_name[]; /* Filename (null-terminated) */
};

/**
 * This class wraps raw memory which itself represents either struct linux_dirent or
 * struct linux_dirent64. That is, directory entries for the system calls getdents and
 * getdents64.
 *
 * WARNING: This class can only be be instantiated with linux_dirent or linux_dirent64.
 */
template <typename T>
class directoryEntries{
public:
  // Dynamically allocate enough memory to hold all directory entries by the user.
  directoryEntries(size_t bytes){
    rawEntries.reserve(bytes);
  }

  // Add a chunk of count size to our internal buffer.
  // Resize if needed.
  void addChunk(vector<uint8_t> newChunk){
    rawEntries.insert(rawEntries.end(), newChunk.begin(), newChunk.end());
    return;
  }

  // Return an array of size < bytesNeeded, in order to fill it with as many
  // entries as possible.
  // This operation consumes the previous entries so subsequent calls with same
  // argument will return new entries.
  vector<int8_t> getSortedEntries(size_t bytesNeeded){
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

private:
  // This vector represents contigious linux_dirent entries as a raw array of
  // bytes.
  vector<uint8_t> rawEntries;

  // Have the entries been sorted?
  bool sorted = false;

  // Template magic. No idea why it works.
  void sortOurEntries(){
    if(! entries.empty()){
      throw runtime_error("sortOurEntries was called with non-empty entries.");
    }

    // Variable size data, we cannot "iterate" over the entries in the array.
    uint8_t* position = rawEntries.data();
    while(position < rawEntries.data() + rawEntries.size()){
      T* currentEntry = (T*) position;
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

  // Turn our entries into a vector of (name, address, byteSize) for easy sorting. Were
  // address is it's location on our array this way, we can "sort" the variable
  // sized structs by their filename.
  deque<tuple<string, uint8_t*, size_t>> entries;
};

#endif
