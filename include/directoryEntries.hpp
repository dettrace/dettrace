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

/**
 * This class wraps raw memory which itself represents either struct linux_dirent or
 * struct linux_dirent64. That is, directory entries for the system calls getdents and
 * getdents64.
 *
 */
class directoryEntries{
public:
  // Dynamically allocate enough memory to hold all directory entries by the user.
  directoryEntries(size_t bytes);

  // Add a chunk of count size to our internal buffer.
  // Resize if needed.
  void addChunk(vector<uint8_t> newChunk);

  // Return an array of size < bytesNeeded, in order to fill it with as many
  // entries as possible.
  // This operation consumes the previous entries so subsequent calls with same
  // argument will return new entries.
  vector<int8_t> getSortedEntries(size_t bytesNeeded);

private:
  // This vector represents contigious linux_dirent entries as a raw array of
  // bytes.
  vector<uint8_t> rawEntries;

  // Have the entries been sorted?
  bool sorted = false;

  void sortOurEntries();

  // Turn our entries into a vector of (name, address, byteSize) for easy sorting. Were
  // address is it's location on our array this way, we can "sort" the variable
  // sized structs by their filename.
  deque<tuple<string, uint8_t*, size_t>> entries;
};

#endif
