#ifndef DIRECTORY_ENTRIES_H
#define DIRECTORY_ENTRIES_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <cstdint>

#include <algorithm>
#include <deque>
#include <memory>
#include <string>
#include <vector>

#include "logger.hpp"

using namespace std;

/**
 * Linux directory entry struct
 * As per getdents(2)
 */
struct linux_dirent {
  long d_ino; /*< inode number */
  off_t d_off; /*< offset to next structure */
  unsigned short d_reclen; /*< Size of this dirent */
  char d_name[]; /*< Filename (null-terminated) */
};

struct linux_dirent64 {
  ino64_t d_ino; /**< 64-bit inode number */
  off64_t d_off; /**< 64-bit offset to next structure */
  unsigned short d_reclen; /**< Size of this dirent */
  unsigned char d_type; /**< File type */
  char d_name[]; /**< Filename (null-terminated) */
};

/**
 * This class wraps raw memory which itself represents either struct
 * linux_dirent or struct linux_dirent64. That is, directory entries for the
 * system calls getdents and getdents64.
 *
 * WARNING: This class can only be be instantiated with linux_dirent or
 * linux_dirent64.
 */
template <typename T>
class directoryEntries {
public:
  logger& log; /**< log file wrapper */

  /**
   * Constructor.
   * Dynamically allocate enough memory to hold all directory entries by the
   * user.
   * @param bytes total bytes
   * @param log log file handler
   */
  directoryEntries(size_t bytes, logger& log) : log(log) {
    rawEntries.reserve(bytes);
  }

  /**
   * Add a chunk of count size to our internal buffer.
   * Resize if needed.
   * @param newChunk chunk to be added as a array of bytes
   */
  void addChunk(vector<uint8_t> newChunk) {
    rawEntries.insert(rawEntries.end(), newChunk.begin(), newChunk.end());
    return;
  }

  /**
   * Return an array of size < bytesNeeded, in order to fill it with as many
   * entries as possible. This operation consumes the previous entries so
   * subsequent calls with same argument will return new entries.
   * @param bytesNeeded maximum array size to return.
   * @return sorted array of entries
   */
  vector<uint8_t> getSortedEntries(size_t bytesNeeded) {
    vector<uint8_t> toFill{};

    if (!sorted) {
      sorted = true;
      sortOurEntries();
    }

    while (true) {
      /** We read all entries before filling this buffer. */
      if (entries.empty()) {
        break;
      }

      /** Get current head entry from our queue. */
      auto tupleEntry = entries.front();
      size_t entrySize = get<2>(tupleEntry);

      /** Ensure we have enough room for this entry. Otherwise we're done! */
      if (entrySize + toFill.size() > bytesNeeded) {
        break;
      }

      log.writeToLog(
          Importance::extra, "Returning entry: " + get<0>(tupleEntry) + "\n");

      /** We know we have enough room, it is now okay to get rid of this entry.
       */
      entries.pop_front();

      /** Copy over entry based on address and size of struct. */
      toFill.insert(
          toFill.end(), get<1>(tupleEntry), get<1>(tupleEntry) + entrySize);
    }

    return toFill;
  }

private:
  /**
   * This vector represents contigious linux_dirent entries as a raw array of
   * bytes.
   */
  vector<uint8_t> rawEntries;

  bool sorted = false; /**<  If the entries have been sorted*/

  /**
   * Sorts directory entries from raw entries.
   */
  void sortOurEntries() {
    if (!entries.empty()) {
      throw runtime_error(
          "dettrace runtime exception: sortOurEntries was called with "
          "non-empty entries.");
    }

    /** Variable size data, we cannot "iterate" over the entries in the array.
     */
    uint8_t* position = rawEntries.data();
    while (position < rawEntries.data() + rawEntries.size()) {
      T* currentEntry = (T*)position;
      size_t entrySize = currentEntry->d_reclen;

      entries.push_back(make_tuple(
          string{currentEntry->d_name}, (uint8_t*)currentEntry, entrySize));
      position += entrySize;
    }

    // Sort!
    sort(entries.begin(), entries.end(), [](auto& p1, auto& p2) {
      return get<0>(p1) > get<0>(p2);
    });
  }

  /**
   * Turn our entries into a vector of (name, address, byteSize) for easy
   * sorting. Each address is it's location on our array this way, we can "sort"
   * the variable sized structs by their filename.
   */
  deque<tuple<string, uint8_t*, size_t>> entries;
};

#endif
