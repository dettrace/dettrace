#ifndef MAPPED_MEMORY_H
#define MAPPED_MEMORY_H
#include <sys/mman.h>
#include "globalState.hpp"
#include "ptracer.hpp"
#include "state.hpp"

using namespace std;

class state;

/**
 * Class that abstracts over calling mmap to allocate a memory page
 * that can be used for arbitrary writing/reading in the tracee
 * virtual memory.
 */

class mappedMemory {
public:
  /**
   * Constructor. The values supplied here will be provided to
   * the mmap system call. See `man mmap` for more details
   * @param length the desired length of the mapping
   * @param state, reference to parent state
   */
  mappedMemory(size_t length) : length(length) {}

  /**
   * Getter for the starting address of the mapped memory page.
   * Throws an error if memory wasn't mapped.
   * @return memory address of mapped memory page in tracee memory
   */
  traceePtr<void> getAddr() {
    if (!doesExist) {
      throw runtime_error(
          "Attempting to get address of non-existing MappedMemory.\n");
    }
    return mmapAddr;
  }

  /**
   * Setter for the starting adderss of the mapped memory page. Warning: only
   * meant to be called from the post-hook of an injected mmap and assumes
   * success of mmap.
   * @param addr starting address of mapped memory page
   */
  void setAddr(traceePtr<void> addr) {
    mmapAddr = addr;
    doesExist = true;
  }

  /**
   * Getter for the length of the mapped memory page.
   * @return length of the memory page.
   */
  size_t getLength() { return length; }

  /** boolean flag indicating if a mapping already exists. */
  bool doesExist = false;

private:
  /** pointer to starting address of the mapping in tracee memory. */
  traceePtr<void> mmapAddr = traceePtr<void>((void*)-1);

  /** the length of the mapping */
  size_t length;
};
#endif
