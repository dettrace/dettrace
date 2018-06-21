#ifndef TRACEE_PTR_H
#define TRACEE_PTR_H

/**
 * Simple wrapper around T* pointer used for distinguishing between
 * pointers in the tracee address space and pointers in the local
 * address space
 * Template parameter T is the type of the pointer.
 */
template <typename T>
struct TraceePtr {
  T* ptr;
  explicit TraceePtr(T* ptr) : 
    ptr(ptr) {
  }
};

#endif
