#ifndef TRACEE_PTR_H
#define TRACEE_PTR_H

/**
 * Simple wrapper around T* pointer used for distinguishing between
 * pointers in the tracee address space and pointers in the local
 * address space
 * Template parameter T is the type of the pointer.
 */
template <typename T>
struct traceePtr {
  T* ptr; /**< pointer of a value fo type T*/
  /**
   * Constructor. The constructor has to be explicit or else the
   * compiler will automatically 'promote' T* types to traceePtr<T>
   * and that would lead to the compiler not detecting a case where
   * a memory pointer (T*) was provided instead of a memory pointer
   * in the tracee address space (traceePtr<T>)
   * @param ptr the pointer of type T
   */
  explicit traceePtr(T* ptr) : ptr(ptr) {}
};

#endif
