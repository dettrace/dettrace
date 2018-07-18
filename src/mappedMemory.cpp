#include "state.hpp"
#include "mappedMemory.hpp"

/**
 * We should not inject mmap for the following.
 */
bool shouldRunFor(int syscallNumber){
  return syscallNumber != SYS_mmap &&
         syscallNumber != SYS_execve &&
         syscallNumber != SYS_fork &&
         syscallNumber != SYS_clone &&
         syscallNumber != SYS_vfork;
}

bool mappedMemory::ensureExistenceOfMapping(globalState& gs, state& s, ptracer& t) {
  // only create mapping if one doesn't exist
  if (!doesExist && shouldRunFor(t.getSystemCallNumber())) {
    gs.log.writeToLog(Importance::info, "Injecting mmap call to tracee!\n");
   // Save current register state to restore in fstat.
    s.regSaver.pushRegisterState(t.getRegs());

    // Inject mmap system call to perform!
    s.syscallInjected = true;

    // call mmap
    t.writeArg1((uint64_t) NULL); // kernel will choose address of mapping
    t.writeArg2(this->length); // size of memory page in bytes
    t.writeArg3(this->prot); // page can be read and written
    t.writeArg4(this->flags); // mapping is initialized to 0 and is not backed by a file
    t.writeArg5(this->fd);  // not used in anonymous
    t.writeArg6(this->offset); // not used in anonymous

    // replaySystemcall
    uint16_t minus2 = t.readFromTracee(traceePtr<uint16_t>((uint16_t*) ((uint64_t) t.getRip().ptr - 2)), t.getPid());
    if (!(minus2 == 0x80CD || minus2 == 0x340F || minus2 == 0x050F)) {
      throw runtime_error("IP does not point to system call instruction!\n");
    }

    // Replay system call!
    t.changeSystemCall(SYS_mmap);
    t.writeIp((uint64_t) t.getRip().ptr - 2);

    gs.log.writeToLog(Importance::info, "mmap(NULL, %zu, %d, %d, %d, %d)!\n",
      this->length, this->prot, this->flags, this->fd, this->offset);

    doesExist = true;
    return true;
  }

  return false;
}
