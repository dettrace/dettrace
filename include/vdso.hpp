#ifndef _DETTRACE_VDSO_HPP
#define _DETTRACE_VDSO_HPP

#include <map>
#include <string>
#include <vector>

enum ProcMapPerm {
  ProcMapPermRead = 0x1,
  ProcMapPermWrite = 0x2,
  ProcMapPermExec = 0x4,
  ProcMapPermPrivate = 0x1000,
};

struct ProcMapEntry {
  unsigned long procMapBase;
  long procMapSize;
  long procMapPerms;
  unsigned long procMapOffset;
  unsigned long procMapDev;
  unsigned long procMapInode;
  char procMapName[80];
};

std::ostream& operator<<(std::ostream& out, ProcMapEntry const& e);

enum VDSOFunc {
  VDSO_clock_gettime = 0,
  VDSO_getcpu,
  VDSO_gettimeofday,
  VDSO_time,
};

struct VDSOSymbol {
  enum VDSOFunc func;
  unsigned long offset;
  unsigned long size;
  unsigned long alignment;
  const unsigned char* code;
  unsigned int code_size;
};

/// parse /proc/<pid>/maps
/// returns number of entries parsed.
int parseProcMapEntries(pid_t pid, ProcMapEntry* ep, int size);

/// get vdso symbols information from /proc
/// NB: offset is relative.
/// returns number of vdso symbols parsed.
int vdsoGetSymbols(pid_t pid, struct VDSOSymbol* vdso, int size);

#endif
