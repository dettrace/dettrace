#ifndef _DETTRACE_VDSO_HPP
#define _DETTRACE_VDSO_HPP

#include <sys/types.h>

enum ProcMapPerm {
  ProcMapPermRead = 0x1,
  ProcMapPermWrite = 0x2,
  ProcMapPermExec = 0x4,
  ProcMapPermPrivate = 0x1000,
};

#define PROC_MAP_ENTRY_NAME_MAX 127

struct ProcMapEntry {
  unsigned long procMapBase;
  long procMapSize;
  long procMapPerms;
  unsigned long procMapOffset;
  unsigned long procMapDev;
  unsigned long procMapInode;
  char procMapName[1 + PROC_MAP_ENTRY_NAME_MAX];
};

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
int proc_get_map_entries(pid_t pid, struct ProcMapEntry* ep, int size);

/// parse [vdso] and [vvar] from /proc/pid/maps.
/// returns 0 on success, -1 on failure.
/// caller to verify vdso/vvar have been updated.
int proc_get_vdso_vvar(
    pid_t pid, struct ProcMapEntry* vdso, struct ProcMapEntry* vvar);

/// get vdso symbols from vdso
/// returns number of vdso functions found.
int proc_get_vdso_symbols(
    struct ProcMapEntry* vdso_entry, struct VDSOSymbol* vdso, int size);

#endif
