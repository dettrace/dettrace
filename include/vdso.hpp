#ifndef _DETTRACE_VDSO_HPP
#define _DETTRACE_VDSO_HPP

#include <string>
#include <vector>
#include <map>

enum ProcMapPerm {
  ProcMapPermRead = 0x1,
  ProcMapPermWrite = 0x2,
  ProcMapPermExec = 0x4,
  ProcMapPermPrivate = 0x1000,
};

struct ProcMapEntry {
  uint64_t                   procMapBase;
  long                       procMapSize;
  long                       procMapPerms;
  unsigned long              procMapOffset;
  unsigned long              procMapDev;
  unsigned long              procMapInode;
  std::string                procMapName;
};

std::ostream& operator<< (std::ostream &out, ProcMapEntry const& e);

int vdsoGetMapEntry(pid_t pid, struct ProcMapEntry& entry);
std::map<std::string, std::basic_string<unsigned char>> vdsoGetCandidateData(void);
std::map<std::string, std::tuple<unsigned long, unsigned long, unsigned long>> vdsoGetSymbols(pid_t pid);

#endif
