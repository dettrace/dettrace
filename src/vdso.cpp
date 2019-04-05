#include <sys/types.h>
#include <sys/stat.h>

#include <inttypes.h>

#include <fcntl.h>
#include <unistd.h>

#include <string>
#include <algorithm>
#include <sstream>
#include <iostream>
#include <stdexcept>
#include <cstring>
#include <vector>
#include <tuple>
#include <cstdlib>
#include <cstdio>
#include <cassert>
#include <map>

#include <elf/elf++.hh>

#include "vdso.hpp"

/*
 * byte code for the new psudo vdso functions
 * which do the actual syscalls.
 * NB: the byte code must be 8 bytes
 * aligned
 */
static const unsigned char __vdso_time[] = {
    0xb8, 0xc9, 0x0, 0x0, 0x0                     // mov %SYS_time, %eax
  , 0x0f, 0x05                                    // syscall
  , 0xc3                                          // retq
  , 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00      // nopl 0x0(%rax, %rax, 1)
  , 0x00 };

static const unsigned char __vdso_clock_gettime[] = {
    0xb8, 0xe4, 0x00, 0x00, 0x00                // mov SYS_clock_gettime, %eax
  , 0x0f, 0x05                                  // syscall
  , 0xc3                                        // retq
  , 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00    // nopl 0x0(%rax, %rax, 1)
  , 0x00 };

static const unsigned char __vdso_getcpu[] = {
    0x48, 0x85, 0xff                                   // test %rdi, %rdi
  , 0x74, 0x06                                         // je ..
  , 0xc7, 0x07, 0x00, 0x00, 0x00, 0x00                 // movl $0x0, (%rdi)
  , 0x48, 0x85, 0xf6                                   // test %rsi, %rsi
  , 0x74, 0x06                                         // je ..
  , 0xc7, 0x06, 0x00, 0x00, 0x00, 0x00                 // movl $0x0, (%rsi)
  , 0x31, 0xc0                                         // xor %eax, %eax
  , 0xc3                                               // retq
  , 0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00 };        // nopl 0x0(%rax)

static const unsigned char __vdso_gettimeofday[] = {
    0xb8, 0x60, 0x00, 0x00, 0x00                 // mov SYS_gettimeofday, %eax
  , 0x0f, 0x05                                   // syscall
  , 0xc3                                         // retq
  , 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00     // nopl 0x0(%rax, %rax, 1)
  , 0x00 };

std::map<std::string, std::basic_string<unsigned char>> vdsoGetCandidateData(void) {
  std::map<std::string, std::basic_string<unsigned char>> res;

  std::basic_string<unsigned char> vdso_time(__vdso_time, sizeof(__vdso_time));
  std::basic_string<unsigned char> vdso_clock_gettime(__vdso_clock_gettime, sizeof(__vdso_clock_gettime));
  std::basic_string<unsigned char> vdso_getcpu(__vdso_getcpu, sizeof(__vdso_getcpu));
  std::basic_string<unsigned char> vdso_gettimeofday(__vdso_gettimeofday, sizeof(__vdso_gettimeofday));

  assert( (vdso_time.size() & 0xf) == 0);
  assert( (vdso_clock_gettime.size() & 0xf) == 0);
  assert( (vdso_getcpu.size() & 0xf) == 0);
  assert( (vdso_gettimeofday.size() & 0xf) == 0);

  res["__vdso_time"]          = vdso_time;
  res["__vdso_clock_gettime"] = vdso_clock_gettime;
  res["__vdso_getcpu"]        = vdso_getcpu;
  res["__vdso_gettimeofday"]  = vdso_gettimeofday;

  return res;
}

std::ostream& operator<< (std::ostream &out, ProcMapEntry const& e) {
  out << std::hex << e.procMapBase << '-' << e.procMapBase + e.procMapSize << ' ';
  out << ( (e.procMapPerms & ProcMapPermRead)? 'r': '-');
  out << ( (e.procMapPerms & ProcMapPermWrite)? 'w': '-');
  out << ( (e.procMapPerms & ProcMapPermExec)? 'x': '-');
  out << ( (e.procMapPerms & ProcMapPermPrivate)? 'p': '-') << ' ';
  out << e.procMapOffset << ' ';
  out << (e.procMapDev >> 8) << ':' << (e.procMapDev & 0xffL) << ' ';
  out << e.procMapInode << "\t\t";
  out << e.procMapName;
  return out;
}

int parseProcMapEntry(const std::string& line_, struct ProcMapEntry& res)
{
  char* p, *q;
  char* line = strdupa(line_.c_str());

  p = line;

  res.procMapBase = strtoull(p, &q, 16);
  res.procMapSize = strtoull(1+q, &p, 16) - res.procMapBase;
  while(*p == ' ' || *p == '\t' ) ++p;

  if(*p++ == 'r') res.procMapPerms |= ProcMapPermRead;
  if(*p++ == 'w') res.procMapPerms |= ProcMapPermWrite;
  if(*p++ == 'x') res.procMapPerms |= ProcMapPermExec;
  if(*p++ == 'p') res.procMapPerms |= ProcMapPermPrivate;

  while(*p == ' ' || *p == '\t' ) ++p;
  res.procMapOffset = strtoul(p, &q, 16);
  while(*q == ' ' || *q == '\t' ) ++q;
  res.procMapDev = strtoul(q, &p, 16) * 256;
  res.procMapDev += strtoul(1+p, &q, 16);
  while(*q == ' ' || *q == '\t' ) ++q;
  res.procMapInode = strtoul(q, &p, 16);
  while(*p == ' ' || *p == '\t' ) ++p;
  if (*p == '\0') {
    res.procMapName = {};
  } else {
    res.procMapName = p;
  }
  return 0;
}

std::vector<ProcMapEntry> parseProcMapEntries(pid_t pid)
{
  int fd;
  char* mapsFile;
  char* buffer;
  const int buffer_size = 2 << 20;

  std::vector<ProcMapEntry> res;

  asprintf(&mapsFile, "/proc/%u/maps", pid);

  fd = open(mapsFile, O_RDONLY);
  if (fd < 0) {
    return {};
  }

  free(mapsFile);

  buffer = new char [buffer_size];
  if (!buffer) {
    close(fd);
    return {};
  }

  unsigned long nr = 0;
  while (1) {
    auto nb = read(fd, buffer + nr, buffer_size - nr);
    if (nb < 0) {
      if (errno == EINTR) continue;
      close(fd);
      delete [] buffer;
      return {};
    } else if (nb == 0) {
      break;
    } else {
      nr += nb;
    }
  }

  close(fd);

  std::istringstream f(buffer);
  std::string line;
  delete [] buffer;
  ProcMapEntry mapEntry;

  while (std::getline(f, line)) {
    if (parseProcMapEntry(line, mapEntry) == 0) {
      res.push_back(mapEntry);
    }
  }

  return res;
}

class empty_loader: public elf::loader {
private:
  void* base;
  unsigned long lim;
public:
  empty_loader(void* base_, unsigned long size_): base(base_), lim(size_) {
  }
  ~empty_loader() {
  }
  const void* load(off_t offset, size_t size) {
    if (offset + size > lim)
      throw std::range_error("offset exceeds mapped size");
    return ((const char*)base + offset);
  }
};

std::shared_ptr<elf::loader>
create_empty_loader(void* base, unsigned long size) {
  return std::make_shared<empty_loader>(base, size);
}

int vdsoGetMapEntry(pid_t pid, struct ProcMapEntry& entry)
{
  auto entries = parseProcMapEntries(pid);

  for (auto ent: entries) {
    if (ent.procMapName == "[vdso]") {
      entry = ent;
      return 0;
    }
  }
  return -1;
}

std::vector<std::string> vdsoGetFuncNames(void)
{
  std::vector<std::string> res;

  res.push_back("__vdso_clock_gettime");
  res.push_back("__vdso_getcpu");
  res.push_back("__vdso_time");
  res.push_back("__vdso_gettimeofday");

  return res;
}

/**
 * vdsoGetSymbols: get vdso symbols information
 * return as std::tuple<symbol_address, symbol_size, symbol/section_alignment>
 */
std::map<std::string, std::tuple<unsigned long, unsigned long, unsigned long>> vdsoGetSymbols(pid_t pid)
{
  std::map<std::string, std::tuple<unsigned long, unsigned long, unsigned long>> res;
  struct ProcMapEntry vdsoMapEntry;

  if (vdsoGetMapEntry(pid, vdsoMapEntry) != 0) {
    return res;
  }

  elf::elf elf(create_empty_loader(reinterpret_cast<void*>(vdsoMapEntry.procMapBase), vdsoMapEntry.procMapSize));

  for (auto &sec: elf.sections()) {
    if (sec.get_hdr().type != elf::sht::symtab && sec.get_hdr().type != elf::sht::dynsym)
      continue;
    for (auto sym : sec.as_symtab()) {
      auto &d = sym.get_data();
      if ( (d.binding() == elf::stb::global) &&
	   (d.type() == elf::stt::func) ) {
	assert(d.shnxd >= 0 && d.shnxd < elf.sections().size());
	auto alignment = elf.sections()[d.shnxd].get_hdr().addralign;
	res[sym.get_name()] = std::tie(d.value, d.size, alignment);
      }
    }    
  }
  return res;
}
