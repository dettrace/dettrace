/// NB: This file is written in pure C to avoid heap allocations.
/// Supports Linux/x86-64 only.

/// parsing vDSO symbols based on vDSO entry found from /proc/<pid>/maps
/// Note vDSO can be disabled by passing `vdso=0` kernel command line.
/// The vDSO entry is loaded by Linux kernel before app return from execve
/// Even statically linked app will have vDSO loaded (by Linux kernel).
///
/// vDSO is just a regular dynamic shared object (DSO), like any `.so` file
/// in Linux, with the exception it doesn't have external dependencies.
/// Typically it can be found at: /lib/modules/`uname -r`/vdso/vdso64.so
///
/// vDSO provides symbols like:
///     clock_gettime, time, gettimeofday, getcpu
/// more recent kernel also adds clock_getres
/// The symbols can be found in .dynsym section of the DSO
/// This file parse those symbols from .dynsym section, following the ELF
/// spec defined at:
/// https://refspecs.linuxfoundation.org/elf/gabi4+/ch4.intro.html
///
#include <inttypes.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <fcntl.h>
#include <unistd.h>

#include <elf.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util.hpp"
#include "vdso.hpp"

/*
 * byte code for the new psudo vdso functions which do the actual syscalls.
 * NB: the byte code must be 8 bytes aligned
 */
// clang-format off
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

// returns 0 regardless
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
// clang-format on

/*
std::ostream& operator<<(std::ostream& out, ProcMapEntry const& e) {
  out << std::hex << e.procMapBase << '-' << e.procMapBase + e.procMapSize
      << ' ';
  out << ((e.procMapPerms & ProcMapPermRead) ? 'r' : '-');
  out << ((e.procMapPerms & ProcMapPermWrite) ? 'w' : '-');
  out << ((e.procMapPerms & ProcMapPermExec) ? 'x' : '-');
  out << ((e.procMapPerms & ProcMapPermPrivate) ? 'p' : '-') << ' ';
  out << e.procMapOffset << ' ';
  out << (e.procMapDev >> 8) << ':' << (e.procMapDev & 0xffL) << ' ';
  out << e.procMapInode << "\t\t";
  out << e.procMapName;
  return out;
}
*/

/// parse a single (line of) /proc/<pid>maps.
static int parse_entry(char* line, struct ProcMapEntry* ep) {
  char *p, *q;

  p = line;

  ep->procMapBase = strtoull(p, &q, 16);
  ep->procMapSize = strtoull(1 + q, &p, 16) - ep->procMapBase;
  while (*p == ' ' || *p == '\t') ++p;

  ep->procMapPerms = 0;

  if (*p++ == 'r') ep->procMapPerms |= ProcMapPermRead;
  if (*p++ == 'w') ep->procMapPerms |= ProcMapPermWrite;
  if (*p++ == 'x') ep->procMapPerms |= ProcMapPermExec;
  if (*p++ == 'p') ep->procMapPerms |= ProcMapPermPrivate;

  while (*p == ' ' || *p == '\t') ++p;
  ep->procMapOffset = strtoul(p, &q, 16);
  while (*q == ' ' || *q == '\t') ++q;
  ep->procMapDev = strtoul(q, &p, 16) * 256;
  ep->procMapDev += strtoul(1 + p, &q, 16);
  while (*q == ' ' || *q == '\t') ++q;
  ep->procMapInode = strtoul(q, &p, 16);
  while (*p == ' ' || *p == '\t') ++p;
  strncpy(ep->procMapName, p, sizeof(ep->procMapName) - 1);
  return 0;
}

/// parse /proc/<pid>/maps
int proc_get_map_entries(pid_t pid, struct ProcMapEntry* ep, int size) {
  int fd = -1, res = 0;
  char mapsFile[32];

  snprintf(mapsFile, 32, "/proc/%u/maps", pid);
  fd = open(mapsFile, O_RDONLY);
  if (fd < 0) {
    perror("Failed to open /proc/self/maps");
    return 0;
  }

  unsigned long buffer_size = 0x100000;
  unsigned char* buffer = (unsigned char*)mmap(
      0, buffer_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1,
      0);
  VERIFY(buffer != (unsigned char*)-1L);

  unsigned long nr = 0;
  char *line = NULL, *text = (char*)buffer;

  while (1) {
    long nb = read(fd, buffer + nr, buffer_size - nr);
    if (nb < 0) {
      if (errno == EINTR) continue;
      goto out;
    } else if (nb == 0) {
      break;
    } else {
      nr += nb;
    }
  }
  close(fd);
  buffer[nr] = '\0';

  struct ProcMapEntry mapEntry;
  while (res < size && (line = strsep(&text, "\n")) != NULL) {
    if (parse_entry(line, &ep[res]) == 0) {
      ++res;
    }
  }

out:
  if (fd >= 0) close(fd);
  munmap(buffer, buffer_size);
  return res;
}

static const char* vdsoGetFuncNames(enum VDSOFunc func) {
  switch (func) {
  case VDSO_clock_gettime:
    return "__vdso_clock_gettime";
  case VDSO_getcpu:
    return "__vdso_getcpu";
  case VDSO_gettimeofday:
    return "__vdso_gettimeofday";
  case VDSO_time:
    return "__vdso_time";
    // no default let the compiler do exhaustive check
  }
}

/// parse [vdso] and [vvar] from /proc/pid/maps.
/// returns 0 on success, -1 on failure.
/// caller to verify vdso/vvar have been updated.
int proc_get_vdso_vvar(
    pid_t pid, struct ProcMapEntry* vdso, struct ProcMapEntry* vvar) {
  const long buff_size = 2L << 20;
  char mapsFile[32];
  char* buff;
  snprintf(mapsFile, 32, "/proc/%d/maps", pid);

  buff = (char*)mmap(
      0, buff_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  VERIFY((unsigned char*)buff != (unsigned char*)-1UL);

  int fd = open(mapsFile, O_RDONLY);
  VERIFY(fd >= 0);

  unsigned long nr = 0;
  while (nr < buff_size - 1) {
    long nb = read(fd, buff + nr, buff_size - nr);
    if (nb < 0) {
      if (errno == EINTR) continue;
      break;
    } else if (nb == 0) {
      break;
    } else {
      nr += nb;
    }
  }
  buff[nr] = '\0';
  VERIFY(close(fd) == 0);

  // we cannot stat procfs.
  long file_size = nr;
  VERIFY(file_size >= 0);

  const long page_size = 4096;

  long off = file_size >= page_size ? file_size - page_size : 0;

  // s -> skip the first (likely partial) line.
  char* s = (char*)((unsigned char*)buff + off);
  while (s && *s && *s != '\n' && *s != '\0') ++s;
  while (s && *s == '\n' && *s != '\0') ++s;

  struct ProcMapEntry mapEntry;
  char* line;

  while ((line = strsep(&s, "\n")) != NULL) {
    if (parse_entry(line, &mapEntry) != 0) {
      return -1;
    }
    if (strcmp(mapEntry.procMapName, "[vdso]") == 0) {
      if (vdso) {
        memcpy(vdso, &mapEntry, sizeof(mapEntry));
      }
    } else if (strcmp(mapEntry.procMapName, "[vvar]") == 0) {
      if (vvar) {
        memcpy(vvar, &mapEntry, sizeof(mapEntry));
      }
    } else {
      continue;
    }
  }

  VERIFY(munmap(buff, buff_size) == 0);

  return 0;
}

/// get vdso symbols from vdso
/// returns number of vdso functions found.
int proc_get_vdso_symbols(
    struct ProcMapEntry* vdso_entry, struct VDSOSymbol* vdso, int size) {
  int res = 0;

  unsigned long base = vdso_entry->procMapBase;
  Elf64_Ehdr* ehdr = (Elf64_Ehdr*)base;
  Elf64_Shdr *shbase = (Elf64_Shdr*)(base + ehdr->e_shoff), *dynsym = NULL;
  const char* strtab = NULL;

  for (int i = 0; i < ehdr->e_shnum; i++) {
    Elf64_Shdr* sh = &shbase[i];
    if (sh->sh_type == SHT_DYNSYM) {
      dynsym = sh;
    } else if (sh->sh_type == SHT_STRTAB && (sh->sh_flags & SHF_ALLOC)) {
      strtab = (const char*)(base + sh->sh_offset);
    }
  }

  if (!dynsym || !strtab) return res;

  for (int i = 0; i < dynsym->sh_size / dynsym->sh_entsize && res < size; i++) {
    Elf64_Sym* sym =
        (Elf64_Sym*)(base + dynsym->sh_offset + i * dynsym->sh_entsize);
    const char* name = (const char*)((unsigned long)strtab + sym->st_name);
    if (ELF64_ST_BIND(sym->st_info) == STB_GLOBAL &&
        ELF64_ST_TYPE(sym->st_info) == STT_FUNC) {
      VERIFY(sym->st_shndx < ehdr->e_shnum);
      unsigned long alignment = sym->st_shndx < ehdr->e_shnum
                                    ? shbase[sym->st_shndx].sh_addralign
                                    : 16;
      if (strcmp("__vdso_clock_gettime", name) == 0) {
        vdso[res].func = VDSO_clock_gettime;
        vdso[res].code_size = sizeof(__vdso_clock_gettime);
        vdso[res].code = (const unsigned char*)__vdso_clock_gettime;
      } else if (strcmp("__vdso_getcpu", name) == 0) {
        vdso[res].func = VDSO_getcpu;
        vdso[res].code_size = sizeof(__vdso_getcpu);
        vdso[res].code = (const unsigned char*)__vdso_getcpu;
      } else if (strcmp("__vdso_gettimeofday", name) == 0) {
        vdso[res].func = VDSO_gettimeofday;
        vdso[res].code_size = sizeof(__vdso_gettimeofday);
        vdso[res].code = (const unsigned char*)__vdso_gettimeofday;
      } else if (strcmp("__vdso_time", name) == 0) {
        vdso[res].func = VDSO_time;
        vdso[res].code_size = sizeof(__vdso_time);
        vdso[res].code = (const unsigned char*)__vdso_time;
      } else {
        continue;
      }
      vdso[res].offset = sym->st_value;
      vdso[res].size = sym->st_size;
      vdso[res].alignment = alignment;
      ++res;
    }
  }
  return res;
}
