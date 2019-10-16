#ifndef _MY_FAKEFS_H
#define _MY_FAKEFS_H

#include <sys/sysinfo.h>

#include <iterator>
#include <sstream>
#include <string>
#include <vector>

namespace proc {
std::string filesystems(void);
std::string meminfo(void);
std::string interrupts(void);
std::string softirqs(void);
std::string stat(void);
} // namespace proc

#endif
