#include <sys/sysinfo.h>

#include <string>
#include <vector>
#include <sstream>
#include <iterator>

static std::string join(std::vector<std::string> vec, const char* delim) {
  std::ostringstream res;
  std::copy(vec.begin(), vec.end(), std::ostream_iterator<std::string>(res, "\n"));
  return res.str();
}

namespace proc {

  static const unsigned long total_intrs = (1UL + (1UL << 30));
  static const unsigned long total_softirqs = (1UL + (1UL << 30));
  
  std::string filesystems(void) {
    std::vector<std::string> fs =
      {
       "nodev	sysfs",
       "nodev	rootfs",
       "nodev	ramfs",
       "nodev	proc",
       "nodev	cpuset",
       "nodev	cgroup",
       "nodev	cgroup2",
       "nodev	tmpfs",
       "nodev	devtmpfs",
       "nodev	configfs",
       "nodev	debugfs",
       "nodev	tracefs",
       "nodev	pipefs",
       "nodev	hugetlbfs",
       "nodev	devpts",
       "	ext3",
       "	ext2",
       "	ext4",
       "	vfat",
       "	fuseblk",
       "nodev	fuse",
       "nodev	fusectl",
       "nodev	mqueue",
       "	btrfs",
       "nodev	binfmt_misc",
       "nodev	overlay",
      };
    return join(fs, "\n");
  }

  std::string meminfo(void) {
    std::vector<std::string> mi =
      {
       "MemTotal:       16366972 kB",
       "MemFree:         5221232 kB",
       "MemAvailable:   15204036 kB",
       "Buffers:         4037808 kB",
       "Cached:          4162332 kB",
       "SwapCached:            0 kB",
       "Active:          6616004 kB",
       "Inactive:        2131092 kB",
       "Active(anon):     536584 kB",
       "Inactive(anon):      236 kB",
       "Active(file):    6079420 kB",
       "Inactive(file):  2130856 kB",
       "Unevictable:           0 kB",
       "Mlocked:               0 kB",
       "SwapTotal:        999420 kB",
       "SwapFree:         999420 kB",
       "Dirty:                68 kB",
       "Writeback:             0 kB",
       "AnonPages:        544968 kB",
       "Mapped:           306652 kB",
       "Shmem:              1692 kB",
       "Slab:            2197504 kB",
       "SReclaimable:    2104392 kB",
       "SUnreclaim:        93112 kB",
       "KernelStack:       12528 kB",
       "PageTables:        24900 kB",
       "NFS_Unstable:          0 kB",
       "Bounce:                0 kB",
       "WritebackTmp:          0 kB",
       "CommitLimit:     9182904 kB",
       "Committed_AS:    5592004 kB",
       "VmallocTotal:   34359738367 kB",
       "VmallocUsed:           0 kB",
       "VmallocChunk:          0 kB",
       "HardwareCorrupted:     0 kB",
       "AnonHugePages:         0 kB",
       "ShmemHugePages:        0 kB",
       "ShmemPmdMapped:        0 kB",
       "CmaTotal:              0 kB",
       "CmaFree:               0 kB",
       "HugePages_Total:       0",
       "HugePages_Free:        0",
       "HugePages_Rsvd:        0",
       "HugePages_Surp:        0",
       "Hugepagesize:       2048 kB",
       "DirectMap4k:      309996 kB",
       "DirectMap2M:     6971392 kB",
       "DirectMap1G:    10485760 kB",
      };
    return join(mi, "\n");
  }

  struct CpuStats {
    unsigned long user;
    unsigned long nice;
    unsigned long system;
    unsigned long idle;
    unsigned long iowait;
    unsigned long irq;
    unsigned long softirq;
    unsigned long steal;
    unsigned long guest;
    unsigned long guest_nice;
  };

  static void fake_cpu_stats(CpuStats& stats) {
    stats.user = 1000000UL;
    stats.nice = 1000UL;
    stats.system = 3000000UL;
    stats.idle = 10000000UL;
    stats.iowait = 5000000UL;
    stats.irq = 0;
    stats.softirq = 10000;
    stats.steal = 0;
    stats.guest = 0;
    stats.guest_nice = 0;
  }

  std::string interrupts(void) {
    std::string res;
    int ncpus = get_nprocs();

    res += "\t";

    for (int i = 0; i < ncpus; i++) {
      res += "CPU";
      res += std::to_string(i);
      res += "\t";
    }
    res += "\n";
    res += "0:\t";

    for (int i = 0; i < ncpus; i++) {
      if (i == 0) {
	res += "1\t";
      } else {
	res += "0\t";
      }
    }

    res += "IR-IO-APIC\t2-edge\ttimer\n";

    res += "LOC\t";
    for (int i = 0; i < ncpus; i++) {
      res += std::to_string(total_intrs / ncpus);
      res += "\t";
    }
    res += "Local timer interrupts\n";

    return res;
  }

  std::string softirqs(void) {
    std::string res;
    int ncpus = get_nprocs();

    res += "              ";
    for (int i = 0; i < ncpus; i++) {
      res += "CPU";
      res += std::to_string(i);
      res += "\t";
    }
    res += "\n";
    res += "           HI:";
    res += "1\t";
    for (int i = 1; i < ncpus; i++) {
      res += "0\t";
    }
    res += "\n";
    res += "        TIMER:";
    for (int i = 0; i < ncpus; i++) {
      res += std::to_string(total_softirqs / ncpus);
      res += "\t";
    }
    res += "\n";
    return res;
  }
  
  std::string stat(void) {
    std::string res;
    char line[4096];
    int ncpus = get_nprocs();
    CpuStats* stats = new CpuStats[1+ncpus];

    for (int i = 1; i <= ncpus; i++) {
      fake_cpu_stats(stats[i]);
      stats[0].user += stats[i].user;
      stats[0].nice += stats[i].nice;
      stats[0].system += stats[i].system;
      stats[0].idle += stats[i].idle;
      stats[0].iowait += stats[i].iowait;
      stats[0].irq += stats[i].irq;
      stats[0].softirq += stats[i].softirq;
      stats[0].steal += stats[i].steal;
      stats[0].guest += stats[i].guest;
      stats[0].guest_nice += stats[i].guest_nice;
    }

    snprintf(line, 4096, "cpu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu\n",
	     stats[0].user, stats[0].nice, stats[0].system,
	     stats[0].idle, stats[0].iowait, stats[0].irq,
	     stats[0].softirq, stats[0].steal, stats[0].guest,
	     stats[0].guest_nice);
    res += line;
    for (int i = 1; i <= ncpus; i++) {
      snprintf(line, 4096, "cpu%d %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu\n",
	       i-1, stats[i].user, stats[i].nice, stats[i].system,
	       stats[i].idle, stats[i].iowait, stats[i].irq,
	       stats[i].softirq, stats[i].steal, stats[i].guest,
	       stats[i].guest_nice);
      res += line;
    }
    snprintf(line, 4096, "intr %lu %lu\n", 1UL, total_intrs - 1);

    res += line;
    res += "ctxt 100000000\n";
    res += "btime 1000000\n";
    res += "processes 67108864\n";
    res += "procs_running 1\n";
    res += "procs_blocked 0\n";
    snprintf(line, 4096, "softirq %lu %lu %lu\n", stats[0].softirq,
	     1UL, total_softirqs - 1);
    res += line;

    return res;
  }
}
