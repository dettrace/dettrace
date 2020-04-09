#include <stdio.h>
#include <stdlib.h>
#include <cpuid.h>
// #include <immintrin.h>

#include "util/assert.h"

char vendor_id[12];
unsigned version;
unsigned features;

void clean_string(char* str) {
  while ( ('a' <= *str && *str <= 'z') ||
          ('A' <= *str && *str <= 'Z'))
    str++;
  *str = 0; // Null terminate.
}

int main(void) 
{
  printf("Probing with eax=0 for vendor info...");
  
  // Method (1) Probe using raw assembly
  // ----------------------------------------
  __asm__ (".intel_syntax;"
           "push    rax;"
           "push    rbx;"
           "push    rcx;"
           "push    rdx;"
           // get vendor id 
           "mov     eax,0;"
           "cpuid;"
           "mov     [vendor_id],ebx;"
           "mov     [vendor_id+4],edx;"
           "mov     [vendor_id+8],ecx;"

           // get version and features
           "mov     eax,1;"
           "cpuid;"
           "mov     [version],eax;"
           "mov     [features],ecx;"
                
           "pop     rax;"
           "pop     rcx;"
           "pop     rbx;"
           "pop     rax;"
           );

  clean_string(vendor_id);
  printf("\nvendor_id is %s", vendor_id);

  printf("Probing with eax=1 for version and features...");
  printf("\nversion is 0x%04X", version);
  printf("\nfeatures are 0x%04X\n\n", features);
  
  #ifdef __RDRND__
  printf("C compiler thinks RDRAND is on...\n");
  #else
  printf("C compiler thinks RDRAND is OFF...\n");
  #endif

  // (2) Probe using what's provided from cpuid.h
  // --------------------------------------------
  printf("Using cpuid.h:\n");
  unsigned int sig=0;
  // NOTE: ext=0 for basic, ext=0x80000000 for "extended"
  unsigned int ext=0;
  // unsigned int ext=0x80000000;
  int max_level = __get_cpuid_max(ext,&sig);
  printf("Highest supported __get_cpuid input (aka eax value, cpuid leaf): %d\n",max_level);

  unsigned int eax=0,ebx=0,ecx=0,edx=0;
  for(int i=0; i<1; i++) {
    assert(__get_cpuid(1, &eax,&ebx,&ecx,&edx) == 1);
    printf("Result of __get_cpuid(1) eax|ebx|ecx|edx: %08X %08X %08X %08X\n",
           eax,ebx,ecx,edx);
  }

  char* orig_supports = (char*)malloc(4096);
  char* orig_doesnot  = (char*)malloc(4096);
  char* supports = orig_supports;
  char* doesnot  = orig_doesnot;

  if(edx & 1) supports += sprintf(supports, "fpu ");
  
  // printf("  supports : %d\n", edx & bit_);
  if(edx & bit_CMPXCHG8B) supports += sprintf(supports, "CMPXCHG8B ");
  if(edx & bit_CMOV) supports += sprintf(supports, "CMOV ");
  if(edx & bit_MMX) supports += sprintf(supports, "MMX ");
  if(edx & bit_FXSAVE) supports += sprintf(supports, "FXSAVE ");
  if(edx & bit_SSE) supports += sprintf(supports, "SSE ");
  if(edx & bit_SSE2) supports += sprintf(supports, "SSE2 ");

  if(!(edx & bit_CMPXCHG8B)) doesnot += sprintf(doesnot, "CMPXCHG8B ");
  if(!(edx & bit_CMOV)) doesnot += sprintf(doesnot, "CMOV ");
  if(!(edx & bit_MMX)) doesnot += sprintf(doesnot, "MMX ");
  if(!(edx & bit_FXSAVE)) doesnot += sprintf(doesnot, "FXSAVE ");
  if(!(edx & bit_SSE)) doesnot += sprintf(doesnot, "SSE ");
  if(!(edx & bit_SSE2)) doesnot += sprintf(doesnot, "SSE2 ");

  
  if(ecx & bit_SSE3) supports += sprintf(supports, "SSE3 ");
  if(ecx & bit_PCLMUL) supports += sprintf(supports, "PCLMUL ");
  // if(ecx & bit_LZCNT) supports += sprintf(supports, "LZCNT ");
  if(ecx & bit_SSSE3) supports += sprintf(supports, "SSSE3 ");
  if(ecx & bit_FMA) supports += sprintf(supports, "FMA ");
  if(ecx & bit_CMPXCHG16B) supports += sprintf(supports, "CMPXCHG16B ");
  if(ecx & bit_SSE4_1) supports += sprintf(supports, "SSE4_1 ");
  if(ecx & bit_SSE4_2) supports += sprintf(supports, "SSE4_2 ");
  if(ecx & bit_MOVBE) supports += sprintf(supports, "MOVBE ");
  if(ecx & bit_POPCNT) supports += sprintf(supports, "POPCNT ");
  if(ecx & bit_AES) supports += sprintf(supports, "AES ");
  if(ecx & bit_XSAVE) supports += sprintf(supports, "XSAVE ");
  if(ecx & bit_OSXSAVE) supports += sprintf(supports, "OSXSAVE ");
  if(ecx & bit_AVX) supports += sprintf(supports, "AVX ");
  if(ecx & bit_F16C) supports += sprintf(supports, "F16C ");
  if(ecx & bit_RDRND) supports += sprintf(supports, "RDRND ");

  if(!(ecx & bit_SSE3)) doesnot += sprintf(doesnot, "SSE3 ");
  if(!(ecx & bit_PCLMUL)) doesnot += sprintf(doesnot, "PCLMUL ");
  // if(!(ecx & bit_LZCNT)) doesnot += sprintf(doesnot, "LZCNT ");
  if(!(ecx & bit_SSSE3)) doesnot += sprintf(doesnot, "SSSE3 ");
  if(!(ecx & bit_FMA)) doesnot += sprintf(doesnot, "FMA ");
  if(!(ecx & bit_CMPXCHG16B)) doesnot += sprintf(doesnot, "CMPXCHG16B ");
  if(!(ecx & bit_SSE4_1)) doesnot += sprintf(doesnot, "SSE4_1 ");
  if(!(ecx & bit_SSE4_2)) doesnot += sprintf(doesnot, "SSE4_2 ");
  if(!(ecx & bit_MOVBE)) doesnot += sprintf(doesnot, "MOVBE ");
  if(!(ecx & bit_POPCNT)) doesnot += sprintf(doesnot, "POPCNT ");
  if(!(ecx & bit_AES)) doesnot += sprintf(doesnot, "AES ");
  if(!(ecx & bit_XSAVE)) doesnot += sprintf(doesnot, "XSAVE ");
  if(!(ecx & bit_OSXSAVE)) doesnot += sprintf(doesnot, "OSXSAVE ");
  if(!(ecx & bit_AVX)) doesnot += sprintf(doesnot, "AVX ");
  if(!(ecx & bit_F16C)) doesnot += sprintf(doesnot, "F16C ");
  if(!(ecx & bit_RDRND)) doesnot += sprintf(doesnot, "RDRND ");
  
  supports += sprintf(supports, " (extended/ecx:) ");
  if(ecx & bit_LAHF_LM) supports += sprintf(supports, "LAHF_LM ");
  if(ecx & bit_ABM) supports += sprintf(supports, "ABM ");
  if(ecx & bit_SSE4a) supports += sprintf(supports, "SSE4a ");
  if(ecx & bit_PRFCHW) supports += sprintf(supports, "PRFCHW ");
  if(ecx & bit_XOP) supports += sprintf(supports, "XOP ");
  if(ecx & bit_LWP) supports += sprintf(supports, "LWP ");
  if(ecx & bit_FMA4) supports += sprintf(supports, "FMA4 ");
  if(ecx & bit_TBM) supports += sprintf(supports, "TBM ");
  if(ecx & bit_MWAITX) supports += sprintf(supports, "MWAITX ");


  if(!(ecx & bit_LAHF_LM)) doesnot += sprintf(doesnot, "LAHF_LM ");
  if(!(ecx & bit_ABM)) doesnot += sprintf(doesnot, "ABM ");
  if(!(ecx & bit_SSE4a)) doesnot += sprintf(doesnot, "SSE4a ");
  if(!(ecx & bit_PRFCHW)) doesnot += sprintf(doesnot, "PRFCHW ");
  if(!(ecx & bit_XOP)) doesnot += sprintf(doesnot, "XOP ");
  if(!(ecx & bit_LWP)) doesnot += sprintf(doesnot, "LWP ");
  if(!(ecx & bit_FMA4)) doesnot += sprintf(doesnot, "FMA4 ");
  if(!(ecx & bit_TBM)) doesnot += sprintf(doesnot, "TBM ");
  if(!(ecx & bit_MWAITX)) doesnot += sprintf(doesnot, "MWAITX ");

  *supports = 0;
  *doesnot  = 0;
  printf("  supported features: %s\n", orig_supports);
  printf("  unsupported features: %s\n", orig_doesnot);
  supports = orig_supports;
  doesnot  = orig_doesnot;

  if (max_level < 7) {
    printf("Extended Features (eax==7) not supported.\n");
    printf("Exiting successfully.\n");
    return 0;
  }

  printf("\n   Extended Features (eax == 7)\n");
  printf(  "   ----------------------------\n");
  for(int i=0; i<1; i++) {
    assert(1 == __get_cpuid(7, &eax,&ebx,&ecx,&edx));
    printf("Result of __get_cpuid(7) eax|ebx|ecx|edx: %08X %08X %08X %08X\n",
           eax,ebx,ecx,edx);
  }
   
/* /\* %ebx *\/ */
  if (bit_FSGSBASE & ebx) supports += sprintf(supports, " FSGSBASE");
  else doesnot += sprintf(doesnot, " FSGSBASE");
  if (bit_BMI & ebx) supports += sprintf(supports, " BMI");
  else doesnot += sprintf(doesnot, " BMI");
  if (bit_HLE & ebx) supports += sprintf(supports, " HLE");
  else doesnot += sprintf(doesnot, " HLE");
  if (bit_AVX2 & ebx) supports += sprintf(supports, " AVX2");
  else doesnot += sprintf(doesnot, " AVX2");
  if (bit_BMI2 & ebx) supports += sprintf(supports, " BMI2");
  else doesnot += sprintf(doesnot, " BMI2");
  if (bit_RTM & ebx) supports += sprintf(supports, " RTM");
  else doesnot += sprintf(doesnot, " RTM");
  if (bit_MPX & ebx) supports += sprintf(supports, " MPX");
  else doesnot += sprintf(doesnot, " MPX");
  if (bit_AVX512F & ebx) supports += sprintf(supports, " AVX512F");
  else doesnot += sprintf(doesnot, " AVX512F");
  if (bit_AVX512DQ & ebx) supports += sprintf(supports, " AVX512DQ");
  else doesnot += sprintf(doesnot, " AVX512DQ");
  if (bit_RDSEED & ebx) supports += sprintf(supports, " RDSEED");
  else doesnot += sprintf(doesnot, " RDSEED");
  if (bit_ADX & ebx) supports += sprintf(supports, " ADX");
  else doesnot += sprintf(doesnot, " ADX");
  if (bit_AVX512IFMA & ebx) supports += sprintf(supports, " AVX512IFMA");
  else doesnot += sprintf(doesnot, " AVX512IFMA");
  //  if (bit_PCOMMIT & ebx) supports += sprintf(supports, " PCOMMIT");
  //  else doesnot += sprintf(doesnot, " PCOMMIT");
  if (bit_CLFLUSHOPT & ebx) supports += sprintf(supports, " CLFLUSHOPT");
  else doesnot += sprintf(doesnot, " CLFLUSHOPT");
  if (bit_CLWB & ebx) supports += sprintf(supports, " CLWB");
  else doesnot += sprintf(doesnot, " CLWB");
  if (bit_AVX512PF & ebx) supports += sprintf(supports, " AVX512PF");
  else doesnot += sprintf(doesnot, " AVX512PF");
  /* if (bit_AVX512ER & ebx) supports += sprintf(supports, " AVX512ER"); */
  /* else doesnot += sprintf(doesnot, " AVX512ER"); */
  if (bit_AVX512CD & ebx) supports += sprintf(supports, " AVX512CD");
  else doesnot += sprintf(doesnot, " AVX512CD");
  if (bit_SHA & ebx) supports += sprintf(supports, " SHA");
  else doesnot += sprintf(doesnot, " SHA");
  if (bit_AVX512BW & ebx) supports += sprintf(supports, " AVX512BW");
  else doesnot += sprintf(doesnot, " AVX512BW");
  if (bit_AVX512VL & ebx) supports += sprintf(supports, " AVX512VL");
  else doesnot += sprintf(doesnot, " AVX512VL");
  
  /* %ecx */
  /* if (bit_PREFETCHWT1 & ecx) supports += sprintf(supports, " PREFETCHWT1"); */
  /* else doesnot += sprintf(doesnot, " PREFETCHWT1"); */
  if (bit_AVX512VBMI & ecx) supports += sprintf(supports, " AVX512VBMI");
  else doesnot += sprintf(doesnot, " AVX512VBMI");

  /* XFEATURE_ENABLED_MASK register bits (%eax == 13, %ecx == 0) */
  /* #define bit_BNDREGS     (1 << 3) */
  /* #define bit_BNDCSR      (1 << 4) */

  /* Extended State Enumeration Sub-leaf (%eax == 13, %ecx == 1) */
  /* #define bit_XSAVEOPT	(1 << 0) */
  /* #define bit_XSAVEC	(1 << 1) */
  /* #define bit_XSAVES	(1 << 3) */

  *supports = 0;
  *doesnot  = 0;
  printf("  supported features: %s\n", orig_supports);
  printf("  UNsupported features: %s\n", orig_doesnot);  

  printf("\nNow dumping ALL CPUID results in raw form:\n");
  for(int level=0; level <= max_level; level++) {
    assert(1 == __get_cpuid(level, &eax,&ebx,&ecx,&edx));
    printf("__get_cpuid(%d) eax|ebx|ecx|edx: %08X %08X %08X %08X\n",
           level,eax,ebx,ecx,edx);
  }

  {
    long ext=0x80000000;
    unsigned long max_level = (long)(unsigned)__get_cpuid_max(ext,&sig);
    printf("Highest supported __get_cpuid (extended) input (aka eax value, cpuid leaf): %ld\n",max_level);
    for(long level=ext; level <= max_level; level++) {
      assert(1 == __get_cpuid(level, &eax,&ebx,&ecx,&edx));
      printf("__get_cpuid(%lx) eax|ebx|ecx|edx: { %08X, %08X, %08X, %08X, },\n",
            level,eax,ebx,ecx,edx);
    }
  }

  printf("Exiting successfully.\n");
  return 0;
}
