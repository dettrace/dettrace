#include <stdio.h>

/* Defined in utils.asm */
/* extern void GetCpuID(void); */
/* extern char vendor_id[12]; */
/* extern unsigned version; */
/* extern unsigned features; */

char vendor_id[12];
unsigned version;
unsigned features;

int main(void) 
{
  //  GetCpuID();

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
           "mov     [features],edx;"
                
           "pop     rax;"
           "pop     rcx;"
           "pop     rbx;"
           "pop     rax;"
           );
  
  printf("\nvendor_id is %s", vendor_id);
  printf("\nversion is 0x%04X", version);
  printf("\nfeatures are 0x%04X\n\n", features);
  return 0;
}
