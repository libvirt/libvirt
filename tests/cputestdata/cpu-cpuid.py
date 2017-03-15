#!/usr/bin/python2

import sys
import json

# This is a list of x86 CPU features as of QEMU 2.8.50 and it won't need any
# updates since in the future because query-cpu-model-expansion will be used
# with newer QEMU.
cpuidMap = [
    {"in_eax": 0x00000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0x00000001, "edx": 0, "names": ["pni", "sse3"]},
    {"in_eax": 0x00000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0x00000002, "edx": 0, "names": ["pclmulqdq", "pclmuldq"]},
    {"in_eax": 0x00000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0x00000004, "edx": 0, "names": ["dtes64"]},
    {"in_eax": 0x00000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0x00000008, "edx": 0, "names": ["monitor"]},
    {"in_eax": 0x00000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0x00000010, "edx": 0, "names": ["ds-cpl", "ds_cpl"]},
    {"in_eax": 0x00000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0x00000020, "edx": 0, "names": ["vmx"]},
    {"in_eax": 0x00000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0x00000040, "edx": 0, "names": ["smx"]},
    {"in_eax": 0x00000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0x00000080, "edx": 0, "names": ["est"]},
    {"in_eax": 0x00000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0x00000100, "edx": 0, "names": ["tm2"]},
    {"in_eax": 0x00000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0x00000200, "edx": 0, "names": ["ssse3"]},
    {"in_eax": 0x00000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0x00000400, "edx": 0, "names": ["cid"]},
    {"in_eax": 0x00000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0x00001000, "edx": 0, "names": ["fma"]},
    {"in_eax": 0x00000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0x00002000, "edx": 0, "names": ["cx16"]},
    {"in_eax": 0x00000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0x00004000, "edx": 0, "names": ["xtpr"]},
    {"in_eax": 0x00000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0x00008000, "edx": 0, "names": ["pdcm"]},
    {"in_eax": 0x00000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0x00020000, "edx": 0, "names": ["pcid"]},
    {"in_eax": 0x00000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0x00040000, "edx": 0, "names": ["dca"]},
    {"in_eax": 0x00000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0x00080000, "edx": 0, "names": ["sse4.1", "sse4-1", "sse4_1"]},
    {"in_eax": 0x00000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0x00100000, "edx": 0, "names": ["sse4.2", "sse4-2", "sse4_2"]},
    {"in_eax": 0x00000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0x00200000, "edx": 0, "names": ["x2apic"]},
    {"in_eax": 0x00000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0x00400000, "edx": 0, "names": ["movbe"]},
    {"in_eax": 0x00000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0x00800000, "edx": 0, "names": ["popcnt"]},
    {"in_eax": 0x00000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0x01000000, "edx": 0, "names": ["tsc-deadline"]},
    {"in_eax": 0x00000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0x02000000, "edx": 0, "names": ["aes"]},
    {"in_eax": 0x00000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0x04000000, "edx": 0, "names": ["xsave"]},
    {"in_eax": 0x00000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0x08000000, "edx": 0, "names": ["osxsave"]},
    {"in_eax": 0x00000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0x10000000, "edx": 0, "names": ["avx"]},
    {"in_eax": 0x00000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0x20000000, "edx": 0, "names": ["f16c"]},
    {"in_eax": 0x00000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0x40000000, "edx": 0, "names": ["rdrand"]},
    {"in_eax": 0x00000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0x80000000, "edx": 0, "names": ["hypervisor"]},
    {"in_eax": 0x00000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0, "edx": 0x00000001, "names": ["fpu"]},
    {"in_eax": 0x00000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0, "edx": 0x00000002, "names": ["vme"]},
    {"in_eax": 0x00000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0, "edx": 0x00000004, "names": ["de"]},
    {"in_eax": 0x00000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0, "edx": 0x00000008, "names": ["pse"]},
    {"in_eax": 0x00000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0, "edx": 0x00000010, "names": ["tsc"]},
    {"in_eax": 0x00000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0, "edx": 0x00000020, "names": ["msr"]},
    {"in_eax": 0x00000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0, "edx": 0x00000040, "names": ["pae"]},
    {"in_eax": 0x00000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0, "edx": 0x00000080, "names": ["mce"]},
    {"in_eax": 0x00000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0, "edx": 0x00000100, "names": ["cx8"]},
    {"in_eax": 0x00000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0, "edx": 0x00000200, "names": ["apic"]},
    {"in_eax": 0x00000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0, "edx": 0x00000800, "names": ["sep"]},
    {"in_eax": 0x00000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0, "edx": 0x00001000, "names": ["mtrr"]},
    {"in_eax": 0x00000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0, "edx": 0x00002000, "names": ["pge"]},
    {"in_eax": 0x00000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0, "edx": 0x00004000, "names": ["mca"]},
    {"in_eax": 0x00000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0, "edx": 0x00008000, "names": ["cmov"]},
    {"in_eax": 0x00000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0, "edx": 0x00010000, "names": ["pat"]},
    {"in_eax": 0x00000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0, "edx": 0x00020000, "names": ["pse36"]},
    {"in_eax": 0x00000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0, "edx": 0x00040000, "names": ["pn"]},
    {"in_eax": 0x00000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0, "edx": 0x00080000, "names": ["clflush"]},
    {"in_eax": 0x00000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0, "edx": 0x00200000, "names": ["ds"]},
    {"in_eax": 0x00000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0, "edx": 0x00400000, "names": ["acpi"]},
    {"in_eax": 0x00000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0, "edx": 0x00800000, "names": ["mmx"]},
    {"in_eax": 0x00000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0, "edx": 0x01000000, "names": ["fxsr"]},
    {"in_eax": 0x00000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0, "edx": 0x02000000, "names": ["sse"]},
    {"in_eax": 0x00000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0, "edx": 0x04000000, "names": ["sse2"]},
    {"in_eax": 0x00000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0, "edx": 0x08000000, "names": ["ss"]},
    {"in_eax": 0x00000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0, "edx": 0x10000000, "names": ["ht"]},
    {"in_eax": 0x00000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0, "edx": 0x20000000, "names": ["tm"]},
    {"in_eax": 0x00000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0, "edx": 0x40000000, "names": ["ia64"]},
    {"in_eax": 0x00000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0, "edx": 0x80000000, "names": ["pbe"]},
    {"in_eax": 0x00000006, "in_ecx": 0, "eax": 0x00000004, "ebx": 0, "ecx": 0, "edx": 0, "names": ["arat"]},
    {"in_eax": 0x00000007, "in_ecx": 0, "eax": 0, "ebx": 0x00000001, "ecx": 0, "edx": 0, "names": ["fsgsbase"]},
    {"in_eax": 0x00000007, "in_ecx": 0, "eax": 0, "ebx": 0x00000002, "ecx": 0, "edx": 0, "names": ["tsc-adjust", "tsc_adjust"]},
    {"in_eax": 0x00000007, "in_ecx": 0, "eax": 0, "ebx": 0x00000008, "ecx": 0, "edx": 0, "names": ["bmi1"]},
    {"in_eax": 0x00000007, "in_ecx": 0, "eax": 0, "ebx": 0x00000010, "ecx": 0, "edx": 0, "names": ["hle"]},
    {"in_eax": 0x00000007, "in_ecx": 0, "eax": 0, "ebx": 0x00000020, "ecx": 0, "edx": 0, "names": ["avx2"]},
    {"in_eax": 0x00000007, "in_ecx": 0, "eax": 0, "ebx": 0x00000080, "ecx": 0, "edx": 0, "names": ["smep"]},
    {"in_eax": 0x00000007, "in_ecx": 0, "eax": 0, "ebx": 0x00000100, "ecx": 0, "edx": 0, "names": ["bmi2"]},
    {"in_eax": 0x00000007, "in_ecx": 0, "eax": 0, "ebx": 0x00000200, "ecx": 0, "edx": 0, "names": ["erms"]},
    {"in_eax": 0x00000007, "in_ecx": 0, "eax": 0, "ebx": 0x00000400, "ecx": 0, "edx": 0, "names": ["invpcid"]},
    {"in_eax": 0x00000007, "in_ecx": 0, "eax": 0, "ebx": 0x00000800, "ecx": 0, "edx": 0, "names": ["rtm"]},
    {"in_eax": 0x00000007, "in_ecx": 0, "eax": 0, "ebx": 0x00004000, "ecx": 0, "edx": 0, "names": ["mpx"]},
    {"in_eax": 0x00000007, "in_ecx": 0, "eax": 0, "ebx": 0x00010000, "ecx": 0, "edx": 0, "names": ["avx512f"]},
    {"in_eax": 0x00000007, "in_ecx": 0, "eax": 0, "ebx": 0x00020000, "ecx": 0, "edx": 0, "names": ["avx512dq"]},
    {"in_eax": 0x00000007, "in_ecx": 0, "eax": 0, "ebx": 0x00040000, "ecx": 0, "edx": 0, "names": ["rdseed"]},
    {"in_eax": 0x00000007, "in_ecx": 0, "eax": 0, "ebx": 0x00080000, "ecx": 0, "edx": 0, "names": ["adx"]},
    {"in_eax": 0x00000007, "in_ecx": 0, "eax": 0, "ebx": 0x00100000, "ecx": 0, "edx": 0, "names": ["smap"]},
    {"in_eax": 0x00000007, "in_ecx": 0, "eax": 0, "ebx": 0x00200000, "ecx": 0, "edx": 0, "names": ["avx512ifma"]},
    {"in_eax": 0x00000007, "in_ecx": 0, "eax": 0, "ebx": 0x00400000, "ecx": 0, "edx": 0, "names": ["pcommit"]},
    {"in_eax": 0x00000007, "in_ecx": 0, "eax": 0, "ebx": 0x00800000, "ecx": 0, "edx": 0, "names": ["clflushopt"]},
    {"in_eax": 0x00000007, "in_ecx": 0, "eax": 0, "ebx": 0x01000000, "ecx": 0, "edx": 0, "names": ["clwb"]},
    {"in_eax": 0x00000007, "in_ecx": 0, "eax": 0, "ebx": 0x04000000, "ecx": 0, "edx": 0, "names": ["avx512pf"]},
    {"in_eax": 0x00000007, "in_ecx": 0, "eax": 0, "ebx": 0x08000000, "ecx": 0, "edx": 0, "names": ["avx512er"]},
    {"in_eax": 0x00000007, "in_ecx": 0, "eax": 0, "ebx": 0x10000000, "ecx": 0, "edx": 0, "names": ["avx512cd"]},
    {"in_eax": 0x00000007, "in_ecx": 0, "eax": 0, "ebx": 0x20000000, "ecx": 0, "edx": 0, "names": ["sha-ni"]},
    {"in_eax": 0x00000007, "in_ecx": 0, "eax": 0, "ebx": 0x40000000, "ecx": 0, "edx": 0, "names": ["avx512bw"]},
    {"in_eax": 0x00000007, "in_ecx": 0, "eax": 0, "ebx": 0x80000000, "ecx": 0, "edx": 0, "names": ["avx512vl"]},
    {"in_eax": 0x00000007, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0x00000002, "edx": 0, "names": ["avx512vbmi"]},
    {"in_eax": 0x00000007, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0x00000004, "edx": 0, "names": ["umip"]},
    {"in_eax": 0x00000007, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0x00000008, "edx": 0, "names": ["pku"]},
    {"in_eax": 0x00000007, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0x00000010, "edx": 0, "names": ["ospke"]},
    {"in_eax": 0x00000007, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0x00004000, "edx": 0, "names": ["avx512-vpopcntdq"]},
    {"in_eax": 0x00000007, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0x00010000, "edx": 0, "names": ["la57"]},
    {"in_eax": 0x00000007, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0x00400000, "edx": 0, "names": ["rdpid"]},
    {"in_eax": 0x00000007, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0, "edx": 0x00000004, "names": ["avx512-4vnniw"]},
    {"in_eax": 0x00000007, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0, "edx": 0x00000008, "names": ["avx512-4fmaps"]},
    {"in_eax": 0x0000000d, "in_ecx": 1, "eax": 0x00000001, "ebx": 0, "ecx": 0, "edx": 0, "names": ["xsaveopt"]},
    {"in_eax": 0x0000000d, "in_ecx": 1, "eax": 0x00000002, "ebx": 0, "ecx": 0, "edx": 0, "names": ["xsavec"]},
    {"in_eax": 0x0000000d, "in_ecx": 1, "eax": 0x00000004, "ebx": 0, "ecx": 0, "edx": 0, "names": ["xgetbv1"]},
    {"in_eax": 0x0000000d, "in_ecx": 1, "eax": 0x00000008, "ebx": 0, "ecx": 0, "edx": 0, "names": ["xsaves"]},
    {"in_eax": 0x40000001, "in_ecx": 0, "eax": 0x00000001, "ebx": 0, "ecx": 0, "edx": 0, "names": ["kvmclock"]},
    {"in_eax": 0x40000001, "in_ecx": 0, "eax": 0x00000002, "ebx": 0, "ecx": 0, "edx": 0, "names": ["kvm-nopiodelay", "kvm_nopiodelay"]},
    {"in_eax": 0x40000001, "in_ecx": 0, "eax": 0x00000004, "ebx": 0, "ecx": 0, "edx": 0, "names": ["kvm-mmu", "kvm_mmu"]},
    {"in_eax": 0x40000001, "in_ecx": 0, "eax": 0x00000008, "ebx": 0, "ecx": 0, "edx": 0, "names": ["kvmclock"]},
    {"in_eax": 0x40000001, "in_ecx": 0, "eax": 0x00000010, "ebx": 0, "ecx": 0, "edx": 0, "names": ["kvm-asyncpf", "kvm_asyncpf"]},
    {"in_eax": 0x40000001, "in_ecx": 0, "eax": 0x00000020, "ebx": 0, "ecx": 0, "edx": 0, "names": ["kvm-steal-time", "kvm_steal_time"]},
    {"in_eax": 0x40000001, "in_ecx": 0, "eax": 0x00000040, "ebx": 0, "ecx": 0, "edx": 0, "names": ["kvm-pv-eoi", "kvm_pv_eoi"]},
    {"in_eax": 0x40000001, "in_ecx": 0, "eax": 0x00000080, "ebx": 0, "ecx": 0, "edx": 0, "names": ["kvm-pv-unhalt", "kvm_pv_unhalt"]},
    {"in_eax": 0x40000001, "in_ecx": 0, "eax": 0x01000000, "ebx": 0, "ecx": 0, "edx": 0, "names": ["kvmclock-stable-bit"]},
    {"in_eax": 0x80000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0x00000001, "edx": 0, "names": ["lahf-lm", "lahf_lm"]},
    {"in_eax": 0x80000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0x00000002, "edx": 0, "names": ["cmp-legacy", "cmp_legacy"]},
    {"in_eax": 0x80000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0x00000004, "edx": 0, "names": ["svm"]},
    {"in_eax": 0x80000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0x00000008, "edx": 0, "names": ["extapic"]},
    {"in_eax": 0x80000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0x00000010, "edx": 0, "names": ["cr8legacy"]},
    {"in_eax": 0x80000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0x00000020, "edx": 0, "names": ["abm"]},
    {"in_eax": 0x80000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0x00000040, "edx": 0, "names": ["sse4a"]},
    {"in_eax": 0x80000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0x00000080, "edx": 0, "names": ["misalignsse"]},
    {"in_eax": 0x80000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0x00000100, "edx": 0, "names": ["3dnowprefetch"]},
    {"in_eax": 0x80000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0x00000200, "edx": 0, "names": ["osvw"]},
    {"in_eax": 0x80000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0x00000400, "edx": 0, "names": ["ibs"]},
    {"in_eax": 0x80000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0x00000800, "edx": 0, "names": ["xop"]},
    {"in_eax": 0x80000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0x00001000, "edx": 0, "names": ["skinit"]},
    {"in_eax": 0x80000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0x00002000, "edx": 0, "names": ["wdt"]},
    {"in_eax": 0x80000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0x00008000, "edx": 0, "names": ["lwp"]},
    {"in_eax": 0x80000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0x00010000, "edx": 0, "names": ["fma4"]},
    {"in_eax": 0x80000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0x00020000, "edx": 0, "names": ["tce"]},
    {"in_eax": 0x80000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0x00080000, "edx": 0, "names": ["nodeid-msr", "nodeid_msr"]},
    {"in_eax": 0x80000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0x00200000, "edx": 0, "names": ["tbm"]},
    {"in_eax": 0x80000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0x00400000, "edx": 0, "names": ["topoext"]},
    {"in_eax": 0x80000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0x00800000, "edx": 0, "names": ["perfctr-core", "perfctr_core"]},
    {"in_eax": 0x80000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0x01000000, "edx": 0, "names": ["perfctr-nb", "perfctr_nb"]},
    {"in_eax": 0x80000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0, "edx": 0x00000800, "names": ["syscall"]},
    {"in_eax": 0x80000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0, "edx": 0x00100000, "names": ["nx", "xd"]},
    {"in_eax": 0x80000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0, "edx": 0x00400000, "names": ["mmxext"]},
    {"in_eax": 0x80000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0, "edx": 0x02000000, "names": ["fxsr-opt", "ffxsr", "fxsr_opt"]},
    {"in_eax": 0x80000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0, "edx": 0x04000000, "names": ["pdpe1gb"]},
    {"in_eax": 0x80000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0, "edx": 0x08000000, "names": ["rdtscp"]},
    {"in_eax": 0x80000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0, "edx": 0x20000000, "names": ["lm", "i64"]},
    {"in_eax": 0x80000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0, "edx": 0x40000000, "names": ["3dnowext"]},
    {"in_eax": 0x80000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0, "edx": 0x80000000, "names": ["3dnow"]},
    {"in_eax": 0x80000007, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0, "edx": 0x00000100, "names": ["invtsc"]},
    {"in_eax": 0x8000000A, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0, "edx": 0x00000001, "names": ["npt"]},
    {"in_eax": 0x8000000A, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0, "edx": 0x00000002, "names": ["lbrv"]},
    {"in_eax": 0x8000000A, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0, "edx": 0x00000004, "names": ["svm-lock", "svm_lock"]},
    {"in_eax": 0x8000000A, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0, "edx": 0x00000008, "names": ["nrip-save", "nrip_save"]},
    {"in_eax": 0x8000000A, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0, "edx": 0x00000010, "names": ["tsc-scale", "tsc_scale"]},
    {"in_eax": 0x8000000A, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0, "edx": 0x00000020, "names": ["vmcb-clean", "vmcb_clean"]},
    {"in_eax": 0x8000000A, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0, "edx": 0x00000040, "names": ["flushbyasid"]},
    {"in_eax": 0x8000000A, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0, "edx": 0x00000080, "names": ["decodeassists"]},
    {"in_eax": 0x8000000A, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0, "edx": 0x00000400, "names": ["pause-filter", "pause_filter"]},
    {"in_eax": 0x8000000A, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0, "edx": 0x00001000, "names": ["pfthreshold"]},
    {"in_eax": 0xC0000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0, "edx": 0x00000004, "names": ["xstore"]},
    {"in_eax": 0xC0000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0, "edx": 0x00000008, "names": ["xstore-en"]},
    {"in_eax": 0xC0000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0, "edx": 0x00000040, "names": ["xcrypt"]},
    {"in_eax": 0xC0000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0, "edx": 0x00000080, "names": ["xcrypt-en"]},
    {"in_eax": 0xC0000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0, "edx": 0x00000100, "names": ["ace2"]},
    {"in_eax": 0xC0000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0, "edx": 0x00000200, "names": ["ace2-en"]},
    {"in_eax": 0xC0000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0, "edx": 0x00000400, "names": ["phe"]},
    {"in_eax": 0xC0000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0, "edx": 0x00000800, "names": ["phe-en"]},
    {"in_eax": 0xC0000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0, "edx": 0x00001000, "names": ["pmm"]},
    {"in_eax": 0xC0000001, "in_ecx": 0, "eax": 0, "ebx": 0, "ecx": 0, "edx": 0x00002000, "names": ["pmm-en"]},
]


def cpuidIsSet(cpuid, feature):
    in_eax = feature["in_eax"]
    in_ecx = feature["in_ecx"]
    eax = feature["eax"]
    ebx = feature["ebx"]
    ecx = feature["ecx"]
    edx = feature["edx"]

    if in_eax not in cpuid or in_ecx not in cpuid[in_eax]:
        return False
    else:
        leaf = cpuid[in_eax][in_ecx]
        return ((eax > 0 and leaf["eax"] & eax > 0) or
                (ebx > 0 and leaf["ebx"] & ebx > 0) or
                (ecx > 0 and leaf["ecx"] & ecx > 0) or
                (edx > 0 and leaf["edx"] & edx > 0))


def parseFeatureWords(path):
    features = None

    dec = json.JSONDecoder()

    with open(path, "r") as f:
        s = f.read()

    props = {}
    for i in range(5):
        (data, pos) = dec.raw_decode(s)
        if i == 0:
            features = data["return"]
        else:
            keys = ["family", "model", "stepping", "model-id"]
            props[keys[i - 1]] = data["return"]

        while pos < len(s) and s[pos] != "{":
            pos += 1
        s = s[pos:]

    if props["model-id"].find("Intel") != -1:
        props["vendor"] = "GenuineIntel"
    elif props["model-id"].find("AMD") != -1:
        props["vendor"] = "AuthenticAMD"

    cpuid = {}
    for feat in features:
        in_eax = feat["cpuid-input-eax"]
        in_ecx = 0
        if "cpuid-input-ecx" in feat:
            in_ecx = feat["cpuid-input-ecx"]

        if in_eax not in cpuid:
            cpuid[in_eax] = {}
        leaf = cpuid[in_eax]

        if in_ecx not in leaf:
            leaf[in_ecx] = {"eax": 0, "ebx": 0, "ecx": 0, "edx": 0}
        leaf = leaf[in_ecx]

        leaf[feat["cpuid-register"].lower()] = feat["features"]

    return props, cpuid


def convert(path):
    props, cpuid = parseFeatureWords(path)

    for feature in cpuidMap:
        value = cpuidIsSet(cpuid, feature)
        for name in feature["names"]:
            props[name] = value

    with open(path, "w") as f:
        json.dump({"return": {"model": {"name": "base", "props": props}},
                   "id": "model-expansion"},
                  f, indent = 2, separators = (',', ': '))
        f.write("\n")


if len(sys.argv) < 3:
    print "Usage: %s convert json_file..." % sys.argv[0]
    sys.exit(1)

action = sys.argv[1]
args = sys.argv[2:]

if action == "convert":
    for path in args:
        convert(path)
else:
    print "Unknown action: " + action
    sys.exit(1)
