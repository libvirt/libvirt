cpu_sources = [
  'cpu.c',
  'cpu_arm.c',
  'cpu_map.c',
  'cpu_ppc64.c',
  'cpu_riscv64.c',
  'cpu_s390.c',
  'cpu_x86.c',
]

cpu_lib = static_library(
  'virt_cpu',
  cpu_sources,
  dependencies: [
    src_dep,
  ],
  include_directories: [
    conf_inc_dir,
  ],
)

libvirt_libs += cpu_lib
