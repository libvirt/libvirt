hypervisor_sources = [
  'domain_cgroup.c',
  'domain_driver.c',
  'virclosecallbacks.c',
  'virhostdev.c',
]

hypervisor_lib = static_library(
  'virt_hypervisor',
  [
    hypervisor_sources,
  ],
  dependencies: [
    src_dep,
  ],
  include_directories: [
    conf_inc_dir,
  ],
)

libvirt_libs += hypervisor_lib

hypervisor_inc_dir = include_directories('.')
