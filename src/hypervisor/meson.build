hypervisor_sources = [
  'domain_cgroup.c',
  'domain_driver.c',
  'virclosecallbacks.c',
  'virhostdev.c',
]

stateful_driver_source_files += files(hypervisor_sources)

hypervisor_lib = static_library(
  'virt_hypervisor',
  [
    hypervisor_sources,
  ],
  dependencies: [
    access_dep,
    src_dep,
  ],
  include_directories: [
    conf_inc_dir,
    util_inc_dir,
  ],
)

libvirt_libs += hypervisor_lib

hypervisor_inc_dir = include_directories('.')
