lock_driver_sources = [
  'lock_manager.c',
  'lock_driver_nop.c',
  'domain_lock.c',
]

lock_driver_lib = static_library(
  'virt_lock_driver',
  [
    lock_driver_sources,
  ],
  dependencies: [
    src_dep,
  ],
  include_directories: [
    conf_inc_dir,
  ],
)
