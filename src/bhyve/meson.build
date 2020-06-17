bhyve_sources = files(
  'bhyve_capabilities.c',
  'bhyve_command.c',
  'bhyve_conf.c',
  'bhyve_parse_command.c',
  'bhyve_device.c',
  'bhyve_domain.c',
  'bhyve_driver.c',
  'bhyve_monitor.c',
  'bhyve_process.c',
)

if conf.has('WITH_BHYVE')
  bhyve_driver_impl = static_library(
    'virt_driver_bhyve_impl',
    [
      bhyve_sources,
    ],
    dependencies: [
      access_dep,
      src_dep,
    ],
    include_directories: [
      conf_inc_dir,
      hypervisor_inc_dir,
    ],
  )
endif
