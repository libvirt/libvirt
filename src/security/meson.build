security_driver_sources = [
  'security_dac.c',
  'security_driver.c',
  'security_manager.c',
  'security_nop.c',
  'security_stack.c',
  'security_util.c',
]

if conf.has('WITH_SECDRIVER_APPARMOR')
  security_driver_sources += 'security_apparmor.c'
endif

if conf.has('WITH_SECDRIVER_SELINUX')
  security_driver_sources += 'security_selinux.c'
endif

security_driver_lib = static_library(
  'virt_security_manager',
  [
    security_driver_sources,
  ],
  dependencies: [
    apparmor_dep,
    selinux_dep,
    src_dep,
  ],
  include_directories: [
    conf_inc_dir,
  ],
)
