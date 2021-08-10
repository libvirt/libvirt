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

apparmor_helper_sources = files(
  'virt-aa-helper.c',
)

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

libvirt_libs += security_driver_lib

if conf.has('WITH_LIBVIRTD') and conf.has('WITH_APPARMOR')
  virt_helpers += {
    'name': 'virt-aa-helper',
    'sources': [
      apparmor_helper_sources,
      dtrace_gen_objects,
    ],
    'include': [
      conf_inc_dir,
      hypervisor_inc_dir,
      include_directories('.'),
      include_directories('..' / 'storage_file'),
    ],
  }
endif

if conf.has('WITH_APPARMOR_PROFILES')
  subdir('apparmor')
endif
