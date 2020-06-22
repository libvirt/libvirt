libxl_driver_sources = [
  'libxl_capabilities.c',
  'libxl_conf.c',
  'libxl_domain.c',
  'libxl_driver.c',
  'libxl_logger.c',
  'libxl_migration.c',
  'xen_common.c',
  'xen_xl.c',
  'xen_xm.c',
]

if conf.has('WITH_LIBXL')
  libxl_driver_imp = static_library(
    'virt_driver_libxl_impl',
    [
      libxl_driver_sources,
    ],
    dependencies: [
      access_dep,
      libxl_dep,
      src_dep,
    ],
    include_directories: [
      conf_inc_dir,
      hypervisor_inc_dir,
    ],
  )

  virt_modules += {
    'name': 'virt_driver_libxl',
    'link_whole': [
      libxl_driver_imp,
    ],
    'link_args': [
      libvirt_no_undefined,
    ],
  }

  virt_daemons += {
    'name': 'virtxend',
    'c_args': [
      '-DDAEMON_NAME="virtxend"',
      '-DMODULE_NAME="libxl"',
    ],
  }

  virt_conf_files += files('libxl.conf')
  virt_aug_files += files('libvirtd_libxl.aug')
  virt_test_aug_files += {
    'name': 'test_libvirtd_libxl.aug',
    'aug': files('test_libvirtd_libxl.aug.in'),
    'conf': files('libxl.conf'),
  }
endif
