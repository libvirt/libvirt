bhyve_sources = files(
  'bhyve_capabilities.c',
  'bhyve_command.c',
  'bhyve_conf.c',
  'bhyve_firmware.c',
  'bhyve_parse_command.c',
  'bhyve_device.c',
  'bhyve_domain.c',
  'bhyve_driver.c',
  'bhyve_monitor.c',
  'bhyve_process.c',
)

driver_source_files += bhyve_sources
stateful_driver_source_files += bhyve_sources

if conf.has('WITH_BHYVE')
  bhyve_driver_impl = static_library(
    'virt_driver_bhyve_impl',
    [
      bhyve_sources,
    ],
    dependencies: [
      access_dep,
      libkvm_dep,
      libutil_dep,
      src_dep,
    ],
    include_directories: [
      conf_inc_dir,
      hypervisor_inc_dir,
    ],
  )

  virt_modules += {
    'name': 'virt_driver_bhyve',
    'link_whole': [
      bhyve_driver_impl,
    ],
    'link_args': [
      libvirt_no_undefined,
    ],
  }

  virt_daemons += {
    'name': 'virtbhyved',
    'c_args': [
      '-DDAEMON_NAME="virtbhyved"',
      '-DMODULE_NAME="bhyve"'
    ],
  }

  virt_conf_files += files('bhyve.conf')
  virt_aug_files += files('libvirtd_bhyve.aug')
  virt_test_aug_files += {
    'name': 'test_libvirtd_bhyve.aug',
    'aug': files('test_libvirtd_bhyve.aug.in'),
    'conf': files('bhyve.conf'),
    'test_name': 'libvirtd_bhyve',
    'test_srcdir': meson.current_source_dir(),
    'test_builddir': meson.current_build_dir(),
  }

  virt_daemon_confs += {
    'name': 'virtbhyved',
  }
endif
