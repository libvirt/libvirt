ch_driver_sources = [
  'ch_capabilities.h',
  'ch_capabilities.c',
  'ch_conf.c',
  'ch_conf.h',
  'ch_domain.c',
  'ch_domain.h',
  'ch_driver.c',
  'ch_driver.h',
  'ch_monitor.c',
  'ch_monitor.h',
  'ch_process.c',
  'ch_process.h',
]

driver_source_files += files(ch_driver_sources)

stateful_driver_source_files += files(ch_driver_sources)

if conf.has('WITH_CH')
  ch_driver_impl = static_library(
    'virt_driver_ch_impl',
    [
      ch_driver_sources,
    ],
    dependencies: [
      access_dep,
      curl_dep,
      log_dep,
      src_dep,
    ],
    include_directories: [
      conf_inc_dir,
      hypervisor_inc_dir,
    ],
  )

  virt_modules += {
    'name': 'virt_driver_ch',
    'link_whole': [
      ch_driver_impl,
    ],
    'link_args': [
      libvirt_no_undefined,
    ],
  }

  virt_daemons += {
    'name': 'virtchd',
    'c_args': [
      '-DDAEMON_NAME="virtchd"',
      '-DMODULE_NAME="ch"',
    ],
  }

  virt_daemon_confs += {
    'name': 'virtchd',
  }

  virt_daemon_units += {
    'service': 'virtchd',
    'name': 'Cloud Hypervisor',
    'service_extra_in': [
      files('virtchd.service.extra.in'),
      systemd_service_limitnofile_extra_in,
      systemd_service_tasksmax_extra_in,
      systemd_service_limitmemlock_extra_in,
    ],
    'socket_extra_in': [
      files('virtchd.socket.extra.in'),
    ],
  }

  virt_install_dirs += [
    localstatedir / 'lib' / 'libvirt' / 'ch',
    localstatedir / 'log' / 'libvirt' / 'ch',
    runstatedir / 'libvirt' / 'ch',
  ]
endif
