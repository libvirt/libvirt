vz_driver_sources = [
  'vz_driver.c',
  'vz_utils.c',
  'vz_sdk.c',
]

driver_source_files += files(vz_driver_sources)
stateful_driver_source_files += files(vz_driver_sources)

if conf.has('WITH_VZ')
  vz_driver_impl = static_library(
    'virt_driver_vz_impl',
    [
      vz_driver_sources,
    ],
    dependencies: [
      access_dep,
      libnl_dep,
      parallels_sdk_dep,
      src_dep,
    ],
    include_directories: [
      conf_inc_dir,
    ],
  )

  virt_modules += {
    'name': 'virt_driver_vz',
    'link_whole': [
      vz_driver_impl,
    ],
    'link_args': [
      libvirt_no_undefined,
    ],
  }

  virt_daemons += {
    'name': 'virtvzd',
    'c_args': [
      '-DDAEMON_NAME="virtvzd"',
      '-DMODULE_NAME="vz"',
    ],
  }

  virt_daemon_confs += {
    'name': 'virtvzd',
  }

  virt_daemon_units += {
    'service': 'virtvzd',
    'name': 'vz',
    'service_extra_in': [
      files('virtvzd.service.extra.in'),
    ],
    'socket_extra_in': [
      files('virtvzd.socket.extra.in'),
    ],
  }

  openrc_init_files += {
    'name': 'virtvzd',
    'in_file': files('virtvzd.init.in'),
  }
endif
