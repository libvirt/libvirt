node_device_driver_sources = [
  'node_device_driver.c',
]

stateful_driver_source_files += files(node_device_driver_sources)

if conf.has('WITH_UDEV')
  node_device_driver_sources += 'node_device_udev.c'
endif

driver_source_files += files(node_device_driver_sources)

if conf.has('WITH_NODE_DEVICES')
  node_device_driver_impl = static_library(
    'virt_driver_nodedev_impl',
    [
      node_device_driver_sources,
    ],
    dependencies: [
      access_dep,
      libnl_dep,
      pciaccess_dep,
      src_dep,
      udev_dep,
    ],
    include_directories: [
      conf_inc_dir,
    ],
  )

  virt_modules += {
    'name': 'virt_driver_nodedev',
    'link_whole': [
      node_device_driver_impl,
    ],
    'link_args': [
      libvirt_no_undefined,
    ],
  }

  virt_daemons += {
    'name': 'virtnodedevd',
    'c_args': [
      '-DDAEMON_NAME="virtnodedevd"',
      '-DMODULE_NAME="nodedev"',
    ],
  }

  virt_daemon_confs += {
    'name': 'virtnodedevd',
  }

  virt_daemon_units += {
    'service': 'virtnodedevd',
    'name': 'nodedev',
    'service_extra_in': [
      files('virtnodedevd.service.extra.in'),
    ],
    'socket_extra_in': [
      files('virtnodedevd.socket.extra.in'),
    ],
  }

  openrc_init_files += {
    'name': 'virtnodedevd',
    'in_file': files('virtnodedevd.init.in'),
  }

  virt_install_dirs += [
    runstatedir / 'libvirt' / 'nodedev',
  ]
endif
