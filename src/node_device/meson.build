node_device_driver_sources = [
  'node_device_driver.c',
]

if conf.has('WITH_HAL')
  node_device_driver_sources += 'node_device_hal.c'
endif

if conf.has('WITH_UDEV')
  node_device_driver_sources += 'node_device_udev.c'
endif

if conf.has('WITH_NODE_DEVICES')
  node_device_driver_impl = static_library(
    'virt_driver_nodedev_impl',
    [
      node_device_driver_sources,
    ],
    dependencies: [
      access_dep,
      hal_dep,
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
endif
