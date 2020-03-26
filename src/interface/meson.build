interface_driver_sources = [
  'interface_driver.c',
]

if conf.has('WITH_NETCF')
  interface_driver_sources += 'interface_backend_netcf.c'
endif

if conf.has('WITH_UDEV')
  interface_driver_sources += 'interface_backend_udev.c'
endif

if conf.has('WITH_INTERFACE')
  virt_modules += {
    'name': 'virt_driver_interface',
    'sources': [
      files(interface_driver_sources),
    ],
    'deps': [
      access_dep,
      libnl_dep,
      netcf_dep,
      udev_dep,
    ],
    'link_args': [
      libvirt_no_undefined,
    ],
  }
endif
