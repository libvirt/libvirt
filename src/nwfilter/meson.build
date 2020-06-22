nwfilter_driver_sources = [
  'nwfilter_driver.c',
  'nwfilter_gentech_driver.c',
  'nwfilter_dhcpsnoop.c',
  'nwfilter_ebiptables_driver.c',
  'nwfilter_learnipaddr.c',
]

if conf.has('WITH_NWFILTER')
  nwfilter_driver_impl = static_library(
    'virt_driver_nwfilter_impl',
    [
      nwfilter_driver_sources,
    ],
    dependencies: [
      access_dep,
      dbus_dep,
      libnl_dep,
      libpcap_dep,
      src_dep,
    ],
    include_directories: [
      conf_inc_dir,
    ],
  )

  virt_modules += {
    'name': 'virt_driver_nwfilter',
    'link_whole': [
      nwfilter_driver_impl,
    ],
    'link_args': [
      libvirt_no_undefined,
    ],
  }

  virt_daemons += {
    'name': 'virtnwfilterd',
    'c_args': [
      '-DDAEMON_NAME="virtnwfilterd"',
      '-DMODULE_NAME="nwfilter"',
    ],
  }
endif
