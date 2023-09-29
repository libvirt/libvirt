nwfilter_driver_sources = [
  'nwfilter_driver.c',
  'nwfilter_gentech_driver.c',
  'nwfilter_dhcpsnoop.c',
  'nwfilter_ebiptables_driver.c',
  'nwfilter_learnipaddr.c',
]

driver_source_files += files(nwfilter_driver_sources)
stateful_driver_source_files += files(nwfilter_driver_sources)

if conf.has('WITH_NWFILTER')
  nwfilter_driver_impl = static_library(
    'virt_driver_nwfilter_impl',
    [
      nwfilter_driver_sources,
    ],
    dependencies: [
      access_dep,
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

  virt_daemon_confs += {
    'name': 'virtnwfilterd',
  }

  virt_daemon_units += {
    'service': 'virtnwfilterd',
    'name': 'nwfilter',
    'service_extra_in': [
      files('virtnwfilterd.service.extra.in'),
    ],
    'socket_extra_in': [
      files('virtnwfilterd.socket.extra.in'),
    ],
  }

  openrc_init_files += {
    'name': 'virtnwfilterd',
    'in_file': files('virtnwfilterd.init.in'),
  }

  virt_install_dirs += [
    confdir / 'nwfilter',
    runstatedir / 'libvirt' / 'nwfilter-binding',
    runstatedir / 'libvirt' / 'nwfilter',
  ]

  subdir('xml')
endif
