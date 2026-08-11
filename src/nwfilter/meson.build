nwfilter_driver_sources = [
  'nwfilter_driver.c',
  'nwfilter_driver_conf.c',
  'nwfilter_gentech_driver.c',
  'nwfilter_tech_driver.c',
  'nwfilter_dhcpsnoop.c',
  'nwfilter_ebiptables_driver.c',
  'nwfilter_learnipaddr.c',
  'nwfilter_nftables_driver.c',
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

  nwfilter_options_conf = configuration_data({
    'FIREWALL_BACKEND_PRIORITY': ', '.join(firewall_backend_priority),
    'FIREWALL_BACKEND': firewall_backend_priority[0],
  })

  nwfilter_conf = configure_file(
    input: 'nwfilter.conf.in',
    output: 'nwfilter.conf',
    configuration: nwfilter_options_conf,
  )

  nwfilter_options_hack_conf = configuration_data({
    'FIREWALL_BACKEND_PRIORITY': ', '.join(firewall_backend_priority),
    'FIREWALL_BACKEND': firewall_backend_priority[0],
    # This hack is necessary because the output file is going to be
    # used as input for another configure_file() call later, which
    # will take care of substituting @CONFIG@ with useful data
    'CONFIG': '@CONFIG@',
  })
  test_libvirtd_network_aug_tmp = configure_file(
    input: 'test_libvirtd_nwfilter.aug.in',
    output: 'test_libvirtd_nwfilter.aug.tmp',
    configuration: nwfilter_options_hack_conf,
  )

  virt_conf_files += nwfilter_conf
  virt_aug_files += files('libvirtd_nwfilter.aug')
  virt_test_aug_files += {
    'name': 'test_libvirtd_nwfilter.aug',
    'aug': test_libvirtd_network_aug_tmp,
    'conf': nwfilter_conf,
    'test_name': 'libvirtd_nwfilter',
    'test_srcdir': meson.current_source_dir(),
    'test_builddir': meson.current_build_dir(),
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
