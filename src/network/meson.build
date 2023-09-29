network_driver_sources = [
  'bridge_driver.c',
  'bridge_driver_conf.c',
  'bridge_driver_platform.c',
]

driver_source_files += files(network_driver_sources)
stateful_driver_source_files += files(network_driver_sources)

network_leases_helper_sources = files(
  'leaseshelper.c',
)

if conf.has('WITH_NETWORK')
  network_driver_impl = static_library(
    'virt_driver_network_impl',
    [
      network_driver_sources,
    ],
    dependencies: [
      access_dep,
      libnl_dep,
      src_dep,
    ],
    include_directories: [
      conf_inc_dir,
    ],
  )

  virt_modules += {
    'name': 'virt_driver_network',
    'deps': [
      libnl_dep,
    ],
    'link_whole': [
      network_driver_impl,
    ],
    'link_args': [
      libvirt_no_undefined,
    ],
  }

  virt_daemons += {
    'name': 'virtnetworkd',
    'c_args': [
      '-DDAEMON_NAME="virtnetworkd"',
      '-DMODULE_NAME="network"',
    ],
  }

  virt_daemon_confs += {
    'name': 'virtnetworkd',
  }

  virt_helpers += {
    'name': 'libvirt_leaseshelper',
    'sources': [
      network_leases_helper_sources,
      dtrace_gen_objects,
    ],
  }

  virt_daemon_units += {
    'service': 'virtnetworkd',
    'name': 'network',
    'service_extra_in': [
      files('virtnetworkd.service.extra.in'),
    ],
    'socket_extra_in': [
      files('virtnetworkd.socket.extra.in'),
    ],
  }

  openrc_init_files += {
    'name': 'virtnetworkd',
    'in_file': files('virtnetworkd.init.in'),
  }

  virt_install_dirs += [
    confdir / 'qemu' / 'networks',
    confdir / 'qemu' / 'networks' / 'autostart',
    localstatedir / 'lib' / 'libvirt' / 'network',
    localstatedir / 'lib' / 'libvirt' / 'dnsmasq',
    runstatedir / 'libvirt' / 'network',
  ]

  configure_file(
    input: 'default.xml.in',
    output: '@BASENAME@',
    configuration: configmake_conf,
    install: true,
    install_dir: confdir / 'qemu' / 'networks',
  )

  meson.add_install_script(
    meson_python_prog.full_path(), python3_prog.full_path(), meson_install_symlink_prog.full_path(),
    confdir / 'qemu' / 'networks' / 'autostart',
    '../default.xml', 'default.xml',
  )

  if conf.has('WITH_FIREWALLD_ZONE')
    install_data(
      'libvirt.zone',
      install_dir: prefix / 'lib' / 'firewalld' / 'zones',
      rename: [ 'libvirt.xml' ],
    )
    install_data(
      'libvirt-routed.zone',
      install_dir: prefix / 'lib' / 'firewalld' / 'zones',
      rename: [ 'libvirt-routed.xml' ],
    )
    install_data(
      'libvirt-to-host.policy',
      install_dir: prefix / 'lib' / 'firewalld' / 'policies',
      rename: [ 'libvirt-to-host.xml' ],
    )
    install_data(
      'libvirt-routed-out.policy',
      install_dir: prefix / 'lib' / 'firewalld' / 'policies',
      rename: [ 'libvirt-routed-out.xml' ],
    )
    install_data(
      'libvirt-routed-in.policy',
      install_dir: prefix / 'lib' / 'firewalld' / 'policies',
      rename: [ 'libvirt-routed-in.xml' ],
    )
  endif
endif
