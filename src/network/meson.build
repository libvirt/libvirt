network_driver_sources = [
  'bridge_driver.c',
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
      dbus_dep,
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
      dbus_dep,
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
    'service_in': files('virtnetworkd.service.in'),
    'name': 'Libvirt network',
    'sockprefix': 'virtnetworkd',
    'sockets': [ 'main', 'ro', 'admin' ],
    'conflicts': true,
  }

  openrc_init_files += {
    'name': 'virtnetworkd',
    'in_file': files('virtnetworkd.init.in'),
  }

  sysconf_files += {
    'name': 'virtnetworkd',
    'file': files('virtnetworkd.sysconf'),
  }

  virt_install_dirs += [
    localstatedir / 'lib' / 'libvirt' / 'network',
    localstatedir / 'lib' / 'libvirt' / 'dnsmasq',
    runstatedir / 'libvirt' / 'network',
  ]

  uuidgen_prog = find_program('uuidgen', required: false)

  if uuidgen_prog.found()
    uuid = run_command(uuidgen_prog).stdout().strip()

    configure_file(
      input: 'default.xml.in',
      output: 'default.xml',
      command: [
        'sed', '-e', 's|</name>|</name>\\n  <uuid>@0@</uuid>|'.format(uuid),
        '@INPUT@',
      ],
      capture: true,
      install: true,
      install_dir: confdir / 'qemu' / 'networks',
    )
  else
    configure_file(
      input: 'default.xml.in',
      output: 'default.xml',
      copy: true,
      install: true,
      install_dir: confdir / 'qemu' / 'networks',
    )
  endif

  meson.add_install_script(
    meson_python_prog.path(), python3_prog.path(), meson_install_symlink_prog.path(),
    confdir / 'qemu' / 'networks' / 'autostart',
    '../default.xml', 'default.xml',
  )

  if conf.has('WITH_FIREWALLD_ZONE')
    install_data(
      'libvirt.zone',
      install_dir: prefix / 'lib' / 'firewalld' / 'zones',
      rename: [ 'libvirt.xml' ],
    )
  endif
endif
