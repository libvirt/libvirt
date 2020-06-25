network_driver_sources = [
  'bridge_driver.c',
  'bridge_driver_platform.c',
]

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
endif
