vbox_driver_sources = [
  'vbox_V5_2.c',
  'vbox_V6_0.c',
  'vbox_V6_1.c',
  'vbox_common.c',
  'vbox_driver.c',
  'vbox_network.c',
  'vbox_snapshot_conf.c',
  'vbox_storage.c',
  'vbox_XPCOMCGlue.c',
]

driver_source_files += files(
  vbox_driver_sources,
  'vbox_tmpl.c',
)

if conf.has('WITH_VBOX')
  vbox_driver_impl = static_library(
    'virt_driver_vbox_impl',
    [
      vbox_driver_sources,
    ],
    c_args: [
      '-DVBOX_DRIVER',
    ],
    dependencies: [
      dlopen_dep,
      src_dep,
      win32_dep,
    ],
    include_directories: [
      conf_inc_dir,
    ],
  )

  virt_modules += {
    'name': 'virt_driver_vbox',
    'link_whole': [
      vbox_driver_impl,
    ],
    'link_args': [
      libvirt_no_undefined,
    ],
  }

  virt_daemons += {
    'name': 'virtvboxd',
    'c_args': [
      '-DDAEMON_NAME="virtvboxd"',
      '-DMODULE_NAME="vbox"',
    ],
  }

  virt_daemon_confs += {
    'name': 'virtvboxd',
  }

  virt_daemon_units += {
    'service': 'virtvboxd',
    'service_in': files('virtvboxd.service.in'),
    'name': 'Libvirt vbox',
    'sockprefix': 'virtvboxd',
    'sockets': [ 'main', 'ro', 'admin' ],
  }

  openrc_init_files += {
    'name': 'virtvboxd',
    'in_file': files('virtvboxd.init.in'),
  }

  sysconf_files += {
    'name': 'virtvboxd',
    'file': files('virtvboxd.sysconf'),
  }
endif
