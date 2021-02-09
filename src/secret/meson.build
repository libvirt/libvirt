secret_driver_sources = [
  'secret_driver.c',
]

driver_source_files += files(secret_driver_sources)
stateful_driver_source_files += files(secret_driver_sources)

if conf.has('WITH_SECRETS')
  virt_modules += {
    'name': 'virt_driver_secret',
    'sources': [
      files(secret_driver_sources),
    ],
    'deps': [
      access_dep,
    ],
    'link_args': [
      libvirt_no_undefined,
    ],
  }

  virt_daemons += {
    'name': 'virtsecretd',
    'c_args': [
      '-DDAEMON_NAME="virtsecretd"',
      '-DMODULE_NAME="secret"',
    ],
  }

  virt_daemon_confs += {
    'name': 'virtsecretd',
  }

  virt_daemon_units += {
    'service': 'virtsecretd',
    'service_in': files('virtsecretd.service.in'),
    'name': 'Libvirt secret',
    'sockprefix': 'virtsecretd',
    'sockets': [ 'main', 'ro', 'admin' ],
  }

  openrc_init_files += {
    'name': 'virtsecretd',
    'in_file': files('virtsecretd.init.in'),
  }

  sysconf_files += {
    'name': 'virtsecretd',
    'file': files('virtsecretd.sysconf'),
  }
endif
