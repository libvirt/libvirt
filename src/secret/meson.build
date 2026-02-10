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

  virt_secret_init_encryption_conf = configuration_data()

  virt_secret_init_encryption_conf.set('localstatedir', localstatedir)

  configure_file(
    input: 'virt-secret-init-encryption.service.in',
    output: '@0@.service'.format('virt-secret-init-encryption'),
    configuration: virt_secret_init_encryption_conf,
    install: true,
    install_dir: unitdir,
  )

  virt_daemon_units += {
    'service': 'virtsecretd',
    'name': 'secret',
    'service_extra_in': [
      files('virtsecretd.service.extra.in'),
    ],
    'socket_extra_in': [
      files('virtsecretd.socket.extra.in'),
    ],
  }

  openrc_init_files += {
    'name': 'virtsecretd',
    'in_file': files('virtsecretd.init.in'),
  }

  virt_install_dirs += [
    confdir / 'secrets',
    runstatedir / 'libvirt' / 'secrets',
    localstatedir / 'lib' / 'libvirt' / 'secrets',
  ]
endif
