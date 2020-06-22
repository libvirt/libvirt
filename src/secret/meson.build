secret_driver_sources = [
  'secret_driver.c',
]

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
endif
