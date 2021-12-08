example_admin_files = [
  'client_close',
  'client_info',
  'client_limits',
  'list_clients',
  'list_servers',
  'logging',
  'threadpool_params',
]

if conf.has('WITH_REMOTE')
  foreach name : example_admin_files
    source_file = '@0@.c'.format(name)
    executable(
      name,
      [
        source_file,
      ],
      include_directories: [
        libvirt_inc,
      ],
      link_with: [
        libvirt_lib,
        libvirt_admin_lib,
      ],
    )
    install_data(source_file, install_dir: example_dir / 'c' / 'admin')
  endforeach
endif
