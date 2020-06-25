example_domain_files = [
  'dommigrate',
  'domtop',
  'info1',
  'rename',
  'suspend',
]

foreach name : example_domain_files
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
    ],
  )
  install_data(source_file, install_dir: example_dir / 'c' / 'domain')
endforeach
